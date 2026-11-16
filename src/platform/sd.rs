//! microSD storage actor: mounts the card once and serialises file writes.
//!
//! Formatting and export logic lives in [`super::export`]; this module only owns
//! the bus and the FAT volume. Jobs cross the actor boundary as owned buffers so
//! the UI never blocks on SPI and no long critical sections are needed.

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::RefCell;

use critical_section::Mutex;
use embedded_hal::spi::{ErrorType, Operation, SpiBus, SpiDevice};
use embedded_sdmmc::{Mode, SdCard, TimeSource, Timestamp, VolumeIdx, VolumeManager};
use esp_hal::delay::Delay;
use esp_hal::gpio::Output;
use esp_hal::spi::master::Spi;
use esp_hal::Blocking;
use esp_hal::spi::Error as SpiError;

const QUEUE_DEPTH: usize = 8;

/// SPI bus with its own chip-select, shaped as an `embedded-hal` `SpiDevice`.
pub struct SdBus<'d> {
    spi: Spi<'d, Blocking>,
    cs: Output<'d>,
}

impl<'d> SdBus<'d> {
    pub fn new(spi: Spi<'d, Blocking>, cs: Output<'d>) -> Self {
        Self { spi, cs }
    }
}

impl ErrorType for SdBus<'_> {
    type Error = SpiError;
}

impl SpiDevice<u8> for SdBus<'_> {
    fn transaction(&mut self, operations: &mut [Operation<'_, u8>]) -> Result<(), SpiError> {
        self.cs.set_low();
        let result = operations.iter_mut().try_for_each(|operation| match operation {
            Operation::Read(buffer) => self.spi.read(buffer),
            Operation::Write(buffer) => self.spi.write(buffer),
            Operation::TransferInPlace(buffer) => self.spi.transfer_in_place(buffer),
            _ => Ok(()),
        });
        self.cs.set_high();
        result
    }
}

/// No RTC on the board: FAT timestamps are fixed until time sync exists.
struct FixedClock;

impl TimeSource for FixedClock {
    fn get_timestamp(&self) -> Timestamp {
        Timestamp {
            year_since_1970: 56,
            zero_indexed_month: 10,
            zero_indexed_day: 15,
            hours: 0,
            minutes: 0,
            seconds: 0,
        }
    }
}

struct StorageState {
    mounted: bool,
    status: String,
    files: u32,
    bytes: u64,
}

impl StorageState {
    const fn new() -> Self {
        Self {
            mounted: false,
            status: String::new(),
            files: 0,
            bytes: 0,
        }
    }
}

/// One queued file write.
pub struct Job {
    pub name: String,
    pub append: bool,
    pub bytes: Vec<u8>,
}

static STATE: Mutex<RefCell<StorageState>> = Mutex::new(RefCell::new(StorageState::new()));
static JOBS: Mutex<RefCell<VecDeque<Job>>> = Mutex::new(RefCell::new(VecDeque::new()));
static NEXT: Mutex<RefCell<u32>> = Mutex::new(RefCell::new(0));

fn publish(status: &str, mounted: bool, file_len: Option<u64>) {
    critical_section::with(|cs| {
        let mut state = STATE.borrow_ref_mut(cs);
        state.mounted = mounted;
        state.status.clear();
        state.status.push_str(status);
        if let Some(len) = file_len {
            state.files = state.files.saturating_add(1);
            state.bytes = state.bytes.saturating_add(len);
        }
    });
}

/// True once a FAT volume is open and writes are being serviced.
pub fn ready() -> bool {
    critical_section::with(|cs| STATE.borrow_ref(cs).mounted)
}

pub fn status_line() -> String {
    critical_section::with(|cs| {
        let state = STATE.borrow_ref(cs);
        if state.mounted {
            alloc::format!("SD: {} files, {} B", state.files, state.bytes)
        } else if state.status.is_empty() {
            String::from("SD: not mounted")
        } else {
            alloc::format!("SD: {}", state.status)
        }
    })
}

/// Queue a file write. Returns false when the card is absent or the queue is full.
pub fn enqueue(name: &str, bytes: Vec<u8>, append: bool) -> bool {
    if bytes.is_empty() || !ready() {
        return false;
    }
    critical_section::with(|cs| {
        let mut jobs = JOBS.borrow_ref_mut(cs);
        if jobs.len() >= QUEUE_DEPTH {
            return false;
        }
        jobs.push_back(Job {
            name: String::from(name),
            append,
            bytes,
        });
        true
    })
}

/// Highest numeric suffix already on the card, so numbering survives reboots.
pub fn next_name(stem: &str, extension: &str) -> String {
    let index = critical_section::with(|cs| {
        let mut next = NEXT.borrow_ref_mut(cs);
        *next = next.wrapping_add(1);
        *next
    });
    alloc::format!("{stem}{index:03}.{extension}")
}

fn scan_existing<D>(
    manager: &VolumeManager<D, FixedClock, 4, 4, 1>,
    volume: embedded_sdmmc::RawVolume,
) -> u32
where
    D: embedded_sdmmc::BlockDevice,
{
    let mut highest = 0u32;
    let Ok(root) = manager.open_root_dir(volume) else {
        return 1;
    };
    let _ = manager.iterate_dir(root, |entry| {
        let base = entry.name.base_name();
        let mut value = 0u32;
        let mut digits = 0usize;
        for byte in base.iter().rev() {
            if !byte.is_ascii_digit() {
                break;
            }
            value += u32::from(byte - b'0') * 10u32.pow(digits as u32);
            digits += 1;
        }
        if digits > 0 {
            highest = highest.max(value);
        }
    });
    let _ = manager.close_dir(root);
    highest.saturating_add(1)
}

fn take_job() -> Option<Job> {
    critical_section::with(|cs| JOBS.borrow_ref_mut(cs).pop_front())
}

fn write_job<D>(
    manager: &VolumeManager<D, FixedClock, 4, 4, 1>,
    volume: embedded_sdmmc::RawVolume,
    job: &Job,
) -> Result<u64, ()>
where
    D: embedded_sdmmc::BlockDevice,
{
    let mode = if job.append {
        Mode::ReadWriteCreateOrAppend
    } else {
        Mode::ReadWriteCreateOrTruncate
    };
    let root = manager.open_root_dir(volume).map_err(|_| ())?;
    let file = manager
        .open_file_in_dir(root, job.name.as_str(), mode)
        .map_err(|_| {
            let _ = manager.close_dir(root);
        })?;
    let mut written = 0u64;
    for chunk in job.bytes.chunks(512) {
        if manager.write(file, chunk).is_err() {
            let _ = manager.close_file(file);
            let _ = manager.close_dir(root);
            return Err(());
        }
        written += chunk.len() as u64;
    }
    let _ = manager.close_file(file);
    let _ = manager.close_dir(root);
    Ok(written)
}

/// Own the card for the lifetime of the firmware.
pub async fn run(bus: SdBus<'static>) -> ! {
    let card = SdCard::new(bus, Delay::new());
    let manager = VolumeManager::new(card, FixedClock);
    let volume = match manager.open_volume(VolumeIdx(0)) {
        Ok(volume) => {
            let raw = volume.to_raw_volume();
            let next = scan_existing(&manager, raw);
            critical_section::with(|cs| *NEXT.borrow_ref_mut(cs) = next);
            publish("mounted", true, None);
            Some(raw)
        }
        Err(_) => {
            publish("no FAT volume", false, None);
            None
        }
    };

    loop {
        if let Some(volume) = volume {
            while let Some(job) = take_job() {
                match write_job(&manager, volume, &job) {
                    Ok(len) => publish("written", true, Some(len)),
                    Err(()) => publish("write failed", true, None),
                }
            }
        }
        embassy_time::Timer::after(embassy_time::Duration::from_millis(50)).await;
    }
}
