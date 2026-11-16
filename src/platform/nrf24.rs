//! nRF24L01+ SPI driver: register access, RPD sampling and payload receive.
//!
//! The register map, bit meanings and timing live in `cyberdeck_core::rf::nrf24`
//! (host-tested); this adapter only performs SPI transactions. Probing is explicit:
//! a module that does not answer with the written config is reported as an
//! initialisation failure instead of being used blindly.

use cyberdeck_core::rf::nrf24::*;
use alloc::rc::Rc;
use core::cell::RefCell;
use embedded_hal::spi::SpiBus;
use esp_hal::Blocking;
use esp_hal::gpio::{Level, Output, OutputConfig};
use esp_hal::spi::master::Spi;

/// Driver failure with an actionable message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Nrf24Error {
    Bus,
    NotFound,
    AddressWidth,
}

impl Nrf24Error {
    pub const fn message(self) -> &'static str {
        match self {
            Self::Bus => "nRF24 SPI transfer failed",
            Self::NotFound => "nRF24L01 not responding (check 3V3, CE/CSN and MISO)",
            Self::AddressWidth => "nRF24 rejected the 5-byte address width",
        }
    }
}

/// One nRF24L01+ module.
pub struct Nrf24<'d> {
    spi: Rc<RefCell<Spi<'d, Blocking>>>,
    csn: Output<'d>,
    ce: Output<'d>,
    channel: u8,
}

impl<'d> Nrf24<'d> {
    pub fn new(
        spi: Spi<'d, Blocking>,
        csn: Output<'d>,
        ce: Output<'d>,
        rate: DataRate,
    ) -> Result<Self, Nrf24Error> {
        Self::from_shared(Rc::new(RefCell::new(spi)), csn, ce, rate)
    }

    pub fn from_shared(spi: Rc<RefCell<Spi<'d, Blocking>>>, csn: Output<'d>, ce: Output<'d>, rate: DataRate) -> Result<Self, Nrf24Error> {
        let mut radio = Self {
            spi,
            csn,
            ce,
            channel: 76,
        };
        radio.csn.set_high();
        radio.ce.set_low();
        // Hardware bring-up sequence from the datasheet §6.1.
        radio.write_register(REG_CONFIG, CONFIG_EN_CRC | CONFIG_CRCO)?;
        if radio.read_register(REG_CONFIG)? & 0x0C != CONFIG_EN_CRC | CONFIG_CRCO {
            return Err(Nrf24Error::NotFound);
        }
        radio.write_register(REG_EN_AA, 0x00)?;
        radio.write_register(REG_EN_RXADDR, 0x01)?; // pipe 0 only
        radio.write_register(REG_SETUP_AW, 0x03)?; // 5-byte addresses
        if radio.read_register(REG_SETUP_AW)? & 0x03 != 0x03 {
            return Err(Nrf24Error::AddressWidth);
        }
        radio.write_register(REG_SETUP_RETR, 0x00)?;
        radio.write_register(REG_RF_SETUP, rate.rf_setup_bits())?;
        radio.write_register(REG_FEATURE, 0x00)?;
        radio.write_register(REG_DYNPD, 0x00)?;
        radio.write_register(REG_RX_PW_P0, MAX_PAYLOAD)?;
        radio.command(CMD_FLUSH_RX)?;
        radio.command(CMD_FLUSH_TX)?;
        radio.write_register(REG_STATUS, STATUS_RX_DR | STATUS_TX_DS | STATUS_MAX_RT)?;
        radio.write_register(
            REG_CONFIG,
            CONFIG_EN_CRC | CONFIG_CRCO | CONFIG_PWR_UP | CONFIG_PRIM_RX,
        )?;
        radio.set_channel(radio.channel)?;
        Ok(radio)
    }

    pub const fn channel(&self) -> u8 {
        self.channel
    }

    fn command(&mut self, command: u8) -> Result<(), Nrf24Error> {
        self.csn.set_low();
        let mut read = [0u8; 1];
        let result =
            SpiBus::transfer(&mut *self.spi.borrow_mut(), &mut read, &[command]).map_err(|_| Nrf24Error::Bus);
        self.csn.set_high();
        result
    }

    /// Full-duplex read of `cmd` followed by one status byte.
    fn read_raw(&mut self, command: u8) -> Result<u8, Nrf24Error> {
        self.csn.set_low();
        let mut read = [0u8; 2];
        let result = SpiBus::transfer(&mut *self.spi.borrow_mut(), &mut read, &[command, 0x00])
            .map_err(|_| Nrf24Error::Bus);
        self.csn.set_high();
        result.map(|()| read[1])
    }

    fn read_register(&mut self, register: u8) -> Result<u8, Nrf24Error> {
        self.read_raw(CMD_R_REGISTER | (register & 0x1F))
    }

    fn write_register(&mut self, register: u8, value: u8) -> Result<(), Nrf24Error> {
        self.csn.set_low();
        let mut read = [0u8; 2];
        let result = SpiBus::transfer(
            &mut *self.spi.borrow_mut(),
            &mut read,
            &[CMD_W_REGISTER | (register & 0x1F), value],
        )
        .map_err(|_| Nrf24Error::Bus);
        self.csn.set_high();
        result
    }

    pub fn set_channel(&mut self, channel: u8) -> Result<(), Nrf24Error> {
        let channel = channel.min(MAX_CHANNEL);
        self.write_register(REG_RF_CH, channel)?;
        self.channel = channel;
        Ok(())
    }

    /// Received-power-detector bit for the current channel.
    pub fn rpd(&mut self) -> Result<bool, Nrf24Error> {
        Ok(self.read_register(REG_RPD)? & 0x01 != 0)
    }

    /// Sample one channel and fold it into the supplied spectrum model.
    pub fn sample(
        &mut self,
        spectrum: &mut cyberdeck_core::rf::spectrum::Spectrum,
    ) -> Result<bool, Nrf24Error> {
        let asserted = self.rpd()?;
        spectrum.apply(self.channel, asserted);
        Ok(asserted)
    }

    /// Pop one received payload, if any.
    pub fn read_packet(
        &mut self,
        buffer: &mut [u8; MAX_PAYLOAD as usize],
    ) -> Result<Option<(u8, u8)>, Nrf24Error> {
        let status = self.read_register(REG_STATUS)?;
        let pipe = (status >> 1) & 0x07;
        if pipe == STATUS_RX_P_NO_EMPTY {
            return Ok(None);
        }
        let width = usize::from(self.read_register(REG_RX_PW_P0 + pipe)?).min(buffer.len());
        if width == 0 {
            return Ok(None);
        }
        self.csn.set_low();
        let mut write = [0xFFu8; MAX_PAYLOAD as usize + 1];
        write[0] = CMD_R_RX_PAYLOAD;
        let mut read = [0u8; MAX_PAYLOAD as usize + 1];
        let result =
            SpiBus::transfer(&mut *self.spi.borrow_mut(), &mut read, &write).map_err(|_| Nrf24Error::Bus);
        self.csn.set_high();
        result?;
        buffer[..width].copy_from_slice(&read[1..1 + width]);
        self.write_register(REG_STATUS, STATUS_RX_DR)?;
        Ok(Some((pipe, width as u8)))
    }

    /// Assert or release CE, which is what actually starts/stops the RX state.
    pub fn rx_mode(&mut self, enable: bool) {
        if enable {
            self.ce.set_high();
        } else {
            self.ce.set_low();
        }
    }

    /// Configure a known lab receive profile. Address bytes use nRF register order.
    pub fn configure(&mut self, rate: DataRate, payload_len: u8, address: [u8; 5]) -> Result<(), Nrf24Error> {
        self.ce.set_low();
        self.write_register(REG_RF_SETUP, rate.rf_setup_bits())?;
        self.write_register(REG_RX_PW_P0, payload_len.clamp(1, MAX_PAYLOAD))?;
        self.csn.set_low();
        let mut command = [0u8; 6];
        command[0] = CMD_W_REGISTER | REG_RX_ADDR_P0;
        command[1..].copy_from_slice(&address);
        let mut response = [0u8; 6];
        let result = SpiBus::transfer(&mut *self.spi.borrow_mut(), &mut response, &command).map_err(|_| Nrf24Error::Bus);
        self.csn.set_high();
        result?;
        self.command(CMD_FLUSH_RX)?;
        Ok(())
    }
    pub fn power_down(&mut self) -> Result<(), Nrf24Error> {
        self.ce.set_low();
        self.write_register(REG_CONFIG, CONFIG_EN_CRC | CONFIG_CRCO)?;
        Ok(())
    }

    pub fn power_up_rx(&mut self) -> Result<(), Nrf24Error> {
        self.write_register(
            REG_CONFIG,
            CONFIG_EN_CRC | CONFIG_CRCO | CONFIG_PWR_UP | CONFIG_PRIM_RX,
        )?;
        self.ce.set_high();
        Ok(())
    }
}

pub fn outputs<'d>(
    csn: impl esp_hal::gpio::OutputPin + 'd,
    ce: impl esp_hal::gpio::OutputPin + 'd,
) -> (Output<'d>, Output<'d>) {
    let config = OutputConfig::default();
    (
        Output::new(csn, Level::High, config),
        Output::new(ce, Level::Low, config),
    )
}
