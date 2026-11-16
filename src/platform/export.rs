//! Export formats for the shared storage layer.
//!
//! Each exporter turns already-tested core types into bytes and hands them to the
//! storage actor. Nothing here touches SPI or blocks the UI.

use alloc::string::String;
use alloc::vec::Vec;

use cyberdeck_core::pcap::{PcapWriter, VecSink, SNAPLEN_DEFAULT};
use cyberdeck_core::rf::capture::NrfLog;
use cyberdeck_core::time::Timestamp;

use super::ble::BleDevice;
use super::sd;
use super::wifi::CapturedFrame;

/// G01: access-point inventory as a plain-text report.
pub fn save_wifi_findings(aps: &[super::wifi::ApRow]) -> bool {
    if aps.is_empty() {
        return false;
    }
    let mut text = String::from("BSSID,SSID,CHANNEL,RSSI,SECURITY\n");
    for ap in aps {
        text.push_str(&alloc::format!(
            "{},{},{},{},{}\n",
            ap.bssid,
            csv_field(&ap.ssid),
            ap.channel,
            ap.rssi,
            ap.security
        ));
    }
    let name = sd::next_name("WIFI", "CSV");
    sd::enqueue(&name, text.into_bytes(), false)
}

/// G03: observed BLE devices, radio class and RSSI.
pub fn save_ble_history(devices: &[BleDevice], frames: u32) -> bool {
    if devices.is_empty() {
        return false;
    }
    let mut text = alloc::format!("frames {frames}\nname,address,rssi,kind,detail\n");
    for device in devices {
        text.push_str(&alloc::format!(
            "{},{},{},{},{}\n",
            csv_field(&device.name),
            device.address,
            device.rssi,
            device.kind,
            csv_field(&device.detail)
        ));
    }
    let name = sd::next_name("BLE", "CSV");
    sd::enqueue(&name, text.into_bytes(), false)
}

/// G05: nRF24 capture log, already CSV-formatted by the core.
pub fn save_rf_capture(log: &NrfLog<24>) -> bool {
    if log.is_empty() {
        return false;
    }
    let name = sd::next_name("RF", "CSV");
    sd::enqueue(&name, log.to_csv().into_bytes(), false)
}

/// G02: radiotap pcap built from captured frames.
///
/// Callers must supply the frames for one session; the capture loop does not yet
/// retain them, so this path is ready but not driven from the UI.
pub fn save_pcap(frames: &[CapturedFrame]) -> bool {
    if frames.is_empty() {
        return false;
    }
    let mut writer = match PcapWriter::new(
        VecSink(Vec::new()),
        SNAPLEN_DEFAULT,
        true,
        16 * 1024 * 1024,
    ) {
        Ok(writer) => writer,
        Err(_) => return false,
    };
    for frame in frames {
        let channel_mhz = 2407 + u16::from(frame.channel) * 5;
        let stamp = Timestamp::new(0, 0);
        if writer
            .write_frame_on_channel(stamp, frame.bytes(), channel_mhz, frame.rssi)
            .is_err()
        {
            return false;
        }
    }
    let Ok((sink, _stats)) = writer.finish() else {
        return false;
    };
    let name = sd::next_name("CAPTURE", "PCAP");
    sd::enqueue(&name, sink.0, false)
}

fn csv_field(value: &str) -> String {
    if value.contains(',') || value.contains('"') {
        let mut out = String::from("\"");
        for character in value.chars() {
            if character == '"' {
                out.push('"');
            }
            out.push(character);
        }
        out.push('"');
        out
    } else {
        String::from(value)
    }
}
