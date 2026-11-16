//! Export formats for the shared storage layer.
//!
//! Each exporter turns already-tested core types into bytes and hands them to the
//! storage actor. Nothing here touches SPI or blocks the UI.

use alloc::string::String;

use cyberdeck_core::rf::capture::NrfLog;

use super::ble::BleDevice;
use super::sd;

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

/// G01: EAPOL/PMKID findings in hashcat 22000 format, ready for offline analysis.
pub fn save_wifi_hashes(hashes: &str) -> bool {
    if hashes.is_empty() {
        return false;
    }
    let name = sd::next_name("HASH", "22000");
    sd::enqueue(&name, hashes.as_bytes().to_vec(), false)
}

/// G01: credentials submitted to the Evil Twin portal (header-only means none).
pub fn save_portal_credentials(csv: &str) -> bool {
    if csv.lines().count() <= 1 {
        return false;
    }
    let name = sd::next_name("PORTAL", "CSV");
    sd::enqueue(&name, csv.as_bytes().to_vec(), false)
}

/// G03: observed BLE devices, radio class and RSSI, plus any GATT read.
pub fn save_ble_history(devices: &[BleDevice], frames: u32, gatt: &[String]) -> bool {
    if devices.is_empty() && gatt.is_empty() {
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
    if !gatt.is_empty() {
        text.push_str("# gatt\n");
        for line in gatt.iter().take(64) {
            text.push_str("# ");
            text.push_str(&csv_field(line));
            text.push('\n');
        }
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

/// G05: per-channel session baseline from the core session statistics.
pub fn save_rf_baseline(csv: &str) -> bool {
    if csv.is_empty() {
        return false;
    }
    let name = sd::next_name("BASE", "CSV");
    sd::enqueue(&name, csv.as_bytes().to_vec(), false)
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
