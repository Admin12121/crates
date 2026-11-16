//! nRF24L01+ register map, command encoding and configuration plans.
//!
//! Values are taken from the Nordic nRF24L01+ product specification; the same
//! sequence is used by the RF24 Arduino library and by Bruce's
//! `src/modules/NRF24/*` port, so the transmitted/received behaviour matches.

use alloc::vec::Vec;

/// CONFIG register.
pub const REG_CONFIG: u8 = 0x00;
pub const REG_EN_AA: u8 = 0x01;
pub const REG_EN_RXADDR: u8 = 0x02;
pub const REG_SETUP_AW: u8 = 0x03;
pub const REG_SETUP_RETR: u8 = 0x04;
pub const REG_RF_CH: u8 = 0x05;
pub const REG_RF_SETUP: u8 = 0x06;
pub const REG_STATUS: u8 = 0x07;
pub const REG_OBSERVE_TX: u8 = 0x08;
pub const REG_RPD: u8 = 0x09;
pub const REG_RX_ADDR_P0: u8 = 0x0A;
pub const REG_RX_ADDR_P1: u8 = 0x0B;
pub const REG_RX_ADDR_P5: u8 = 0x0F;
pub const REG_TX_ADDR: u8 = 0x10;
pub const REG_RX_PW_P0: u8 = 0x11;
pub const REG_RX_PW_P1: u8 = 0x12;
pub const REG_RX_PW_P5: u8 = 0x16;
pub const REG_FIFO_STATUS: u8 = 0x17;
pub const REG_DYNPD: u8 = 0x1C;
pub const REG_FEATURE: u8 = 0x1D;

/// Command byte bases.
pub const CMD_R_REGISTER: u8 = 0x00;
pub const CMD_W_REGISTER: u8 = 0x20;
pub const CMD_R_RX_PAYLOAD: u8 = 0x61;
pub const CMD_W_TX_PAYLOAD: u8 = 0xA0;
pub const CMD_FLUSH_TX: u8 = 0xE1;
pub const CMD_FLUSH_RX: u8 = 0xE2;
pub const CMD_REUSE_TX_PL: u8 = 0xE3;
pub const CMD_R_RX_PL_WID: u8 = 0x60;
pub const CMD_W_ACK_PAYLOAD: u8 = 0xA8;
pub const CMD_W_TX_PAYLOAD_NOACK: u8 = 0xB0;
pub const CMD_NOP: u8 = 0xFF;

/// STATUS bits.
pub const STATUS_RX_DR: u8 = 0x40;
pub const STATUS_TX_DS: u8 = 0x20;
pub const STATUS_MAX_RT: u8 = 0x10;
pub const STATUS_TX_FULL: u8 = 0x01;
/// `RX_P_NO` reports the pipe for the next payload; 111 means RX FIFO empty.
pub const STATUS_RX_P_NO_EMPTY: u8 = 0x07;

/// CONFIG bits.
pub const CONFIG_MASK_RX_DR: u8 = 0x40;
pub const CONFIG_MASK_TX_DS: u8 = 0x20;
pub const CONFIG_MASK_MAX_RT: u8 = 0x10;
pub const CONFIG_EN_CRC: u8 = 0x08;
pub const CONFIG_CRCO: u8 = 0x04;
pub const CONFIG_PWR_UP: u8 = 0x02;
pub const CONFIG_PRIM_RX: u8 = 0x01;

/// FIFO_STATUS bits.
pub const FIFO_RX_EMPTY: u8 = 0x01;
pub const FIFO_TX_FULL: u8 = 0x20;

/// Highest RF channel register value (2400..=2525 MHz).
pub const MAX_CHANNEL: u8 = 125;
/// Number of 1 MHz channels in the nRF24 band.
pub const CHANNEL_COUNT: u8 = 126;
/// Payload width used for packet capture (maximum).
pub const MAX_PAYLOAD: u8 = 32;

/// Air data rate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataRate {
    Kbps250,
    Mbps1,
    Mbps2,
}

impl DataRate {
    /// RF_SETUP bits for this rate (0 dBm output power).
    ///
    /// RF_SETUP layout: bit5 `RF_DR_LOW` (250 kbps), bit3 `RF_DR_HIGH` (2 Mbps),
    /// bits2:1 `RF_PWR` (0b11 = 0 dBm).
    pub const fn rf_setup_bits(self) -> u8 {
        const PWR_0DBM: u8 = 0x06;
        const RF_DR_LOW: u8 = 0x20;
        const RF_DR_HIGH: u8 = 0x08;
        match self {
            Self::Kbps250 => PWR_0DBM | RF_DR_LOW,
            Self::Mbps1 => PWR_0DBM,
            Self::Mbps2 => PWR_0DBM | RF_DR_HIGH,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Kbps250 => "250 kbps",
            Self::Mbps1 => "1 Mbps",
            Self::Mbps2 => "2 Mbps",
        }
    }
}

/// What the radio is being configured for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Nrf24Mode {
    /// RPD-only sweep across the band (spectrum/waterfall).
    SpectrumSweep,
    /// Promiscuous receive on the noise addresses (packet capture).
    PacketCapture,
    /// Fixed-address RX for a specific 2.4 GHz link test.
    LinkTest,
}

impl Nrf24Mode {
    pub const fn label(self) -> &'static str {
        match self {
            Self::SpectrumSweep => "Spectrum Sweep",
            Self::PacketCapture => "Packet Capture",
            Self::LinkTest => "Link Test",
        }
    }
}

/// One register write in a configuration plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisterWrite {
    pub register: u8,
    pub value: u8,
}

/// Encode a register-read command byte.
pub const fn read_command(register: u8) -> u8 {
    CMD_R_REGISTER | (register & 0x1F)
}

/// Encode a register-write command byte.
pub const fn write_command(register: u8) -> u8 {
    CMD_W_REGISTER | (register & 0x1F)
}

/// RF channel register value for a frequency in MHz (2400..=2525).
pub fn channel_for_mhz(freq_mhz: u16) -> Option<u8> {
    if !(2400..=2525).contains(&freq_mhz) {
        return None;
    }
    Some((freq_mhz - 2400) as u8)
}

/// Centre frequency of a channel register value.
pub const fn frequency_mhz(channel: u8) -> u16 {
    2400 + channel as u16
}

/// RX pipe reported by a STATUS read, `None` when the FIFO is empty.
pub const fn rx_pipe(status: u8) -> Option<u8> {
    let pipe = (status >> 1) & 0x07;
    if pipe == STATUS_RX_P_NO_EMPTY {
        None
    } else {
        Some(pipe)
    }
}

/// Decode `OBSERVE_TX` packet-loss counters `(lost, retransmitted)`.
pub const fn observe_tx(observe: u8) -> (u8, u8) {
    (((observe >> 4) & 0x0F), observe & 0x0F)
}

/// Build the register plan for a mode.
///
/// Spectrum sweep intentionally disables CRC, auto-ack, dynamic payloads and opens
/// all six pipes on 3-byte noise addresses: it must accept any on-air energy, which
/// is exactly how the reference implementations configure the module.
pub fn configuration(mode: Nrf24Mode, channel: u8, rate: DataRate) -> Vec<RegisterWrite> {
    let channel = channel.min(MAX_CHANNEL);
    let mut plan = Vec::with_capacity(12);
    match mode {
        Nrf24Mode::SpectrumSweep => {
            plan.push(RegisterWrite {
                register: REG_CONFIG,
                // CRC disabled, powered up, RX mode.
                value: CONFIG_PWR_UP,
            });
            plan.push(RegisterWrite {
                register: REG_EN_AA,
                value: 0x00,
            });
            plan.push(RegisterWrite {
                register: REG_EN_RXADDR,
                value: 0x3F, // all six pipes
            });
            plan.push(RegisterWrite {
                register: REG_SETUP_AW,
                value: 0x01, // 3-byte addresses
            });
            plan.push(RegisterWrite {
                register: REG_RF_CH,
                value: channel,
            });
            plan.push(RegisterWrite {
                register: REG_RF_SETUP,
                value: rate.rf_setup_bits(),
            });
            for pipe in 0..6u8 {
                plan.push(RegisterWrite {
                    register: REG_RX_PW_P0 + pipe,
                    value: MAX_PAYLOAD,
                });
            }
        }
        Nrf24Mode::PacketCapture => {
            plan.push(RegisterWrite {
                register: REG_CONFIG,
                value: CONFIG_EN_CRC | CONFIG_CRCO | CONFIG_PWR_UP,
            });
            plan.push(RegisterWrite {
                register: REG_EN_AA,
                value: 0x00,
            });
            plan.push(RegisterWrite {
                register: REG_EN_RXADDR,
                value: 0x3F,
            });
            plan.push(RegisterWrite {
                register: REG_SETUP_AW,
                value: 0x01,
            });
            plan.push(RegisterWrite {
                register: REG_RF_CH,
                value: channel,
            });
            plan.push(RegisterWrite {
                register: REG_RF_SETUP,
                value: rate.rf_setup_bits(),
            });
            for pipe in 0..6u8 {
                plan.push(RegisterWrite {
                    register: REG_RX_PW_P0 + pipe,
                    value: MAX_PAYLOAD,
                });
            }
        }
        Nrf24Mode::LinkTest => {
            plan.push(RegisterWrite {
                register: REG_CONFIG,
                value: CONFIG_EN_CRC | CONFIG_CRCO | CONFIG_PWR_UP,
            });
            plan.push(RegisterWrite {
                register: REG_EN_AA,
                value: 0x01, // auto-ack on pipe 0
            });
            plan.push(RegisterWrite {
                register: REG_EN_RXADDR,
                value: 0x01,
            });
            plan.push(RegisterWrite {
                register: REG_SETUP_AW,
                value: 0x01,
            });
            plan.push(RegisterWrite {
                register: REG_SETUP_RETR,
                value: 0x1F, // 500 us retry delay, 15 retries
            });
            plan.push(RegisterWrite {
                register: REG_RF_CH,
                value: channel,
            });
            plan.push(RegisterWrite {
                register: REG_RF_SETUP,
                value: rate.rf_setup_bits(),
            });
            plan.push(RegisterWrite {
                register: REG_RX_PW_P0,
                value: MAX_PAYLOAD,
            });
        }
    }
    plan
}

/// Validate a configuration plan before it is written (catches impossible values
/// such as an out-of-range channel while still on the bench).
pub fn validate(plan: &[RegisterWrite]) -> Result<(), &'static str> {
    for write in plan {
        match write.register {
            REG_RF_CH if write.value > MAX_CHANNEL => return Err("RF channel out of range"),
            REG_SETUP_AW if !(0x01..=0x03).contains(&write.value) => {
                return Err("address width must be 3..5 bytes");
            }
            REG_RX_PW_P0..=REG_RX_PW_P5 if write.value == 0 || write.value > MAX_PAYLOAD => {
                return Err("payload width must be 1..32 bytes");
            }
            _ => {}
        }
    }
    Ok(())
}

/// Address bytes for the "noise" reception mode used by packet capture.
pub const NOISE_ADDRESS: [u8; 3] = [0x55, 0x55, 0x55];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_encoding_masks_register() {
        assert_eq!(read_command(REG_STATUS), 0x07);
        assert_eq!(write_command(REG_RF_CH), 0x25);
        assert_eq!(read_command(0xFF), 0x1F, "register index is masked");
    }

    #[test]
    fn channel_mapping_round_trips() {
        for channel in [0u8, 1, 76, 100, MAX_CHANNEL] {
            let freq = frequency_mhz(channel);
            assert_eq!(channel_for_mhz(freq), Some(channel));
        }
        assert_eq!(channel_for_mhz(2399), None);
        assert_eq!(channel_for_mhz(2500), Some(100));
        assert_eq!(channel_for_mhz(2526), None);
    }

    #[test]
    fn status_decoding_reports_pipe_and_events() {
        assert_eq!(rx_pipe(0x40 | (3 << 1)), Some(3));
        assert_eq!(rx_pipe(0x0E), None);
        assert!(STATUS_RX_DR & 0x40 != 0);
        assert_eq!(observe_tx(0x35), (3, 5));
    }

    #[test]
    fn spectrum_plan_disables_crc_and_opens_all_pipes() {
        let plan = configuration(Nrf24Mode::SpectrumSweep, 40, DataRate::Mbps1);
        validate(&plan).unwrap();
        assert_eq!(
            plan.iter()
                .find(|w| w.register == REG_CONFIG)
                .unwrap()
                .value,
            CONFIG_PWR_UP
        );
        assert_eq!(
            plan.iter().find(|w| w.register == REG_EN_AA).unwrap().value,
            0
        );
        assert_eq!(
            plan.iter()
                .find(|w| w.register == REG_EN_RXADDR)
                .unwrap()
                .value,
            0x3F
        );
        assert_eq!(
            plan.iter().find(|w| w.register == REG_RF_CH).unwrap().value,
            40
        );
        // All six payload-width registers are programmed.
        let widths = plan
            .iter()
            .filter(|w| (REG_RX_PW_P0..=REG_RX_PW_P5).contains(&w.register))
            .count();
        assert_eq!(widths, 6);
    }

    #[test]
    fn capture_plan_enables_crc() {
        let plan = configuration(Nrf24Mode::PacketCapture, 76, DataRate::Mbps2);
        assert_eq!(
            plan.iter()
                .find(|w| w.register == REG_CONFIG)
                .unwrap()
                .value,
            CONFIG_EN_CRC | CONFIG_CRCO | CONFIG_PWR_UP
        );
        assert_eq!(
            plan.iter()
                .find(|w| w.register == REG_RF_SETUP)
                .unwrap()
                .value,
            DataRate::Mbps2.rf_setup_bits()
        );
        validate(&plan).unwrap();
    }

    #[test]
    fn link_test_plan_adds_retries() {
        let plan = configuration(Nrf24Mode::LinkTest, 10, DataRate::Kbps250);
        assert_eq!(
            plan.iter().find(|w| w.register == REG_EN_AA).unwrap().value,
            0x01
        );
        assert_eq!(
            plan.iter()
                .find(|w| w.register == REG_SETUP_RETR)
                .unwrap()
                .value,
            0x1F
        );
        validate(&plan).unwrap();
    }

    #[test]
    fn validation_rejects_impossible_values() {
        assert!(
            validate(&[RegisterWrite {
                register: REG_RF_CH,
                value: 200
            }])
            .is_err()
        );
        assert!(
            validate(&[RegisterWrite {
                register: REG_SETUP_AW,
                value: 0
            }])
            .is_err()
        );
        assert!(
            validate(&[RegisterWrite {
                register: REG_RX_PW_P0,
                value: 0
            }])
            .is_err()
        );
        // Channel is clamped when building a plan.
        let plan = configuration(Nrf24Mode::SpectrumSweep, 250, DataRate::Mbps1);
        assert_eq!(
            plan.iter().find(|w| w.register == REG_RF_CH).unwrap().value,
            MAX_CHANNEL
        );
    }

    #[test]
    fn data_rate_bits_match_datasheet() {
        assert_eq!(DataRate::Mbps1.rf_setup_bits(), 0x06);
        assert_eq!(DataRate::Mbps2.rf_setup_bits(), 0x0E);
        assert_eq!(DataRate::Kbps250.rf_setup_bits(), 0x26);
        assert_eq!(DataRate::Mbps2.rf_setup_bits() & 0x08, 0x08, "RF_DR_HIGH");
        assert_eq!(DataRate::Kbps250.rf_setup_bits() & 0x20, 0x20, "RF_DR_LOW");
    }
}
