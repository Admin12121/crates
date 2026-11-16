//! Host harness: compile the actual firmware view with driver snapshot stubs.
extern crate alloc;

pub mod platform {
    #[derive(Debug, Clone, Copy)]
    pub enum Button { Up, Down, Select, Back, Home }
    pub mod wifi {
        #[derive(Clone)]
        pub struct ApRow {
            pub ssid: alloc::string::String,
            pub bssid: cyberdeck_core::net::MacAddr,
            pub channel: u8,
            pub rssi: i8,
            pub security: &'static str,
        }
    }
    pub mod ble {
        #[derive(Clone)]
        pub struct BleDevice {
            pub address: alloc::string::String,
            pub name: alloc::string::String,
            pub rssi: i8,
            pub kind: &'static str,
            pub detail: alloc::string::String,
        }
    }
}

#[path = "../mod.rs"]
pub mod app;

#[derive(Default)]
pub struct TestCanvas {
    pub width: u16, pub height: u16,
    pub text: String,
    pub glyphs: Vec<(i16, i16, u8)>,
}
impl TestCanvas {
    pub fn new(width:u16,height:u16)->Self { Self { width,height,..Self::default() } }
}
impl cyberdeck_core::ui::Canvas for TestCanvas {
    fn width(&self)->u16 { self.width }
    fn height(&self)->u16 { self.height }
    fn fill_rect(&mut self,_:cyberdeck_core::ui::Rect,_:cyberdeck_core::ui::Rgb565) {}
    fn draw_glyph(&mut self,x:i16,y:i16,ch:char,_:cyberdeck_core::ui::Rgb565,_:cyberdeck_core::ui::Rgb565,scale:u8) {
        self.text.push(ch); self.glyphs.push((x,y,scale));
    }
}
pub fn registry()->cyberdeck_core::PeripheralRegistry {
    use cyberdeck_core::hardware::{DeviceClass,DeviceState};
    let mut registry=cyberdeck_core::PeripheralRegistry::new();
    for class in [DeviceClass::WifiRadio,DeviceClass::BleRadio,DeviceClass::UsbDevice,DeviceClass::Nrf24,DeviceClass::Gps,DeviceClass::SdCard] {
        registry.upsert(class,DeviceState::Ready,None);
    }
    registry
}

#[cfg(test)]
mod tests {
    use super::*;
    use app::{Action,App,Live};
    use platform::Button;
    fn open_legacy(group:usize)->App {
        let mut app=App::new(registry());
        for _ in 0..group {app.handle(Button::Down);}
        app.handle(Button::Select); app.handle(Button::Select); app.handle(Button::Select);
        app
    }
    #[test]
    fn same_size_ap_change_repaints() {
        let mut app=open_legacy(0);
        let mut live=Live::default();
        live.aps.push(platform::wifi::ApRow { ssid:"Lab".into(),bssid:cyberdeck_core::net::MacAddr::new([1;6]),channel:1,rssi:-50,security:"WPA2" });
        app.set_live(live.clone()); app.take_dirty();
        live.aps[0].rssi=-70; app.set_live(live);
        assert!(app.take_dirty(),"RSSI/content changes in an unchanged-size list must repaint");
    }
    #[test]
    fn ble_frames_and_same_size_devices_repaint() {
        let mut app=open_legacy(2);
        let mut live=Live::default();
        live.ble_devices.push(platform::ble::BleDevice { address:"AA".into(),name:"Tag".into(),rssi:-40,kind:"tag",detail:"".into() });
        app.set_live(live.clone()); app.take_dirty();
        live.ble_frames=1; app.set_live(live.clone());
        assert!(app.take_dirty(),"BLE frame count must repaint");
        live.ble_devices[0].name="New tag".into(); app.set_live(live);
        assert!(app.take_dirty(),"BLE list content must repaint");
    }
    #[test]
    fn rf_envelope_and_drops_repaint_at_stable_peak() {
        let mut app=open_legacy(4);
        let mut live=Live::default(); live.rf_peak=3; live.rf_envelope=vec![1,5,2];
        app.set_live(live.clone()); app.take_dirty();
        live.rf_envelope[0]=4; app.set_live(live.clone());
        assert!(app.take_dirty(),"RF bars must repaint even if peak channel is unchanged");
        live.rf_dropped=1; app.set_live(live);
        assert!(app.take_dirty(),"RF drop count must repaint");
    }
    #[test]
    fn rendering_fits_small_panel() {
        let mut app=App::new(registry());
        let mut canvas=TestCanvas::new(128,160);
        app.render(&mut canvas);
        for (x,y,scale) in canvas.glyphs {
            assert!(x>=0 && y>=0 && x+6*i16::from(scale)<=128 && y+7*i16::from(scale)<=160,"out of bounds glyph at {x},{y} x{scale}");
        }
    }
    #[test]
    fn setup_run_stop_results_and_saved_session_navigation() {
        let mut app=App::new(registry());
        assert_eq!(app.handle(Button::Select),Action::None);
        assert_eq!(app.handle(Button::Select),Action::None,"opening setup must not start a driver");
        let mut canvas=TestCanvas::new(240,320);app.render(&mut canvas);
        assert!(canvas.text.contains("SETUP"));
        assert_eq!(app.handle(Button::Select),Action::Start(app::Tool::WifiScan));
        let mut live=Live::default();live.wifi_frames=42;app.set_live(live);
        assert_eq!(app.handle(Button::Back),Action::Stop);
        app.set_live(Live::default());
        let mut canvas=TestCanvas::new(240,320);app.render(&mut canvas);
        assert!(canvas.text.contains("RESULTS"));assert!(canvas.text.contains("42 FR"),"stopping preserves the result even when driver counters reset");
        app.handle(Button::Home);app.handle(Button::Select);app.handle(Button::Select);app.handle(Button::Up);app.handle(Button::Select);
        let mut canvas=TestCanvas::new(240,320);app.render(&mut canvas);assert!(canvas.text.contains("42 FR"));
    }
    #[test]
    fn all_seven_modules_are_reachable_without_developer_badges() {
        for index in 0..8 {
            let mut app=App::new(registry());for _ in 0..index{app.handle(Button::Down);}
            app.handle(Button::Select);
            let mut canvas=TestCanvas::new(240,320);app.render(&mut canvas);
            let expected=["Wi-Fi","Packet","Bluetooth","USB / HID","Radio","GPS","Network","Diagnostics"][index];
            assert!(canvas.text.contains(expected),"missing module {expected}");
            for clutter in ["G01","G02","BUILT","NO HW","CYBERDECK"] {assert!(!canvas.text.contains(clutter));}
        }
    }
    #[test]
    fn usb_payload_selection_layout_pause_resume_and_stop() {
        let mut app=App::new(registry());app.set_payloads(&["HID test","Text editor","Presenter"]);
        for _ in 0..3 {app.handle(Button::Down);}app.handle(Button::Select);app.handle(Button::Select);
        app.handle(Button::Down);app.handle(Button::Select);assert_eq!(app.settings().payload,1);
        app.handle(Button::Down);app.handle(Button::Select);assert_eq!(app.settings().layout,app::KeyboardLayout::Uk);
        app.handle(Button::Up);app.handle(Button::Up);
        assert_eq!(app.handle(Button::Select),Action::Start(app::Tool::HidIntro));
        assert_eq!(app.handle(Button::Select),Action::Pause(true));
        assert_eq!(app.handle(Button::Select),Action::Pause(false));
        assert_eq!(app.handle(Button::Back),Action::Stop);
    }
    #[test]
    fn unavailable_tools_explain_reason_and_never_dispatch_fake_work() {
        let mut app=App::new(cyberdeck_core::PeripheralRegistry::new());
        app.handle(Button::Select);assert_eq!(app.handle(Button::Select),Action::None);
        let mut canvas=TestCanvas::new(240,320);app.render(&mut canvas);
        assert!(canvas.text.contains("Wi-Fi radio"));
        let mut app=App::new(registry());app.set_tool_unavailable(app::Tool::WifiScan,"Disabled in simulator");
        app.handle(Button::Select);assert_eq!(app.handle(Button::Select),Action::None);
        let mut canvas=TestCanvas::new(128,160);app.render(&mut canvas);assert!(canvas.text.contains("Disabled"));
    }
    #[test]
    fn ssid_and_password_editor_supply_real_credentials() {
        let mut app=App::new(registry());app.set_tool_available(app::Tool::NetInfo);
        for _ in 0..6 {app.handle(Button::Down);}app.handle(Button::Select);app.handle(Button::Select);
        app.handle(Button::Down);app.handle(Button::Down);app.handle(Button::Select);
        app.handle(Button::Up);app.handle(Button::Select);app.handle(Button::Back);
        app.handle(Button::Down);app.handle(Button::Select);app.handle(Button::Select);app.handle(Button::Back);
        assert_eq!(app.network_credentials(),("b".into(),"a".into()));
    }

    #[test]
    fn long_wrapped_content_is_reachable_by_scrolling() {
        let mut app=App::new(registry());app.handle(Button::Select);app.handle(Button::Down);app.handle(Button::Select);app.handle(Button::Select);
        let mut live=Live::default();live.packet_lines=vec![format!("Header {} END_MARKER","X".repeat(240))];app.set_live(live);
        let mut canvas=TestCanvas::new(128,160);app.render(&mut canvas);
        for _ in 0..100 {app.handle(Button::Down);}
        let mut canvas=TestCanvas::new(128,160);app.render(&mut canvas);
        assert!(canvas.text.contains("END_MARKER"),"scroll must reach long wrapped content, not truncate a long word");
    }
    #[test]
    fn setup_and_live_content_fit_both_panel_sizes() {
        for (width,height) in [(128,160),(240,320)] {
            for group in 0..7 {
                let mut app=App::new(registry());
                for tool in [app::Tool::GpsStatus,app::Tool::NetInfo]{app.set_tool_available(tool);}
                for _ in 0..group{app.handle(Button::Down);}
                for _ in 0..3 {
                    app.handle(Button::Select);
                    let mut canvas=TestCanvas::new(width,height);app.render(&mut canvas);
                    for (x,y,scale) in canvas.glyphs {
                        assert!(x>=0&&y>=0&&x+6*i16::from(scale)<=width as i16&&y+7*i16::from(scale)<=height as i16,"group {group} glyph outside {width}x{height}");
                    }
                }
            }
        }
    }
    #[test]
    fn network_host_and_rf_settings_are_bounded() {
        let mut app=App::new(registry());app.set_tool_available(app::Tool::NetProbe);
        for _ in 0..6{app.handle(Button::Down);}app.handle(Button::Select);app.handle(Button::Down);app.handle(Button::Down);app.handle(Button::Select);app.handle(Button::Down);
        for _ in 0..600{app.handle(Button::Select);assert!((1..=254).contains(&app.settings().target));}
        app.handle(Button::Home);app.handle(Button::Up);app.handle(Button::Up);app.handle(Button::Select);app.handle(Button::Down);app.handle(Button::Select);app.handle(Button::Down);
        for _ in 0..300{app.handle(Button::Select);assert!(app.settings().channel<=125);}
        app.handle(Button::Down);
        for _ in 0..10{app.handle(Button::Select);assert!(app.settings().rf_rate<=2);}
        app.handle(Button::Down);
        for _ in 0..70{app.handle(Button::Select);assert!((1..=32).contains(&app.settings().rf_payload_len));}
    }

    fn open_setup(group: usize, tool: usize) -> App {
        let mut app = App::new(registry());
        for _ in 0..group { app.handle(Button::Down); }
        app.handle(Button::Select);
        for _ in 0..tool { app.handle(Button::Down); }
        app.handle(Button::Select);
        app
    }

    fn scanned_ap(name: &str) -> platform::wifi::ApRow {
        platform::wifi::ApRow {
            ssid: name.into(),
            bssid: cyberdeck_core::net::MacAddr::new([1; 6]),
            channel: 1,
            rssi: -50,
            security: "WPA2",
        }
    }

    #[test]
    fn scanned_network_selection_starts_with_first_ap() {
        let mut app = open_setup(6, 0);
        let mut live = Live::default();
        live.aps = vec![scanned_ap("First"), scanned_ap("Second")];
        app.set_live(live);
        app.handle(Button::Down);
        app.handle(Button::Select);
        assert_eq!(app.network_credentials().0, "First");
        app.handle(Button::Select);
        assert_eq!(app.network_credentials().0, "Second");
    }

    #[test]
    fn scanned_network_selection_normalizes_reused_host_target() {
        let mut app = open_setup(6, 2);
        app.handle(Button::Down);
        for _ in 0..5 { app.handle(Button::Select); }
        assert_eq!(app.settings().target, 6);
        app.handle(Button::Home);
        app.handle(Button::Select);
        app.handle(Button::Select);
        let mut live = Live::default();
        live.aps = vec![scanned_ap("Only network")];
        app.set_live(live);
        app.handle(Button::Down);
        app.handle(Button::Select);
        assert_eq!(app.network_credentials().0, "Only network");
        assert_eq!(app.settings().target, 0);
    }

    #[test]
    fn gatt_details_render_in_live_and_saved_results() {
        let mut app = open_setup(2, 2);
        assert_eq!(app.handle(Button::Select), Action::Start(app::Tool::BleGatt));
        let mut live = Live::default();
        live.ble_status = "GATT inspection complete".into();
        live.packet_lines = vec!["Service 180F".into(), "  Characteristic 2A19".into()];
        app.set_live(live);
        let mut canvas = TestCanvas::new(240, 320);
        app.render(&mut canvas);
        assert!(canvas.text.contains("Service 180F"));
        assert!(canvas.text.contains("Characteristic 2A19"));
        assert_eq!(app.handle(Button::Back), Action::Stop);
        app.set_live(Live::default());
        let mut canvas = TestCanvas::new(240, 320);
        app.render(&mut canvas);
        assert!(canvas.text.contains("Service 180F"));
        assert!(canvas.text.contains("Characteristic 2A19"));
    }

    #[test]
    fn ble_hid_renders_delivery_status_progress_and_pause() {
        let mut app = open_setup(2, 3);
        assert_eq!(app.handle(Button::Select), Action::Start(app::Tool::BleHid));
        let mut live = Live::default();
        live.ble_status = "Keyboard advertising".into();
        live.usb_status = "Delivering selected script".into();
        live.usb_percent = 62;
        live.usb_keystrokes = 24;
        live.usb_unsupported = 3;
        app.set_live(live);
        assert_eq!(app.handle(Button::Select), Action::Pause(true));
        let mut canvas = TestCanvas::new(240, 320);
        app.render(&mut canvas);
        for text in ["Delivering selected script", "62%", "24 KEYS", "3 UNSUPPORTED", "PAUSED"] {
            assert!(canvas.text.contains(text), "missing BLE HID status: {text}");
        }
        assert_eq!(app.handle(Button::Select), Action::Pause(false));
        assert_eq!(app.handle(Button::Back), Action::Stop);
    }

    #[test]
    fn wrapped_long_word_after_prefix_stays_within_width() {
        let lines=cyberdeck_core::ui::wrap("short ABCDEFGHIJKLMNOPQRSTUVWXYZ tail",10);
        assert!(lines.iter().all(|line|line.chars().count()<=10),"every wrapped line must fit: {lines:?}");
        assert_eq!(lines.join("").replace(' ',""),"shortABCDEFGHIJKLMNOPQRSTUVWXYZtail");
    }

}
