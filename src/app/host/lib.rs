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
        app.handle(Button::Select); app.handle(Button::Select);
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
}
