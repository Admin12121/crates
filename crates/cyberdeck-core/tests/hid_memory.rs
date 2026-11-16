use cyberdeck_core::hid::{ducky, engine::HidEngine, Layout};
use std::alloc::{GlobalAlloc, Layout as AllocationLayout, System};
use std::cell::Cell;

thread_local! {
    static TRACKING: Cell<bool> = const { Cell::new(false) };
    static ALLOCATED: Cell<usize> = const { Cell::new(0) };
}
struct TrackingAllocator;
unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: AllocationLayout) -> *mut u8 {
        let _ = TRACKING.try_with(|tracking| {
            if tracking.get() { let _ = ALLOCATED.try_with(|bytes| bytes.set(bytes.get() + layout.size())); }
        });
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: AllocationLayout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: TrackingAllocator = TrackingAllocator;

#[test]
fn short_repeated_text_does_not_allocate_more_than_the_device_heap() {
    let source = format!("STRING {}\nREPEAT 1000", "a".repeat(256));
    let script = ducky::parse("repeat.txt", &source).unwrap();
    ALLOCATED.with(|bytes| bytes.set(0));
    TRACKING.with(|tracking| tracking.set(true));
    let engine = HidEngine::new(&script, Layout::Us);
    TRACKING.with(|tracking| tracking.set(false));
    let allocated = ALLOCATED.with(Cell::get);
    assert!(allocated < 16 * 1024, "small payload allocated {allocated} bytes for its plan");
    assert_eq!(engine.progress().command_total, 1001);
}

#[test]
fn repeated_commands_beyond_the_old_expansion_limit_are_not_silently_lost() {
    let source = format!("DEFAULT_DELAY 2\n{}", "STRING a\nREPEAT 1000\n".repeat(9));
    let script = ducky::parse("complete.txt", &source).unwrap();
    let mut engine = HidEngine::new(&script, Layout::Us);
    assert_eq!(engine.progress().command_total, 9010);
    let _ = engine.run_to_end(0, 1);
    assert!(engine.is_finished());
    assert_eq!(engine.typed_chars(), 9009);
    assert_eq!(engine.progress().percent, 100);
}
