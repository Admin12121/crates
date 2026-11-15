//! Scrollable list widget shared by every menu screen.
//!
//! Runtime availability (hardware present) is displayed independently from
//! development status, so a tool can be "Requires Hardware" while another tool in
//! the same list stays usable — the mandated fault-isolation UX.

use alloc::string::String;
use alloc::vec::Vec;

/// Why an entry cannot be launched right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ItemStatus {
    /// Runnable.
    Ready,
    /// Implemented but requires a module that is not detected.
    RequiresHardware { device: &'static str },
    /// Group not implemented yet (never used for a Ready group).
    ComingSoon,
    /// An operation is running for this entry.
    Running,
}

impl ItemStatus {
    pub const fn short_label(&self) -> &'static str {
        match self {
            Self::Ready => "",
            Self::RequiresHardware { .. } => "NO HW",
            Self::ComingSoon => "SOON",
            Self::Running => "RUN",
        }
    }

    pub const fn is_selectable(&self) -> bool {
        matches!(self, Self::Ready | Self::Running)
    }
}

/// One menu row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MenuItem {
    pub label: String,
    pub status: ItemStatus,
    /// Secondary line (target, channel, count) shown next to the label.
    pub detail: Option<String>,
}

impl MenuItem {
    pub fn ready(label: &str) -> Self {
        Self {
            label: String::from(label),
            status: ItemStatus::Ready,
            detail: None,
        }
    }

    pub fn with_detail(label: &str, detail: &str) -> Self {
        Self {
            label: String::from(label),
            status: ItemStatus::Ready,
            detail: Some(String::from(detail)),
        }
    }

    pub fn requiring(label: &str, device: &'static str) -> Self {
        Self {
            label: String::from(label),
            status: ItemStatus::RequiresHardware { device },
            detail: None,
        }
    }

    pub fn coming_soon(label: &str) -> Self {
        Self {
            label: String::from(label),
            status: ItemStatus::ComingSoon,
            detail: None,
        }
    }

    /// Row text as rendered, e.g. `Wi-Fi Scan          APs 12`.
    pub fn render_line(&self, width: usize) -> String {
        let badge = self.status.short_label();
        let detail = self.detail.as_deref().unwrap_or("");
        let mut right = String::new();
        let _ = &right;
        if !badge.is_empty() {
            right.push_str(badge);
        }
        if !detail.is_empty() {
            if !right.is_empty() {
                right.push(' ');
            }
            right.push_str(detail);
        }
        if right.is_empty() {
            return super::ellipsize(&self.label, width);
        }
        let left_width = width.saturating_sub(right.chars().count() + 1).max(1);
        let left = super::ellipsize(&self.label, left_width);
        let pad = width
            .saturating_sub(left.chars().count() + right.chars().count())
            .max(1);
        let mut out = left;
        out.push_str(&" ".repeat(pad));
        out.push_str(&right);
        out
    }
}

/// Scrollable selection list.
#[derive(Debug, Default, Clone)]
pub struct MenuList {
    items: Vec<MenuItem>,
    selected: usize,
    top: usize,
    visible_rows: usize,
    title: String,
}

impl MenuList {
    pub fn new(title: &str, items: Vec<MenuItem>, visible_rows: usize) -> Self {
        Self {
            items,
            selected: 0,
            top: 0,
            visible_rows: visible_rows.max(1),
            title: String::from(title),
        }
    }

    pub fn title(&self) -> &str {
        &self.title
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn selected(&self) -> usize {
        self.selected
    }

    pub fn selected_item(&self) -> Option<&MenuItem> {
        self.items.get(self.selected)
    }

    pub fn items(&self) -> &[MenuItem] {
        &self.items
    }

    pub fn replace(&mut self, items: Vec<MenuItem>) {
        self.items = items;
        self.selected = self.selected.min(self.items.len().saturating_sub(1));
        self.clamp_scroll();
    }

    pub fn set_visible_rows(&mut self, rows: usize) {
        self.visible_rows = rows.max(1);
        self.clamp_scroll();
    }

    /// Move the selection by `delta`, skipping entries that cannot be selected.
    pub fn move_by(&mut self, delta: isize) {
        if self.items.is_empty() {
            return;
        }
        let len = self.items.len() as isize;
        let mut index = self.selected as isize;
        for _ in 0..len {
            index = (index + delta).rem_euclid(len);
            if self.items[index as usize].status.is_selectable() {
                break;
            }
        }
        self.selected = index as usize;
        self.clamp_scroll();
    }

    pub fn next(&mut self) {
        self.move_by(1);
    }

    pub fn previous(&mut self) {
        self.move_by(-1);
    }

    pub fn select(&mut self, index: usize) {
        if index < self.items.len() {
            self.selected = index;
            self.clamp_scroll();
        }
    }

    /// Rows currently visible, with their absolute indices.
    pub fn visible(&self) -> impl Iterator<Item = (usize, &MenuItem)> {
        self.items
            .iter()
            .enumerate()
            .skip(self.top)
            .take(self.visible_rows)
    }

    pub fn top(&self) -> usize {
        self.top
    }

    fn clamp_scroll(&mut self) {
        if self.selected < self.top {
            self.top = self.selected;
        } else if self.selected >= self.top + self.visible_rows {
            self.top = self.selected + 1 - self.visible_rows;
        }
        let max_top = self.items.len().saturating_sub(self.visible_rows);
        self.top = self.top.min(max_top);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(count: usize) -> MenuList {
        let items = (0..count)
            .map(|i| MenuItem::ready(&alloc::format!("Item {i}")))
            .collect();
        MenuList::new("Test", items, 4)
    }

    #[test]
    fn selection_wraps_and_scrolls() {
        let mut menu = list(6);
        assert_eq!(menu.selected(), 0);
        menu.next();
        assert_eq!(menu.selected(), 1);
        for _ in 0..5 {
            menu.next();
        }
        assert_eq!(menu.selected(), 0, "wraps to the first item");
        menu.previous();
        assert_eq!(menu.selected(), 5);
        // Scroll window follows the selection.
        assert_eq!(menu.top(), 2);
        assert_eq!(menu.visible().count(), 4);
    }

    #[test]
    fn unselectable_rows_are_skipped() {
        let items = alloc::vec![
            MenuItem::ready("Ready"),
            MenuItem::requiring("RF Monitor", "nRF24L01 radio"),
            MenuItem::coming_soon("GPS"),
            MenuItem::ready("Settings"),
        ];
        let mut menu = MenuList::new("M", items, 4);
        menu.next();
        assert_eq!(menu.selected_item().unwrap().label, "Settings");
        menu.next();
        assert_eq!(menu.selected_item().unwrap().label, "Ready");
        // Direct selection still works for detail screens.
        menu.select(1);
        assert_eq!(menu.selected(), 1);
    }

    #[test]
    fn renders_status_badges_within_width() {
        let item = MenuItem::requiring("RF Monitor", "nRF24L01 radio");
        let line = item.render_line(20);
        assert_eq!(line.chars().count(), 20);
        assert!(line.starts_with("RF Monitor"));
        assert!(line.trim_end().ends_with("NO HW"));

        let item = MenuItem::with_detail("Wi-Fi Scan", "APs 12");
        let line = item.render_line(24);
        assert!(line.ends_with("APs 12"));

        let long = MenuItem::ready("A very long menu entry that will not fit");
        let line = long.render_line(12);
        assert_eq!(line.chars().count(), 12);
        assert!(line.ends_with('~'));
    }

    #[test]
    fn replace_keeps_selection_valid() {
        let mut menu = list(6);
        menu.select(5);
        menu.replace(alloc::vec![MenuItem::ready("Only")]);
        assert_eq!(menu.selected(), 0);
        assert_eq!(menu.len(), 1);
    }
}
