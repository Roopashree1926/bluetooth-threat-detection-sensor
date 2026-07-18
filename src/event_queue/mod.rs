use std::collections::VecDeque;

use crate::models::BluetoothEvent;

pub struct EventQueue {
    events: VecDeque<BluetoothEvent>,
    max_size: usize,
}

impl EventQueue {
    pub fn new(max_size: usize) -> Self {
        Self {
            events: VecDeque::new(),
            max_size,
        }
    }

    pub fn push(&mut self, event: BluetoothEvent) {
        if self.events.len() >= self.max_size {
            self.events.pop_front();
        }

        self.events.push_back(event);
    }

    pub fn recent(&self) -> &VecDeque<BluetoothEvent> {
        &self.events
    }
}