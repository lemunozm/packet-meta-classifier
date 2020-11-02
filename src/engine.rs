use crate::rules::classification::{ClassificationRules};
use crate::packet_info::{PacketInfo};

use std::hash::{Hash};

pub struct Engine<T> {
    rules: ClassificationRules<T>,
}

impl<T> Engine<T>
where T: Hash + Clone + Eq + std::fmt::Debug {
    pub fn new(rules: ClassificationRules<T>) -> Engine<T> {
        Engine { rules }
    }

    pub fn process_packet(&mut self, data: &[u8]) -> Option<&T> {
        let mut packet_info = PacketInfo::new();
        //Eth::process_packet(data, &mut packet_info);
        self.rules.classify(&packet_info)
    }
}
