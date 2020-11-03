use crate::configuration::{Configuration};
use crate::rules::classification::{ClassificationRules, Rule};
use crate::packet_info::{PacketInfo, Analyzer};

use std::hash::{Hash};

pub struct ClassificationResult<'a, T> {
    pub rule: Option<&'a Rule<T>>,
}

pub struct Engine<T> {
    config: Configuration,
    rules: ClassificationRules<T>,
}

impl<T> Engine<T>
where T: Hash + Clone + Eq {
    pub fn new(config: Configuration, rules: ClassificationRules<T>) -> Engine<T> {
        Engine { config, rules }
    }

    pub fn process_packet(&mut self, data: &[u8]) -> ClassificationResult<T> {
        let mut packet_info = PacketInfo::new();
        packet_info.analyze_packet(data);

        ClassificationResult {
            rule: self.rules.classify(&packet_info),
        }
    }
}
