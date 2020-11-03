use crate::configuration::{Configuration};
use crate::rules::classification::{ClassificationRules, Rule};
use crate::packet_info::{BaseAnalyzer, Analyzer};

pub struct ClassificationResult<'a, T> {
    pub rule: Option<&'a Rule<T, BaseAnalyzer>>,
}

pub struct Engine<T> {
    config: Configuration,
    rules: ClassificationRules<T, BaseAnalyzer>,
}

impl<T> Engine<T> {
    pub fn new(config: Configuration, rules: ClassificationRules<T, BaseAnalyzer>) -> Engine<T> {
        Engine { config, rules }
    }

    pub fn process_packet(&mut self, data: &[u8]) -> ClassificationResult<T> {
        let mut analyzer = BaseAnalyzer::new();
        analyzer.analyze_packet(data);

        ClassificationResult {
            rule: self.rules.classify(&analyzer),
        }
    }
}
