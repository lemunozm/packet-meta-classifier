use super::config::Config;

use super::ClassificationResult;
use super::ClassificationRules;
use super::ClassificationState;
use super::PacketInfo;

use crate::classifiers::{Analyzer, AnalyzerKind};
use crate::flow::FlowPool;

pub struct Engine<T> {
    config: Config,
    rules: ClassificationRules<T>,
    packet: PacketInfo,
    flow_pool: FlowPool,
}

impl<T> Engine<T> {
    pub fn new(config: Config, rules: ClassificationRules<T>) -> Engine<T> {
        Engine {
            config,
            rules,
            packet: PacketInfo::default(),
            flow_pool: FlowPool::default(),
        }
    }

    fn process_packet(&mut self, mut data: &[u8]) -> ClassificationResult<T> {
        let mut analyzers: u64 = 0;
        let mut analyzer_kind = AnalyzerKind::START;

        loop {
            let (next_analyzer_kind, next_data) = self.packet.process_for(analyzer_kind, data);
            let analyzer = &self.packet.tcp;
            let flow = match analyzer.identify_flow() {
                Some(flow_def) => {
                    let flow = self
                        .flow_pool
                        .get_or_create(flow_def, || analyzer.create_flow());
                    flow.update(analyzer);
                    Some(&*flow)
                }
                None => None,
            };

            match self.rules.try_classify(analyzers, &self.packet, flow) {
                ClassificationState::None => return ClassificationResult { rule: None },
                ClassificationState::Incompleted => (),
                ClassificationState::Completed(rule) => {
                    return ClassificationResult { rule: Some(rule) }
                }
            };

            analyzers |= analyzer_kind as u64;
            data = next_data;
            match next_analyzer_kind {
                Some(next_analyzer_kind) => analyzer_kind = next_analyzer_kind,
                None => break,
            }
        }

        ClassificationResult { rule: None }
    }
}
