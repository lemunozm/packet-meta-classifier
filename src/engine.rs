use super::config::Config;

use super::ClassificationRules;
use super::ClassificationState;
use super::Rule;

use crate::classifiers::{Analyzer, AnalyzerId, PacketInfo};
use crate::flow::FlowPool;

#[derive(Default)]
pub struct ClassificationResult<'a, T> {
    pub rule: Option<&'a Rule<T>>,
}

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

    pub fn process_packet(&mut self, mut data: &[u8]) -> ClassificationResult<T> {
        let mut analyzers: u64 = 0;
        let mut analyzer_id = AnalyzerId::START;

        loop {
            let analyzer = self.packet.choose_analyzer(analyzer_id);
            let (next_analyzer_kind, next_data) = analyzer.analyze(data);
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

            match self.rules.try_classify(analyzers, analyzer, flow) {
                ClassificationState::None => return ClassificationResult { rule: None },
                ClassificationState::Incompleted => (),
                ClassificationState::Completed(rule) => {
                    return ClassificationResult { rule: Some(rule) }
                }
            };

            analyzers |= analyzer_id as u64;
            data = next_data;
            match next_analyzer_kind {
                Some(next_analyzer_kind) => analyzer_id = next_analyzer_kind,
                None => break,
            }
        }

        ClassificationResult { rule: None }
    }
}
