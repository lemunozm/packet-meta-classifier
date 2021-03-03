use super::config::Config;

use super::ClassificationRules;
use super::ClassificationState;
use super::Rule;

use crate::classifiers::{Analyzer, AnalyzerId, AnalyzerStatus, PacketInfo};
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

        let rule = loop {
            let analyzer = self.packet.choose_analyzer(analyzer_id);
            let analyzer_status = analyzer.analyze(data);
            if let AnalyzerStatus::Abort = analyzer_status {
                break None;
            }

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
                ClassificationState::None => break None,
                ClassificationState::Incompleted => (),
                ClassificationState::Completed(rule) => break Some(rule),
            };

            analyzers |= analyzer_id as u64;
            match analyzer_status {
                AnalyzerStatus::Finished(_) => break None,
                AnalyzerStatus::Next(next_analyzer_id, next_data) => {
                    data = next_data;
                    analyzer_id = next_analyzer_id;
                }
                _ => unreachable!(),
            }
        };

        ClassificationResult { rule }
    }
}
