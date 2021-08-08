use super::config::Config;

use super::{Exp, Rule};

use crate::classifiers::{Analyzer, AnalyzerId, AnalyzerStatus, PacketInfo};
use crate::flow::FlowPool;

use std::fmt::Display;

#[derive(Default)]
pub struct ClassificationResult<'a, T: Display> {
    pub rule: Option<&'a Rule<T>>,
}

pub struct Engine<T: Display> {
    config: Config,
    rules: Vec<Rule<T>>,
    packet: PacketInfo,
    flow_pool: FlowPool,
}

impl<T: Display> Engine<T> {
    pub fn new(config: Config, rule_exp: Vec<(Exp, T)>) -> Engine<T> {
        let rules = rule_exp
            .into_iter()
            .enumerate()
            .map(|(index, (exp, tag))| Rule::new(exp, tag, index + 1))
            .collect();

        Engine {
            config,
            rules,
            packet: PacketInfo::default(),
            flow_pool: FlowPool::default(),
        }
    }

    pub fn process_packet(&mut self, mut data: &[u8]) -> ClassificationResult<T> {
        let mut next_analyzer_id = AnalyzerId::START;
        let Self {
            config,
            rules,
            packet,
            flow_pool,
        } = self;

        for rule in rules {
            let is_validated = rule.exp.check(&mut |value| {
                while value.analyzer_id() > next_analyzer_id {
                    let analyzer = packet.choose_analyzer(next_analyzer_id);
                    log::trace!("Analyze for: {:?}", next_analyzer_id);
                    let analyzer_status = analyzer.analyze(data);
                    if let AnalyzerStatus::Abort = analyzer_status {
                        log::trace!("Not classified: Analysis aborted");
                        return false;
                    }

                    if let Some(flow_def) = analyzer.identify_flow() {
                        let flow = flow_pool.get_or_create(flow_def, || analyzer.create_flow());
                        log::trace!("Flow update for: {:?}", next_analyzer_id);
                        flow.update(analyzer);
                    }

                    match analyzer_status {
                        AnalyzerStatus::Finished(_) => {
                            log::trace!("Analysis finished");
                            break;
                        }
                        AnalyzerStatus::Next(analyzer_id, next_data) => {
                            data = next_data;
                            next_analyzer_id = analyzer_id;
                        }
                        _ => unreachable!(),
                    }
                }
                let analyzer = packet.choose_analyzer(value.analyzer_id());
                let flow = analyzer
                    .identify_flow()
                    .map(|flow_def| flow_pool.get(&flow_def).unwrap());

                let answer = value.check(analyzer, flow);
                log::trace!("Check for value: {}", answer);
                answer
            });

            if is_validated {
                return ClassificationResult { rule: Some(rule) };
            }
        }

        log::trace!("Not classified: Not rule matched");
        ClassificationResult { rule: None }
    }

    /*
    pub fn process_packet(&mut self, mut data: &[u8]) -> ClassificationResult<T> {
        let mut analyzers: u64 = 0;
        let mut analyzer_id = AnalyzerId::START;

        let rule = loop {
            let analyzer = self.packet.choose_analyzer(analyzer_id);
            log::trace!("Analyze for: {:?}", analyzer_id);
            let analyzer_status = analyzer.analyze(data);
            if let AnalyzerStatus::Abort = analyzer_status {
                log::trace!("Analysis aborted");
                break None;
            }

            let flow = match analyzer.identify_flow() {
                Some(flow_def) => {
                    let flow = self
                        .flow_pool
                        .get_or_create(flow_def, || analyzer.create_flow());
                    log::trace!("Flow update for: {:?}", analyzer_id);
                    flow.update(analyzer);
                    Some(&*flow)
                }
                None => None,
            };

            match self.rules.try_classify(analyzers, analyzer, flow) {
                ClassificationState::None => {
                    log::trace!("Not classified: not matching rules");
                    break None;
                }
                ClassificationState::Incompleted => {
                    log::trace!("Incomplete classification for this analyzer stage");
                }
                ClassificationState::Classified(rule) => {
                    log::trace!("Classified with {}", rule.tag);
                    break Some(rule);
                }
            };

            analyzers |= analyzer_id as u64;
            match analyzer_status {
                AnalyzerStatus::Finished(_) => {
                    log::trace!("Not classified: analysis finished");
                    break None;
                }
                AnalyzerStatus::Next(next_analyzer_id, next_data) => {
                    data = next_data;
                    analyzer_id = next_analyzer_id;
                }
                _ => unreachable!(),
            }
        };

        ClassificationResult { rule }
    }
    */
}
