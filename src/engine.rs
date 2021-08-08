use super::config::Config;

use crate::analyzer::{Analyzer, AnalyzerRegistry, AnalyzerStatus};
use crate::classifiers::{ip::analyzer::IpAnalyzer, tcp::analyzer::TcpAnalyzer, ClassifierId};
use crate::flow::FlowPool;
use crate::rule::{Exp, Rule};

use std::fmt::Display;

#[derive(Default)]
pub struct ClassificationResult<'a, T: Display> {
    pub rule: Option<&'a Rule<T>>,
}

pub struct Engine<T: Display> {
    config: Config,
    rules: Vec<Rule<T>>,
    analyzers: AnalyzerRegistry,
    flow_pool: FlowPool,
}

impl<T: Display> Engine<T> {
    pub fn new(config: Config, rule_exp: Vec<(Exp, T)>) -> Engine<T> {
        let rules = rule_exp
            .into_iter()
            .enumerate()
            .map(|(index, (exp, tag))| Rule::new(exp, tag, index + 1))
            .collect();

        let mut registry = AnalyzerRegistry::default();
        registry.add(ClassifierId::Ip, IpAnalyzer::default());
        registry.add(ClassifierId::Tcp, TcpAnalyzer::default());

        Engine {
            config,
            rules,
            analyzers: registry,
            flow_pool: FlowPool::default(),
        }
    }

    pub fn process_packet(&mut self, mut data: &[u8]) -> ClassificationResult<T> {
        let Self {
            config,
            rules,
            analyzers,
            flow_pool,
        } = self;

        let mut next_classifier_id = ClassifierId::Ip;

        for rule in rules {
            let is_validated = rule.exp.check(&mut |value| {
                while analyzers.exists_path(next_classifier_id, value.classifier_id()) {
                    let analyzer = analyzers.get_mut(next_classifier_id);
                    log::trace!("Analyze for: {:?}", next_classifier_id);
                    let analyzer_status = analyzer.analyze(data);
                    if let AnalyzerStatus::Abort = analyzer_status {
                        log::trace!("Not classified: Analysis aborted");
                        return false;
                    }

                    if let Some(flow_def) = analyzer.identify_flow() {
                        let flow = flow_pool.get_or_create(flow_def, || analyzer.create_flow());
                        log::trace!("Flow update for: {:?}", next_classifier_id);
                        flow.update(analyzer);
                    }

                    match analyzer_status {
                        AnalyzerStatus::Finished(_) => {
                            log::trace!("Analysis finished");
                            break;
                        }
                        AnalyzerStatus::Next(classifier_id, next_data) => {
                            data = next_data;
                            next_classifier_id = classifier_id;
                        }
                        _ => unreachable!(),
                    }
                }

                let analyzer = analyzers.get(next_classifier_id);
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
}
