use super::config::Config;

use crate::analyzer::{Analyzer, AnalyzerRegistry, AnalyzerStatus, DependencyStatus};
use crate::classifiers::{ip::analyzer::IpAnalyzer, tcp::analyzer::TcpAnalyzer, ClassifierId};
use crate::flow::FlowPool;
use crate::rule::{Exp, Rule, ValidatedExp};

use std::fmt::Display;

#[derive(Default)]
pub struct ClassificationResult<'a, T: Display> {
    pub rule: Option<&'a Rule<T>>,
}

pub struct Classifier<T: Display> {
    config: Config,
    rules: Vec<Rule<T>>,
    analyzers: AnalyzerRegistry,
    flow_pool: FlowPool,
}

impl<T: Display> Classifier<T> {
    pub fn new(config: Config, rule_exp: Vec<(Exp, T)>) -> Classifier<T> {
        let rules = rule_exp
            .into_iter()
            .enumerate()
            .map(|(index, (exp, tag))| Rule::new(exp, tag, index + 1))
            .collect();

        let mut analyzers = AnalyzerRegistry::default();
        analyzers.register(IpAnalyzer::default());
        analyzers.register(TcpAnalyzer::default());

        Classifier {
            config,
            rules,
            analyzers,
            flow_pool: FlowPool::default(),
        }
    }

    pub fn classify_packet(&mut self, data: &[u8]) -> ClassificationResult<T> {
        let Self {
            config,
            rules,
            analyzers,
            flow_pool,
        } = self;

        let mut state = ClassificationState {
            data,
            next_classifier_id: ClassifierId::Ip,
            analyzers,
            flow_pool,
            finished_analysis: false,
        };

        for rule in rules {
            let validated_expression = rule.exp.check(&mut |rule_value| {
                let status = state.analyze_classification_for(rule_value.classifier_id());
                match status {
                    ClassificationStatus::CanClassify => {
                        let analyzer = state.analyzers.get(state.next_classifier_id);
                        let flow = analyzer
                            .identify_flow()
                            .map(|flow_def| state.flow_pool.get(&flow_def).unwrap());

                        let answer = rule_value.check(analyzer, flow);
                        log::trace!("Check for value: {}", answer);
                        ValidatedExp::from_bool(answer)
                    }
                    ClassificationStatus::NotClassify => ValidatedExp::NotClassified,
                    ClassificationStatus::Abort => ValidatedExp::Abort,
                }
            });

            match validated_expression {
                ValidatedExp::Classified => {
                    log::trace!("Classified: rule {}", rule.tag);
                    return ClassificationResult { rule: Some(rule) };
                }
                ValidatedExp::NotClassified => continue,
                ValidatedExp::Abort => break,
            }
        }

        log::trace!("Not classified: not rule matched");
        ClassificationResult { rule: None }
    }
}

struct ClassificationState<'a> {
    data: &'a [u8],
    next_classifier_id: ClassifierId,
    analyzers: &'a mut AnalyzerRegistry,
    flow_pool: &'a mut FlowPool,
    finished_analysis: bool,
}

enum ClassificationStatus {
    CanClassify,
    NotClassify,
    Abort,
}

impl<'a> ClassificationState<'a> {
    fn analyze_classification_for(&mut self, classifier_id: ClassifierId) -> ClassificationStatus {
        loop {
            let status = self
                .analyzers
                .check_dependencies(self.next_classifier_id, classifier_id);

            match status {
                DependencyStatus::NeedAnalysis => {
                    if self.finished_analysis {
                        return ClassificationStatus::CanClassify;
                    }

                    log::trace!("Analyze for: {:?}", self.next_classifier_id);
                    let analyzer = self.analyzers.get_clean_mut(self.next_classifier_id);
                    let analyzer_status = analyzer.analyze(self.data);
                    if let AnalyzerStatus::Abort = analyzer_status {
                        log::trace!("Analysis aborted: cannot classify");
                        break ClassificationStatus::Abort;
                    }

                    if let Some(flow_def) = analyzer.identify_flow() {
                        let flow = self
                            .flow_pool
                            .get_or_create(flow_def, || analyzer.create_flow());
                        log::trace!("Flow update for: {:?}", self.next_classifier_id);
                        flow.update(analyzer);
                    }

                    match analyzer_status {
                        AnalyzerStatus::Finished(_) => {
                            log::trace!("Analysis finished");
                            self.finished_analysis = true;
                            break match self.next_classifier_id == classifier_id {
                                true => ClassificationStatus::CanClassify,
                                false => ClassificationStatus::NotClassify,
                            };
                        }
                        AnalyzerStatus::Next(classifier_id, next_data) => {
                            self.data = next_data;
                            self.next_classifier_id = classifier_id;
                        }
                        AnalyzerStatus::Abort => unreachable!(),
                    }
                }
                DependencyStatus::Ok => break ClassificationStatus::CanClassify,
                DependencyStatus::None => break ClassificationStatus::NotClassify,
            }
        }
    }
}
