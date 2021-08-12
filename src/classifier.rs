use super::config::Config;

use crate::analyzer::{AnalyzerRegistry, AnalyzerStatus, DependencyStatus};
use crate::classifiers::{ip::analyzer::IpAnalyzer, tcp::analyzer::TcpAnalyzer, ClassifierId};
use crate::expression::{Expr, ValidatedExpr};
use crate::flow::FlowPool;

use std::fmt::Display;

use std::collections::HashMap;

struct Rule<T> {
    pub exp: Expr,
    pub tag: T,
    pub priority: usize,
}

impl<T> Rule<T> {
    pub fn new(exp: Expr, tag: T, priority: usize) -> Self {
        Self { exp, tag, priority }
    }
}

#[derive(Default)]
pub struct ClassificationResult<T> {
    pub rule: T,
}

pub struct Classifier<T> {
    config: Config,
    rules: Vec<Rule<T>>,
    analyzers: AnalyzerRegistry,
    flow_pool: FlowPool,
}

impl<T: Display + Default + Clone> Classifier<T> {
    pub fn new(config: Config, rule_exp: Vec<(Expr, T)>) -> Classifier<T> {
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
            flow_signature: Vec::with_capacity(16),
            flow_signature_level: HashMap::new(),
            flow_pool,
            finished_analysis: false,
        };

        log::trace!("Start packet classification");
        for rule in rules {
            log::trace!("Check rule {}: {}", rule.priority, rule.tag);
            let validated_expression = rule.exp.check(&mut |expr_value| {
                log::trace!(
                    "Check expresion value of {:?}: [{:?}]",
                    expr_value.classifier_id(),
                    expr_value
                );
                let status = state.analyze_classification_for(expr_value.classifier_id());
                match status {
                    ClassificationStatus::CanClassify => {
                        let analyzer = state.analyzers.get(expr_value.classifier_id());
                        //TODO: state.get_flow(classifier_id, flow_signature)
                        let flow = state
                            .flow_signature_level
                            .get(&expr_value.classifier_id())
                            .map(|flow_signature| {
                                state
                                    .flow_pool
                                    .get(expr_value.classifier_id(), &flow_signature)
                                    .unwrap()
                            });

                        let answer = expr_value.check(analyzer, flow);
                        log::trace!("Expression value: [{:?}] = {}", expr_value, answer);
                        ValidatedExpr::from_bool(answer)
                    }
                    ClassificationStatus::NotClassify => ValidatedExpr::NotClassified,
                    ClassificationStatus::Abort => ValidatedExpr::Abort,
                }
            });

            match validated_expression {
                ValidatedExpr::Classified => {
                    log::trace!("Classified: rule {}", rule.tag);
                    return ClassificationResult {
                        rule: rule.tag.clone(),
                    };
                }
                ValidatedExpr::NotClassified => continue,
                ValidatedExpr::Abort => break,
            }
        }

        log::trace!("Not classified: not rule matched");
        ClassificationResult { rule: T::default() }
    }
}

struct ClassificationState<'a> {
    data: &'a [u8],
    next_classifier_id: ClassifierId,
    analyzers: &'a mut AnalyzerRegistry,
    flow_signature: Vec<u8>,
    flow_signature_level: HashMap<ClassifierId, Vec<u8>>, //Already initialized
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

                    if analyzer.update_flow_signature(&mut self.flow_signature) {
                        let flow_signature = &self.flow_signature;
                        let next_classifier_id = self.next_classifier_id;

                        let flow = self.flow_pool.get_mut_or_create(
                            next_classifier_id,
                            flow_signature,
                            || {
                                log::trace!(
                                    "Create flow [{:?}] for: {:?}",
                                    flow_signature,
                                    next_classifier_id
                                );
                                analyzer.create_flow()
                            },
                        );

                        log::trace!(
                            "Update flow [{:?}] for: {:?}",
                            flow_signature,
                            next_classifier_id
                        );
                        flow.update(analyzer);

                        self.flow_signature_level
                            .insert(next_classifier_id, flow_signature.clone());
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
