use super::config::Config;

use crate::analyzer::{AnalyzerRegistry, AnalyzerStatus, DependencyStatus};
use crate::classifiers::{ip::analyzer::IpAnalyzer, tcp::analyzer::TcpAnalyzer, ClassifierId};
use crate::expression::{Expr, ValidatedExpr};
use crate::flow::FlowPool;

use std::fmt::Display;

pub struct Rule<T> {
    pub exp: Expr,
    pub tag: T,
}

#[derive(Clone, Default)]
pub struct ClassificationResult<T> {
    pub rule_tag: T,
    pub bytes: usize,
}

pub struct Classifier<T> {
    _config: Config,
    rules: Vec<Rule<T>>,
    analyzers: AnalyzerRegistry,
    flow_pool: FlowPool,
}

impl<T: Display + Default + Eq + Copy> Classifier<T> {
    pub fn new(_config: Config, rule_exprs: Vec<(T, Expr)>) -> Classifier<T> {
        let mut analyzers = AnalyzerRegistry::default();
        analyzers.register(IpAnalyzer::default());
        analyzers.register(TcpAnalyzer::default());

        Classifier {
            _config,
            rules: rule_exprs
                .into_iter()
                .map(|(tag, exp)| {
                    assert!(
                        tag != T::default(),
                        "The default tag value is reserved for not maching packets"
                    );
                    Rule { exp, tag }
                })
                .collect(),
            analyzers,
            flow_pool: FlowPool::default(),
        }
    }

    pub fn rule_tags(&self) -> Vec<T> {
        self.rules.iter().map(|rule| rule.tag).collect()
    }

    pub fn classify_packet(&mut self, data: &[u8]) -> ClassificationResult<T> {
        let Self {
            _config,
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

        log::trace!("Start packet classification");
        for (priority, rule) in rules.iter().enumerate() {
            log::trace!("Check rule {}: {}", priority, rule.tag);
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
                        let flow = state.flow_pool.get_cached(expr_value.classifier_id());
                        let answer = expr_value.check(analyzer, flow.as_ref().map(|flow| &**flow));

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
                        rule_tag: rule.tag,
                        bytes: data.len(),
                    };
                }
                ValidatedExpr::NotClassified => continue,
                ValidatedExpr::Abort => break,
            }
        }

        log::trace!("Not classified: not rule matched");
        ClassificationResult {
            rule_tag: T::default(),
            bytes: data.len(),
        }
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

                    self.flow_pool.update(analyzer);

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
