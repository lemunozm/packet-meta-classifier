use crate::analyzer_cache::{AnalyzerCache, CacheFrame};
use crate::base::config::{ClassifierId, Config};
use crate::controller::expression_value::ExpressionValueController;
use crate::dependency_checker::{DependencyChecker, DependencyStatus};
use crate::expression::{Expr, ValidatedExpr};
use crate::flow_pool::FlowPool;
use crate::loader::ClassifierLoader;
use crate::packet::Packet;

use std::fmt;

pub struct Rule<T, C: Config> {
    tag: T,
    expr: Expr<C>,
}

impl<T: Copy, C: Config> Rule<T, C> {
    pub fn new(tag: T, expr: Expr<C>) -> Self {
        Self { tag, expr }
    }

    pub fn expr(&self) -> &Expr<C> {
        &self.expr
    }

    pub fn tag(&self) -> T {
        self.tag
    }
}

#[derive(Debug, Clone, Copy)]
pub enum RuleValueKind {
    Computed,
    ComputedAndCached,
    Cached,
}

#[derive(Debug, Clone)]
pub struct ClassificationResult<T> {
    pub rule_tag: T,
    pub payload_bytes: usize,
    pub rule_value_kind: RuleValueKind,
}

pub struct ClassifierEngine<C: Config, T> {
    config: C,
    rules: Vec<Rule<T, C>>,
    analyzer_cache: AnalyzerCache<C>,
    dependency_checker: DependencyChecker<C::ClassifierId>,
    flow_pool: FlowPool<C, usize>,
}

impl<C, T> ClassifierEngine<C, T>
where
    T: fmt::Display + Default + Eq + Copy,
    C: Config,
{
    pub fn new(config: C, rules: Vec<Rule<T, C>>, factory: ClassifierLoader<C>) -> Self {
        rules.iter().for_each(|rule| {
            assert!(
                rule.tag != T::default(),
                "The default tag value is reserved for not maching packets"
            );
        });

        let (analyzer_cache, dependency_checker) = factory.split();

        ClassifierEngine {
            rules,
            analyzer_cache,
            dependency_checker,
            flow_pool: FlowPool::new(config.base().flow_pool_initial_size),
            config,
        }
    }

    pub fn rule_tags(&self) -> Vec<T> {
        self.rules.iter().map(|rule| rule.tag).collect()
    }

    pub fn classify_packet(&mut self, packet: Packet) -> ClassificationResult<T> {
        let Self {
            config,
            rules,
            analyzer_cache,
            dependency_checker,
            flow_pool,
        } = self;

        let packet_len = packet.data.len();
        let mut state = ClassificationState {
            config,
            packet,
            skipped_bytes: 0,
            cache: analyzer_cache.prepare_for_packet(),
            flow_pool,
            dependency_checker,
            last_id: C::ClassifierId::NONE,
            next_id: C::ClassifierId::INITIAL,
        };

        state.prepare();
        for (priority, rule) in rules.iter().enumerate() {
            log::trace!("Check rule {}: {}", priority, rule.tag);
            let validated_expression = rule.expr.check(&mut |expr_value| {
                log::trace!(
                    "Check expresion value of {:?}: [{:?}]",
                    expr_value.classifier_id(),
                    expr_value
                );

                loop {
                    match state.analyze_classification_for(expr_value.classifier_id()) {
                        ClassificationStatus::CanClassify => {
                            break state.check_expr_value(expr_value)
                        }
                        ClassificationStatus::NotClassify => {
                            break ValidatedExpr::NotClassified(false)
                        }
                        ClassificationStatus::NeedMoreAnalysis => continue,
                        ClassificationStatus::Abort => break ValidatedExpr::Abort(None),
                        ClassificationStatus::Cached(rule_priority, should_classify) => {
                            /*
                            let cached_rule = &rules[rule_priority];
                            match &cached_rule.cache_flow {
                                CacheFlow::Never => unreachable!(),
                                CacheFlow::Forever => {
                                    cached_rule_tag.insert(cached_rule.tag);
                                    break ValidatedExpr::Abort;
                                }
                                CacheFlow::Until(expr) => {
                                    let should_clean_cache = expr.check(&mut |until_expr_value| {
                                        state.check_expr_value(until_expr_value)
                                    });
                                    match should_clean_cache {
                                        ValidatedExpr::Classified => {
                                            state.flow_pool.delete_value_to_last_flow();
                                            state.flow_pool.update_last_flow();
                                            match should_classify {
                                                ShouldClassify::Yes => {
                                                    break state.check_expr_value(expr_value)
                                                }
                                                ShouldClassify::No => {
                                                    break ValidatedExpr::NotClassified
                                                }
                                                ShouldClassify::Continue => continue,
                                            }
                                        }
                                        ValidatedExpr::NotClassified => {
                                            cached_rule_tag.insert(cached_rule.tag);
                                            break ValidatedExpr::Abort;
                                        }
                                        ValidatedExpr::Abort => unreachable!(),
                                    }
                                }
                            }
                            */
                            todo!()
                        }
                    }
                }
            });

            match validated_expression {
                ValidatedExpr::Classified(should_cache) => {
                    let rule_value_kind = match should_cache {
                        true => {
                            state.flow_pool.associate_value_to_last_flow(priority);
                            RuleValueKind::ComputedAndCached
                        }
                        false => RuleValueKind::Computed,
                    };

                    log::trace!("Classified: rule {}", rule.tag);
                    return ClassificationResult {
                        rule_tag: rule.tag,
                        rule_value_kind,
                        payload_bytes: packet_len - state.skipped_bytes,
                    };
                }
                ValidatedExpr::NotClassified(_) => continue,
                ValidatedExpr::Abort(cached) => match cached {
                    Some(cached_rule) => {
                        log::trace!("Classified: rule {} (cached by flow)", cached_rule);
                        return ClassificationResult {
                            rule_tag: rules[cached_rule].tag,
                            rule_value_kind: RuleValueKind::Cached,
                            payload_bytes: packet_len - state.skipped_bytes,
                        };
                    }
                    None => break,
                },
            }
        }

        log::trace!("Not classified: not rule matched");
        ClassificationResult {
            rule_tag: T::default(),
            rule_value_kind: RuleValueKind::Computed,
            payload_bytes: packet_len - state.skipped_bytes,
        }
    }
}

enum ShouldClassify {
    Yes,
    No,
    Continue,
}

enum ClassificationStatus {
    CanClassify,
    NotClassify,
    NeedMoreAnalysis,
    Cached(usize, ShouldClassify),
    Abort,
}

struct ClassificationState<'a, C: Config> {
    config: &'a C,
    packet: Packet<'a>,
    skipped_bytes: usize,
    last_id: C::ClassifierId,
    next_id: C::ClassifierId,
    cache: CacheFrame<'a, C>,
    dependency_checker: &'a DependencyChecker<C::ClassifierId>,
    flow_pool: &'a mut FlowPool<C, usize>,
}

impl<'a, C: Config> ClassificationState<'a, C> {
    fn prepare(&mut self) {
        log::trace!(
            "Start {} bytes of {} packet classification",
            self.packet.data.len(),
            self.packet.direction
        );
        self.flow_pool.prepare_for_packet();
    }

    fn check_expr_value(
        &self,
        expr_value: &dyn ExpressionValueController<C>,
    ) -> ValidatedExpr<usize> {
        let analyzer = self.cache.get(expr_value.classifier_id());
        let flow = self.flow_pool.get_cached(expr_value.classifier_id());
        let answer = expr_value.check(analyzer, flow.as_deref());
        log::trace!("Expression value: [{:?}] = {}", expr_value, answer);

        match answer {
            true => {
                let should_cache = (expr_value.classifier_id() == self.last_id)
                    && expr_value.should_grant_by_flow();
                ValidatedExpr::Classified(should_cache)
            }
            false => ValidatedExpr::NotClassified(false),
        }
    }

    fn analyze_classification_for(&mut self, id: C::ClassifierId) -> ClassificationStatus {
        match self.dependency_checker.check(self.next_id, id) {
            DependencyStatus::Descendant => {
                if self.next_id == self.last_id {
                    // The analysis is already finished
                    return match self.next_id == id {
                        true => ClassificationStatus::CanClassify,
                        false => ClassificationStatus::NotClassify,
                    };
                }

                let skip_bytes = self.cache.used() < self.config.base().skip_analyzer_bytes;

                log::trace!("Analyze for: {:?}", self.next_id);
                let analyzer_result =
                    self.cache
                        .build_analyzer(self.next_id, self.config, &self.packet);

                match analyzer_result {
                    Ok(info) => {
                        self.packet.data = &self.packet.data[info.bytes_parsed..];
                        self.last_id = self.next_id;
                        if skip_bytes {
                            self.skipped_bytes += info.bytes_parsed;
                        }

                        let should_classify = if info.next_classifier_id == ClassifierId::NONE {
                            log::trace!("Analysis finished");
                            match self.next_id == id {
                                true => ShouldClassify::Yes,
                                false => ShouldClassify::No,
                            }
                        } else {
                            self.next_id = info.next_classifier_id;
                            ShouldClassify::Continue
                        };

                        match self.flow_pool.update(
                            self.config,
                            info.analyzer,
                            self.packet.direction,
                        ) {
                            Some(priority) => {
                                ClassificationStatus::Cached(priority, should_classify)
                            }
                            None => match should_classify {
                                ShouldClassify::Yes => ClassificationStatus::CanClassify,
                                ShouldClassify::No => ClassificationStatus::NotClassify,
                                ShouldClassify::Continue => ClassificationStatus::NeedMoreAnalysis,
                            },
                        }
                    }
                    Err(reason) => {
                        log::trace!("Analysis aborted. Reason: {}", reason);
                        ClassificationStatus::Abort
                    }
                }
            }
            DependencyStatus::Predecessor => ClassificationStatus::CanClassify,
            DependencyStatus::NoPath => ClassificationStatus::NotClassify,
        }
    }
}
