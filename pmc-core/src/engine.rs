use crate::analyzer_cache::{AnalyzerCache, CacheFrame};
use crate::base::analyzer::UseFlow;
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
    max_classifier_id: C::ClassifierId,
}

impl<T: Copy, C: Config> Rule<T, C> {
    pub fn new(tag: T, expr: Expr<C>) -> Self {
        Self {
            tag,
            max_classifier_id: expr.max_classifier_id(),
            expr,
        }
    }

    pub fn expr(&self) -> &Expr<C> {
        &self.expr
    }

    pub fn tag(&self) -> T {
        self.tag
    }

    pub fn max_classifier_id(&self) -> C::ClassifierId {
        self.max_classifier_id
    }
}

#[derive(Debug, Clone, Copy)]
pub enum RuleValueAction {
    Computed,
    ComputedAndCached,
    Cached,
}

#[derive(Debug, Clone)]
pub struct ClassificationResult<T> {
    pub rule_tag: T,
    pub payload_bytes: usize,
    pub rule_value_action: RuleValueAction,
}

pub struct ClassifierEngine<C: Config, T> {
    config: C,
    rules: Vec<Rule<T, C>>,
    analyzer_cache: AnalyzerCache<C>,
    dependency_checker: DependencyChecker<C::ClassifierId>,
    flow_pool: FlowPool<C>,
}

impl<C, T> ClassifierEngine<C, T>
where
    T: fmt::Display + Default + Eq + Copy,
    C: Config,
{
    pub fn new(factory: ClassifierLoader<C>, config: C, rules: Vec<Rule<T, C>>) -> Self {
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

        log::trace!(
            "Classify {} packet with {} bytes...",
            packet.direction,
            packet.data.len(),
        );

        let packet_len = packet.data.len();
        let mut state = ClassificationState {
            config,
            packet,
            skipped_bytes: 0,
            cache: analyzer_cache.prepare_for_packet(),
            flow_pool,
            current_flow_id: C::FlowId::default(),
            dependency_checker,
            last_id: C::ClassifierId::NONE,
            next_id: C::ClassifierId::INITIAL,
            last_flow_id: C::ClassifierId::NONE,
        };

        let previous_rule_max_classifier_id = C::ClassifierId::NONE;
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
                        ClassificationStatus::Abort(reason) => {
                            log::trace!("Analysis aborted. Reason: {}", reason);
                            break ValidatedExpr::Abort(None);
                        }
                        ClassificationStatus::FlowCached(associated_rule, should_classify) => {
                            let granted_rule = &rules[associated_rule];
                            let should_break = granted_rule.expr.should_break(&mut |value| {
                                let analyzer = state.cache.get(expr_value.classifier_id());
                                !value.should_grant_by_flow() || value.should_break_grant(analyzer)
                            });

                            if !should_break {
                                log::trace!("Use grant value at flow level");
                                break ValidatedExpr::Abort(Some(associated_rule));
                            }

                            log::trace!("Break grant value at flow level");

                            state
                                .flow_pool
                                .get_cached_mut(state.last_flow_id)
                                .unwrap()
                                .delete_associated_index();

                            let analyzer = state.cache.get(state.last_id);

                            log::trace!(
                                "Update {:?} flow. Sig: {:?}",
                                state.last_id,
                                state.current_flow_id
                            );

                            analyzer.update_flow(
                                state.config,
                                &mut *state.flow_pool.get_cached_mut(state.last_flow_id).unwrap(),
                                state.packet.direction,
                            );

                            match should_classify {
                                ShouldClassify::Yes => break state.check_expr_value(expr_value),
                                ShouldClassify::No => break ValidatedExpr::NotClassified(false),
                                ShouldClassify::Continue => continue,
                            }
                        }
                    }
                }
            });

            match validated_expression {
                ValidatedExpr::Classified(should_grant) => {
                    let action = match should_grant {
                        true if state.last_flow_id != C::ClassifierId::NONE => {
                            state
                                .flow_pool
                                .get_cached_mut(state.last_flow_id)
                                .unwrap()
                                .associate_index(priority);
                            RuleValueAction::ComputedAndCached
                        }
                        _ => RuleValueAction::Computed,
                    };

                    log::trace!("Classified: rule {}, action: {:?}", rule.tag, action);
                    return ClassificationResult {
                        rule_tag: rule.tag,
                        rule_value_action: action,
                        payload_bytes: packet_len - state.skipped_bytes,
                    };
                }
                ValidatedExpr::NotClassified(_) => continue,
                ValidatedExpr::Abort(granted) => match granted {
                    Some(granted_rule) => {
                        let action = RuleValueAction::Cached;
                        log::trace!("Classified: rule {}, action: {:?}", granted_rule, action);
                        return ClassificationResult {
                            rule_tag: rules[granted_rule].tag,
                            rule_value_action: action,
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
            rule_value_action: RuleValueAction::Computed,
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
    FlowCached(usize, ShouldClassify),
    Abort(&'static str),
}

struct ClassificationState<'a, C: Config> {
    config: &'a C,
    packet: Packet<'a>,
    skipped_bytes: usize,
    cache: CacheFrame<'a, C>,
    flow_pool: &'a mut FlowPool<C>,
    current_flow_id: C::FlowId,
    dependency_checker: &'a DependencyChecker<C::ClassifierId>,
    last_id: C::ClassifierId,
    next_id: C::ClassifierId,
    last_flow_id: C::ClassifierId,
}

impl<'a, C: Config> ClassificationState<'a, C> {
    fn check_expr_value(
        &self,
        expr_value: &dyn ExpressionValueController<C>,
    ) -> ValidatedExpr<usize> {
        let analyzer = self.cache.get(expr_value.classifier_id());
        let flow = self.flow_pool.get_cached(expr_value.classifier_id());
        let answer = expr_value.check(analyzer, flow.as_deref());
        log::trace!("Expression value: [{:?}] = {}", expr_value, answer);

        match answer {
            true => ValidatedExpr::Classified(expr_value.should_grant_by_flow()),
            false => ValidatedExpr::NotClassified(expr_value.should_grant_by_flow()),
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

                log::trace!("Analyze for: {:?}", self.next_id);

                let flow = match self.cache.update_flow_id(
                    self.next_id,
                    &mut self.current_flow_id,
                    &self.packet,
                ) {
                    UseFlow::Yes => {
                        let cache = &self.cache;
                        let next_id = self.next_id;
                        self.last_flow_id = self.next_id;
                        Some(self.flow_pool.get_or_create(
                            self.next_id,
                            &self.current_flow_id,
                            || cache.build_flow(next_id),
                        ))
                    }
                    UseFlow::No => None,
                    UseFlow::Abort(reason) => return ClassificationStatus::Abort(reason),
                };

                let analyzers_cached = self.cache.analyzers_cached();
                let analyzer_result = self.cache.build_analyzer(
                    self.next_id,
                    self.config,
                    &self.packet,
                    flow.as_deref(),
                );

                match analyzer_result {
                    Ok(info) => {
                        self.packet.data = &self.packet.data[info.bytes_parsed..];
                        self.last_id = self.next_id;

                        if analyzers_cached < self.config.base().skip_analyzer_bytes {
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

                        if let Some(mut flow) = flow {
                            /*
                            if let Some(associated_rule) = flow.associated_index() {
                                log::trace!("Flow with cached rule: {}", associated_rule);
                                return ClassificationStatus::FlowCached(
                                    associated_rule,
                                    should_classify,
                                );
                            }*/

                            log::trace!(
                                "Update {:?} flow. Sig: {:?}",
                                self.last_id,
                                self.current_flow_id
                            );

                            info.analyzer.update_flow(
                                self.config,
                                &mut *flow,
                                self.packet.direction,
                            );
                        }

                        match should_classify {
                            ShouldClassify::Yes => ClassificationStatus::CanClassify,
                            ShouldClassify::No => ClassificationStatus::NotClassify,
                            ShouldClassify::Continue => ClassificationStatus::NeedMoreAnalysis,
                        }
                    }
                    Err(reason) => ClassificationStatus::Abort(reason),
                }
            }
            DependencyStatus::Predecessor => ClassificationStatus::CanClassify,
            DependencyStatus::NoPath => ClassificationStatus::NotClassify,
        }
    }
}
