use crate::analyzer::Analyzer;
use crate::classifiers::ClassifierId;
use crate::flow::{Flow, GenericFlow};

use std::fmt::Display;

pub struct Rule<T: Display> {
    pub exp: Exp,
    pub tag: T,
    pub priority: usize,
}

impl<T: Display> Rule<T> {
    pub fn new(exp: Exp, tag: T, priority: usize) -> Self {
        Self { exp, tag, priority }
    }
}

pub trait RuleValue: std::fmt::Debug {
    type Flow: Flow;
    type Analyzer: Analyzer;

    fn description() -> &'static str
    where
        Self: Sized;
    fn check(&self, analyzer: &Self::Analyzer, flow: &Self::Flow) -> bool;
}

#[non_exhaustive]
pub enum Exp {
    Value(Box<dyn GenericValue>),
    Not(Box<Exp>),
    And(Vec<Exp>),
    Or(Vec<Exp>),
}

impl Exp {
    pub fn value<A: Analyzer + 'static, F: Flow + Default + 'static>(
        value: impl RuleValue<Analyzer = A, Flow = F> + 'static,
    ) -> Exp {
        Exp::Value(Box::new(GenericValueImpl::new(value)))
    }

    pub fn not(rule: Exp) -> Exp {
        Exp::Not(Box::new(rule))
    }

    pub fn and(expressions: Vec<Exp>) -> Exp {
        Exp::And(expressions)
    }

    pub fn or(expressions: Vec<Exp>) -> Exp {
        Exp::Or(expressions)
    }

    pub fn check(&self, value_validator: &mut dyn FnMut(&Box<dyn GenericValue>) -> bool) -> bool {
        match self {
            Exp::Value(value) => value_validator(value),
            Exp::Not(rule) => !rule.check(value_validator),
            Exp::And(rules) => rules.iter().all(|rule| rule.check(value_validator)),
            Exp::Or(rules) => rules.iter().any(|rule| rule.check(value_validator)),
        }
    }
}

pub trait GenericValue {
    fn check(&self, analyzer: &dyn Analyzer, flow: Option<&dyn GenericFlow>) -> bool;
    fn classifier_id(&self) -> ClassifierId;
}

struct GenericValueImpl<A, F> {
    //TODO: remove Box?
    value: Box<dyn RuleValue<Analyzer = A, Flow = F>>,
}

impl<A, F> GenericValueImpl<A, F> {
    fn new(value: impl RuleValue<Analyzer = A, Flow = F> + 'static) -> Self {
        Self {
            value: Box::new(value),
        }
    }
}

impl<A: Analyzer + 'static, F: Flow + Default + 'static> GenericValue for GenericValueImpl<A, F> {
    fn check(&self, analyzer: &dyn Analyzer, flow: Option<&dyn GenericFlow>) -> bool {
        let analyzer = analyzer.as_any().downcast_ref::<A>().unwrap();
        match flow {
            Some(flow) => {
                let flow = flow.as_any().downcast_ref::<F>().unwrap();
                self.value.check(analyzer, flow)
            }
            None => self.value.check(analyzer, &F::default()),
        }
    }

    fn classifier_id(&self) -> ClassifierId {
        A::classifier_id()
    }
}
