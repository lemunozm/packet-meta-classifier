use crate::analyzer::Analyzer;
use crate::classifiers::ClassifierId;
use crate::flow::{Flow, GenericFlow};

use std::fmt::Display;

//TODO: move to classifier
//TODO: rename to expresion.rs
//TODO: Exp to Expr
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

pub enum ValidatedExp {
    Classified,
    NotClassified,
    Abort,
}

impl ValidatedExp {
    pub fn from_bool(value: bool) -> ValidatedExp {
        match value {
            true => ValidatedExp::Classified,
            false => ValidatedExp::NotClassified,
        }
    }
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

    pub fn check(
        &self,
        value_validator: &mut dyn FnMut(&Box<dyn GenericValue>) -> ValidatedExp,
    ) -> ValidatedExp {
        match self {
            Exp::Value(value) => value_validator(value),
            Exp::Not(rule) => match rule.check(value_validator) {
                ValidatedExp::Classified => ValidatedExp::NotClassified,
                ValidatedExp::NotClassified => ValidatedExp::Classified,
                ValidatedExp::Abort => ValidatedExp::Abort,
            },
            Exp::And(rules) => {
                for rule in rules.iter() {
                    match rule.check(value_validator) {
                        ValidatedExp::Classified => continue,
                        ValidatedExp::NotClassified => return ValidatedExp::NotClassified,
                        ValidatedExp::Abort => return ValidatedExp::Abort,
                    }
                }
                ValidatedExp::Classified
            }
            Exp::Or(rules) => {
                for rule in rules.iter() {
                    match rule.check(value_validator) {
                        ValidatedExp::Classified => return ValidatedExp::Classified,
                        ValidatedExp::NotClassified => continue,
                        ValidatedExp::Abort => return ValidatedExp::Abort,
                    }
                }
                ValidatedExp::NotClassified
            }
        }
    }
}

pub trait GenericValue {
    fn check(&self, analyzer: &dyn Analyzer, flow: Option<&dyn GenericFlow>) -> bool;
    fn classifier_id(&self) -> ClassifierId;
}

struct GenericValueImpl<R: RuleValue<Analyzer = A, Flow = F>, A, F> {
    value: R,
}

impl<R: RuleValue<Analyzer = A, Flow = F>, A, F> GenericValueImpl<R, A, F> {
    fn new(value: R) -> Self {
        Self { value }
    }
}

//TODO: ClassifierValue
impl<R: RuleValue<Analyzer = A, Flow = F>, A: Analyzer + 'static, F: Flow + Default + 'static>
    GenericValue for GenericValueImpl<R, A, F>
{
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
