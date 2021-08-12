use crate::analyzer::{Analyzer, GenericAnalyzer, GenericAnalyzerImpl};
use crate::classifiers::ClassifierId;
use crate::flow::{Flow, GenericFlow, GenericFlowImpl};

pub trait ExprValue: std::fmt::Debug {
    type Flow: Flow;
    type Analyzer: Analyzer;

    fn description() -> &'static str;
    fn check(&self, analyzer: &Self::Analyzer, flow: &Self::Flow) -> bool;
}

#[non_exhaustive]
pub enum Expr {
    Value(Box<dyn GenericValue>),
    Not(Box<Expr>),
    And(Vec<Expr>),
    Or(Vec<Expr>),
}

pub enum ValidatedExpr {
    Classified,
    NotClassified,
    Abort,
}

impl ValidatedExpr {
    pub fn from_bool(value: bool) -> ValidatedExpr {
        match value {
            true => ValidatedExpr::Classified,
            false => ValidatedExpr::NotClassified,
        }
    }
}

impl Expr {
    pub fn value<V, A, F>(value: V) -> Expr
    where
        V: ExprValue<Analyzer = A, Flow = F> + 'static,
        A: Analyzer<Flow = F> + 'static,
        F: Flow<Analyzer = A> + 'static,
    {
        Expr::Value(Box::new(GenericValueImpl::new(value)))
    }

    pub fn not(rule: Expr) -> Expr {
        Expr::Not(Box::new(rule))
    }

    pub fn and(expressions: Vec<Expr>) -> Expr {
        Expr::And(expressions)
    }

    pub fn or(expressions: Vec<Expr>) -> Expr {
        Expr::Or(expressions)
    }

    pub fn check(
        &self,
        value_validator: &mut dyn FnMut(&Box<dyn GenericValue>) -> ValidatedExpr,
    ) -> ValidatedExpr {
        match self {
            Expr::Value(value) => value_validator(value),
            Expr::Not(rule) => match rule.check(value_validator) {
                ValidatedExpr::Classified => ValidatedExpr::NotClassified,
                ValidatedExpr::NotClassified => ValidatedExpr::Classified,
                ValidatedExpr::Abort => ValidatedExpr::Abort,
            },
            Expr::And(rules) => {
                for rule in rules.iter() {
                    match rule.check(value_validator) {
                        ValidatedExpr::Classified => continue,
                        ValidatedExpr::NotClassified => return ValidatedExpr::NotClassified,
                        ValidatedExpr::Abort => return ValidatedExpr::Abort,
                    }
                }
                ValidatedExpr::Classified
            }
            Expr::Or(rules) => {
                for rule in rules.iter() {
                    match rule.check(value_validator) {
                        ValidatedExpr::Classified => return ValidatedExpr::Classified,
                        ValidatedExpr::NotClassified => continue,
                        ValidatedExpr::Abort => return ValidatedExpr::Abort,
                    }
                }
                ValidatedExpr::NotClassified
            }
        }
    }
}

pub trait GenericValue: std::fmt::Debug {
    fn check(&self, analyzer: &dyn GenericAnalyzer, flow: Option<&dyn GenericFlow>) -> bool;
    fn classifier_id(&self) -> ClassifierId;
}

struct GenericValueImpl<V> {
    value: V,
}

impl<V> GenericValueImpl<V> {
    fn new(value: V) -> Self {
        Self { value }
    }
}

impl<V: std::fmt::Debug> std::fmt::Debug for GenericValueImpl<V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.value)
    }
}

impl<V, A, F> GenericValue for GenericValueImpl<V>
where
    V: ExprValue<Analyzer = A, Flow = F>,
    A: Analyzer<Flow = F> + 'static,
    F: Flow<Analyzer = A> + 'static,
{
    fn check(&self, analyzer: &dyn GenericAnalyzer, flow: Option<&dyn GenericFlow>) -> bool {
        let analyzer = analyzer
            .as_any()
            .downcast_ref::<GenericAnalyzerImpl<A>>()
            .unwrap()
            .analyzer();

        match flow {
            Some(flow) => {
                let flow = flow
                    .as_any()
                    .downcast_ref::<GenericFlowImpl<F>>()
                    .unwrap()
                    .flow();

                self.value.check(analyzer, flow)
            }
            None => self.value.check(analyzer, &F::create(&analyzer)),
        }
    }

    fn classifier_id(&self) -> ClassifierId {
        A::ID
    }
}
