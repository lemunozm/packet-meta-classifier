use crate::analyzer::Analyzer;
use crate::classifiers::ClassifierId;
use crate::flow::{Flow, GenericFlow};

pub trait ExprValue: std::fmt::Debug {
    type Flow: Flow;
    type Analyzer: Analyzer;

    fn description() -> &'static str
    where
        Self: Sized;
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
    pub fn value<A: Analyzer + 'static, F: Flow + Default + 'static>(
        value: impl ExprValue<Analyzer = A, Flow = F> + 'static,
    ) -> Expr {
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
    fn check(&self, analyzer: &dyn Analyzer, flow: Option<&dyn GenericFlow>) -> bool;
    fn classifier_id(&self) -> ClassifierId;
}

struct GenericValueImpl<R: ExprValue<Analyzer = A, Flow = F>, A, F> {
    value: R,
}

impl<R: ExprValue<Analyzer = A, Flow = F>, A, F> GenericValueImpl<R, A, F> {
    fn new(value: R) -> Self {
        Self { value }
    }
}

impl<R: ExprValue<Analyzer = A, Flow = F>, A: Analyzer + 'static, F: Flow + Default + 'static>
    std::fmt::Debug for GenericValueImpl<R, A, F>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.value)
    }
}

impl<R: ExprValue<Analyzer = A, Flow = F>, A: Analyzer + 'static, F: Flow + Default + 'static>
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
