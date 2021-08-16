use crate::analyzer::{Analyzer, GenericAnalyzer, GenericAnalyzerImpl};
use crate::classifier::id::ClassifierIdTrait;
use crate::flow::{Flow, GenericFlow, GenericFlowImpl};

pub trait ExpressionValue<I: ClassifierIdTrait>: std::fmt::Debug {
    type Analyzer: Analyzer<I>;

    fn description() -> &'static str;
    fn check(
        &self,
        analyzer: &Self::Analyzer,
        flow: &<Self::Analyzer as Analyzer<I>>::Flow,
    ) -> bool;
}

#[non_exhaustive]
pub enum Expr<I: ClassifierIdTrait> {
    Value(Box<dyn GenericValue<I>>),
    Not(Box<Expr<I>>),
    And(Vec<Expr<I>>),
    Or(Vec<Expr<I>>),
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

impl<I: ClassifierIdTrait> Expr<I> {
    pub fn value<V, A, F>(value: V) -> Expr<I>
    where
        V: ExpressionValue<I, Analyzer = A> + 'static,
        A: Analyzer<I, Flow = F> + 'static,
        F: Flow<I, Analyzer = A> + 'static,
    {
        Expr::Value(Box::new(GenericValueImpl::new(value)))
    }

    pub fn not(rule: Expr<I>) -> Expr<I> {
        Expr::Not(Box::new(rule))
    }

    pub fn and(expressions: Vec<Expr<I>>) -> Expr<I> {
        Expr::And(expressions)
    }

    pub fn or(expressions: Vec<Expr<I>>) -> Expr<I> {
        Expr::Or(expressions)
    }

    pub fn check(
        &self,
        value_validator: &mut dyn FnMut(&Box<dyn GenericValue<I>>) -> ValidatedExpr,
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

pub trait GenericValue<I: ClassifierIdTrait>: std::fmt::Debug {
    fn check(&self, analyzer: &dyn GenericAnalyzer<I>, flow: Option<&dyn GenericFlow<I>>) -> bool;
    fn classifier_id(&self) -> I;
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

impl<V, A, F, I> GenericValue<I> for GenericValueImpl<V>
where
    V: ExpressionValue<I, Analyzer = A>,
    A: Analyzer<I, Flow = F> + 'static,
    F: Flow<I, Analyzer = A> + 'static,
    I: ClassifierIdTrait,
{
    fn check(&self, analyzer: &dyn GenericAnalyzer<I>, flow: Option<&dyn GenericFlow<I>>) -> bool {
        let analyzer = analyzer
            .as_any()
            .downcast_ref::<GenericAnalyzerImpl<A>>()
            .unwrap()
            .analyzer();

        match flow {
            Some(flow) => {
                let flow = flow
                    .as_any()
                    .downcast_ref::<GenericFlowImpl<F, I>>()
                    .unwrap()
                    .flow();

                self.value.check(analyzer, flow)
            }
            None => self.value.check(analyzer, &F::create(&analyzer)),
        }
    }

    fn classifier_id(&self) -> I {
        A::ID
    }
}
