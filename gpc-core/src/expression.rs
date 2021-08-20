use crate::base::analyzer::Analyzer;
use crate::base::expression_value::ExpressionValue;
use crate::base::flow::Flow;
use crate::base::id::ClassifierId;
use crate::handler::expression_value::{ExpressionValueHandler, GenericExpressionValueHandler};

use std::ops::{BitAnd, BitOr, Not};

pub(crate) enum ValidatedExpr {
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

pub enum Expr<I: ClassifierId> {
    #[non_exhaustive]
    Value(Box<dyn GenericExpressionValueHandler<I>>),
    #[non_exhaustive]
    Not(Box<Expr<I>>),
    #[non_exhaustive]
    All(Vec<Expr<I>>),
    #[non_exhaustive]
    Any(Vec<Expr<I>>),
    #[non_exhaustive]
    And(Box<(Expr<I>, Expr<I>)>),
    #[non_exhaustive]
    Or(Box<(Expr<I>, Expr<I>)>),
}

impl<I: ClassifierId> Expr<I> {
    pub fn value<V, A, F>(value: V) -> Expr<I>
    where
        V: ExpressionValue<I, Analyzer = A> + 'static,
        A: for<'a> Analyzer<'a, I, Flow = F>,
        F: Flow<I, Analyzer = A> + 'static,
    {
        Expr::Value(Box::new(ExpressionValueHandler::new(value)))
    }

    pub fn all(expressions: Vec<Expr<I>>) -> Expr<I> {
        Expr::All(expressions)
    }

    pub fn any(expressions: Vec<Expr<I>>) -> Expr<I> {
        Expr::Any(expressions)
    }

    pub(crate) fn check(
        &self,
        value_validator: &mut dyn FnMut(
            &Box<dyn GenericExpressionValueHandler<I>>,
        ) -> ValidatedExpr,
    ) -> ValidatedExpr {
        match self {
            Expr::Value(value) => value_validator(value),
            Expr::Not(rule) => match rule.check(value_validator) {
                ValidatedExpr::Classified => ValidatedExpr::NotClassified,
                ValidatedExpr::NotClassified => ValidatedExpr::Classified,
                ValidatedExpr::Abort => ValidatedExpr::Abort,
            },
            Expr::All(rules) => {
                for rule in rules.iter() {
                    match rule.check(value_validator) {
                        ValidatedExpr::Classified => continue,
                        ValidatedExpr::NotClassified => return ValidatedExpr::NotClassified,
                        ValidatedExpr::Abort => return ValidatedExpr::Abort,
                    }
                }
                ValidatedExpr::Classified
            }
            Expr::Any(rules) => {
                for rule in rules.iter() {
                    match rule.check(value_validator) {
                        ValidatedExpr::Classified => return ValidatedExpr::Classified,
                        ValidatedExpr::NotClassified => continue,
                        ValidatedExpr::Abort => return ValidatedExpr::Abort,
                    }
                }
                ValidatedExpr::NotClassified
            }
            Expr::And(pair) => match pair.0.check(value_validator) {
                ValidatedExpr::Classified => pair.1.check(value_validator),
                ValidatedExpr::NotClassified => ValidatedExpr::NotClassified,
                ValidatedExpr::Abort => ValidatedExpr::Abort,
            },
            Expr::Or(pair) => match pair.0.check(value_validator) {
                ValidatedExpr::Classified => ValidatedExpr::Classified,
                ValidatedExpr::NotClassified => pair.1.check(value_validator),
                ValidatedExpr::Abort => ValidatedExpr::Abort,
            },
        }
    }
}

impl<I: ClassifierId> Not for Expr<I> {
    type Output = Expr<I>;
    fn not(self) -> Expr<I> {
        Expr::Not(Box::new(self))
    }
}

impl<I: ClassifierId> BitAnd for Expr<I> {
    type Output = Expr<I>;
    fn bitand(self, expression: Expr<I>) -> Expr<I> {
        Expr::And(Box::new((self, expression)))
    }
}

impl<I: ClassifierId> BitOr for Expr<I> {
    type Output = Expr<I>;
    fn bitor(self, expression: Expr<I>) -> Expr<I> {
        Expr::Or(Box::new((self, expression)))
    }
}
