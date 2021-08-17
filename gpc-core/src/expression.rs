use crate::base::analyzer::Analyzer;
use crate::base::expression_value::ExpressionValue;
use crate::base::flow::Flow;
use crate::base::id::ClassifierId;
use crate::handler::expression_value::{ExpressionValueHandler, GenericExpressionValueHandler};

use std::ops::Not;

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

#[non_exhaustive]
pub enum Expr<I: ClassifierId> {
    Value(Box<dyn GenericExpressionValueHandler<I>>),
    Not(Box<Expr<I>>),
    And(Vec<Expr<I>>),
    Or(Vec<Expr<I>>),
}

impl<I: ClassifierId> Expr<I> {
    pub fn value<V, A, F>(value: V) -> Expr<I>
    where
        V: ExpressionValue<I, Analyzer = A>,
        A: Analyzer<I, Flow = F>,
        F: Flow<I, Analyzer = A>,
    {
        Expr::Value(Box::new(ExpressionValueHandler::new(value)))
    }

    pub fn and(expressions: Vec<Expr<I>>) -> Expr<I> {
        Expr::And(expressions)
    }

    pub fn or(expressions: Vec<Expr<I>>) -> Expr<I> {
        Expr::Or(expressions)
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

impl<I: ClassifierId> Not for Expr<I> {
    type Output = Expr<I>;
    fn not(self) -> Expr<I> {
        Expr::Not(Box::new(self))
    }
}
