use crate::base::classifier::Classifier;
use crate::base::config::Config;
use crate::base::expression_value::ExpressionValue;
use crate::controller::expression_value::ExpressionValueController;

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

pub enum Expr<C: Config> {
    #[non_exhaustive]
    Value(Box<dyn ExpressionValueController<C>>),
    #[non_exhaustive]
    Not(Box<Expr<C>>),
    #[non_exhaustive]
    All(Vec<Expr<C>>),
    #[non_exhaustive]
    Any(Vec<Expr<C>>),
    #[non_exhaustive]
    And(Box<(Expr<C>, Expr<C>)>),
    #[non_exhaustive]
    Or(Box<(Expr<C>, Expr<C>)>),
}

impl<C: Config> Expr<C> {
    pub fn value<V, B>(value: V) -> Expr<C>
    where
        V: ExpressionValue<C, Classifier = B> + 'static,
        B: for<'a> Classifier<'a, C>,
    {
        Expr::Value(<dyn ExpressionValueController<C>>::new(value))
    }

    pub fn all(expressions: Vec<Expr<C>>) -> Expr<C> {
        Expr::All(expressions)
    }

    pub fn any(expressions: Vec<Expr<C>>) -> Expr<C> {
        Expr::Any(expressions)
    }

    pub(crate) fn check(
        &self,
        value_validator: &mut dyn FnMut(&dyn ExpressionValueController<C>) -> ValidatedExpr,
    ) -> ValidatedExpr {
        match self {
            Expr::Value(value) => value_validator(value.as_ref()),
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

impl<C: Config> Not for Expr<C> {
    type Output = Expr<C>;
    fn not(self) -> Expr<C> {
        Expr::Not(Box::new(self))
    }
}

impl<C: Config> BitAnd for Expr<C> {
    type Output = Expr<C>;
    fn bitand(self, expression: Expr<C>) -> Expr<C> {
        Expr::And(Box::new((self, expression)))
    }
}

impl<C: Config> BitOr for Expr<C> {
    type Output = Expr<C>;
    fn bitor(self, expression: Expr<C>) -> Expr<C> {
        Expr::Or(Box::new((self, expression)))
    }
}
