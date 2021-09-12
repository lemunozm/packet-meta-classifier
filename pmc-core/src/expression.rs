use crate::base::classifier::Classifier;
use crate::base::config::Config;
use crate::base::expression_value::ExpressionValue;
use crate::controller::expression_value::ExpressionValueController;

use std::ops::{BitAnd, BitOr, Not};

pub(crate) enum ValidatedExpr {
    Classified(bool),
    NotClassified(bool),
    Abort,
}

impl ValidatedExpr {
    pub fn new(value: bool, should_cache: bool) -> ValidatedExpr {
        match value {
            true => ValidatedExpr::Classified(should_cache),
            false => ValidatedExpr::NotClassified(false),
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
                ValidatedExpr::Classified(cache) => ValidatedExpr::NotClassified(cache),
                ValidatedExpr::NotClassified(cache) => ValidatedExpr::Classified(cache),
                ValidatedExpr::Abort => ValidatedExpr::Abort,
            },
            Expr::All(rules) => {
                let mut cache_result = true;
                for rule in rules.iter() {
                    match rule.check(value_validator) {
                        ValidatedExpr::Classified(cache) => cache_result &= cache,
                        ValidatedExpr::NotClassified(cache) => {
                            return ValidatedExpr::NotClassified(cache & cache_result)
                        }
                        ValidatedExpr::Abort => return ValidatedExpr::Abort,
                    }
                }
                ValidatedExpr::Classified(false)
            }
            Expr::Any(rules) => {
                for rule in rules.iter() {
                    match rule.check(value_validator) {
                        ValidatedExpr::Classified(cache) => {
                            return ValidatedExpr::Classified(cache)
                        }
                        ValidatedExpr::NotClassified(_) => continue,
                        ValidatedExpr::Abort => return ValidatedExpr::Abort,
                    }
                }
                ValidatedExpr::NotClassified(false)
            }
            Expr::And(pair) => match pair.0.check(value_validator) {
                ValidatedExpr::Classified(cache_0) => match pair.1.check(value_validator) {
                    ValidatedExpr::Classified(cache_1) => {
                        ValidatedExpr::Classified(cache_0 & cache_1)
                    }
                    ValidatedExpr::NotClassified(cache_1) => {
                        ValidatedExpr::NotClassified(cache_0 & cache_1)
                    }
                    ValidatedExpr::Abort => ValidatedExpr::Abort,
                },
                ValidatedExpr::NotClassified(cache) => ValidatedExpr::NotClassified(cache),
                ValidatedExpr::Abort => ValidatedExpr::Abort,
            },
            Expr::Or(pair) => match pair.0.check(value_validator) {
                ValidatedExpr::Classified(cache) => ValidatedExpr::Classified(cache),
                ValidatedExpr::NotClassified(_) => pair.1.check(value_validator),
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
