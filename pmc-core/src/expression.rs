use crate::base::classifier::Classifier;
use crate::base::config::Config;
use crate::base::expression_value::ExpressionValue;
use crate::controller::expression_value::ExpressionValueController;

use std::ops::{BitAnd, BitOr, Not};

pub(crate) enum ValidatedExpr<T> {
    Classified(bool),
    NotClassified(bool),
    Abort(Option<T>),
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

    pub(crate) fn check<T>(
        &self,
        value_validator: &mut dyn FnMut(&dyn ExpressionValueController<C>) -> ValidatedExpr<T>,
    ) -> ValidatedExpr<T> {
        match self {
            Expr::Value(value) => value_validator(value.as_ref()),
            Expr::Not(rule) => match rule.check(value_validator) {
                ValidatedExpr::Classified(should_grant) => {
                    ValidatedExpr::NotClassified(should_grant)
                }
                ValidatedExpr::NotClassified(should_grant) => {
                    ValidatedExpr::Classified(should_grant)
                }
                ValidatedExpr::Abort(granted) => ValidatedExpr::Abort(granted),
            },
            Expr::All(rules) => {
                let mut cache_result = true;
                for rule in rules.iter() {
                    match rule.check(value_validator) {
                        ValidatedExpr::Classified(should_grant) => cache_result &= should_grant,
                        ValidatedExpr::NotClassified(should_grant) => {
                            return ValidatedExpr::NotClassified(should_grant & cache_result)
                        }
                        ValidatedExpr::Abort(granted) => return ValidatedExpr::Abort(granted),
                    }
                }
                ValidatedExpr::Classified(false)
            }
            Expr::Any(rules) => {
                for rule in rules.iter() {
                    match rule.check(value_validator) {
                        ValidatedExpr::Classified(should_grant) => {
                            return ValidatedExpr::Classified(should_grant)
                        }
                        ValidatedExpr::NotClassified(_) => continue,
                        ValidatedExpr::Abort(granted) => return ValidatedExpr::Abort(granted),
                    }
                }
                ValidatedExpr::NotClassified(false)
            }
            Expr::And(pair) => match pair.0.check(value_validator) {
                ValidatedExpr::Classified(should_grant_0) => match pair.1.check(value_validator) {
                    ValidatedExpr::Classified(should_grant_1) => {
                        ValidatedExpr::Classified(should_grant_0 & should_grant_1)
                    }
                    ValidatedExpr::NotClassified(should_grant_1) => {
                        ValidatedExpr::NotClassified(should_grant_0 & should_grant_1)
                    }
                    val @ ValidatedExpr::Abort(_) => val,
                },
                val @ ValidatedExpr::NotClassified(_) => val,
                val @ ValidatedExpr::Abort(_) => val,
            },
            Expr::Or(pair) => match pair.0.check(value_validator) {
                val @ ValidatedExpr::Classified(_) => val,
                ValidatedExpr::NotClassified(_) => pair.1.check(value_validator),
                val @ ValidatedExpr::Abort(_) => val,
            },
        }
    }

    pub(crate) fn should_break(
        &self,
        value_validator: &mut dyn FnMut(&dyn ExpressionValueController<C>) -> bool,
    ) -> bool {
        match self {
            Expr::Value(value) => value_validator(value.as_ref()),
            Expr::Not(rule) => !rule.should_break(value_validator),
            Expr::All(rules) => rules.iter().all(|rule| rule.should_break(value_validator)),
            Expr::Any(rules) => rules.iter().any(|rule| rule.should_break(value_validator)),
            Expr::And(pair) => {
                pair.0.should_break(value_validator) && pair.1.should_break(value_validator)
            }
            Expr::Or(pair) => {
                pair.0.should_break(value_validator) || pair.1.should_break(value_validator)
            }
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
