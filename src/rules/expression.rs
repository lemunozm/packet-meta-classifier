use crate::context::{Context};

pub trait Value: std::fmt::Debug {
    fn check_value(&self, context: &Context) -> bool;
}

#[derive(Debug)]
pub enum Exp {
    Value(Box<dyn Value>),
    Not(Box<Exp>),
    And(Vec<Exp>),
    Or(Vec<Exp>),
}

impl Exp {
    pub fn value(value: impl Value + 'static) -> Exp {
        Exp::Value(Box::new(value))
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

    pub fn check(&self, context: &Context) -> bool {
        match self {
            Exp::Value(value) => value.check_value(context),
            Exp::Not(rule) => !rule.check(context),
            Exp::And(rules) => rules.iter().all(|rule| rule.check(context)),
            Exp::Or(rules) => rules.iter().any(|rule| rule.check(context)),
        }
    }
}
