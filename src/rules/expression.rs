pub trait Value<C>: std::fmt::Debug {
    fn check_value(&self, context: &C) -> bool;
}

#[derive(Debug)]
pub enum Exp<C> {
    Value(Box<dyn Value<C>>),
    Not(Box<Exp<C>>),
    And(Vec<Exp<C>>),
    Or(Vec<Exp<C>>),
}

impl<C> Exp<C> {
    pub fn value(value: impl Value<C> + 'static) -> Exp<C> {
        Exp::Value(Box::new(value))
    }

    pub fn not(rule: Exp<C>) -> Exp<C> {
        Exp::Not(Box::new(rule))
    }

    pub fn and(expressions: Vec<Exp<C>>) -> Exp<C> {
        Exp::And(expressions)
    }

    pub fn or(expressions: Vec<Exp<C>>) -> Exp<C> {
        Exp::Or(expressions)
    }

    pub fn check(&self, context: &C) -> bool {
        match self {
            Exp::Value(value) => value.check_value(context),
            Exp::Not(rule) => !rule.check(context),
            Exp::And(rules) => rules.iter().all(|rule| rule.check(context)),
            Exp::Or(rules) => rules.iter().any(|rule| rule.check(context)),
        }
    }
}
