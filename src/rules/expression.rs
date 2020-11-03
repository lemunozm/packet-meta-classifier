pub trait Value<A>: std::fmt::Debug {
    fn check_value(&self, analyzer: &A) -> bool;
}

#[derive(Debug)]
pub enum Exp<A> {
    Value(Box<dyn Value<A>>),
    Not(Box<Exp<A>>),
    And(Vec<Exp<A>>),
    Or(Vec<Exp<A>>),
}

impl<A> Exp<A> {
    pub fn value(value: impl Value<A> + 'static) -> Exp<A> {
        Exp::Value(Box::new(value))
    }

    pub fn not(rule: Exp<A>) -> Exp<A> {
        Exp::Not(Box::new(rule))
    }

    pub fn and(expressions: Vec<Exp<A>>) -> Exp<A> {
        Exp::And(expressions)
    }

    pub fn or(expressions: Vec<Exp<A>>) -> Exp<A> {
        Exp::Or(expressions)
    }

    pub fn check(&self, analyzer: &A) -> bool {
        match self {
            Exp::Value(value) => value.check_value(analyzer),
            Exp::Not(rule) => !rule.check(analyzer),
            Exp::And(rules) => rules.iter().all(|rule| rule.check(analyzer)),
            Exp::Or(rules) => rules.iter().any(|rule| rule.check(analyzer)),
        }
    }
}
