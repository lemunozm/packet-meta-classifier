use crate::packet_info::{PacketInfo};

pub trait RuleValue: std::fmt::Debug {
    fn check_value(&self, packet_info: &PacketInfo) -> bool;
}

#[derive(Debug)]
pub enum Rule {
    Value(Box<dyn RuleValue>),
    Not(Box<Rule>),
    And(Vec<Rule>),
    Or(Vec<Rule>),
}

impl Rule {
    pub fn value(value: impl RuleValue + 'static) -> Rule {
        Rule::Value(Box::new(value))
    }

    pub fn not(rule: Rule) -> Rule {
        Rule::Not(Box::new(rule))
    }

    pub fn and(expressions: Vec<Rule>) -> Rule {
        Rule::And(expressions)
    }

    pub fn or(expressions: Vec<Rule>) -> Rule {
        Rule::Or(expressions)
    }
}

impl Rule {
    pub fn check(&self, packet_info: &PacketInfo) -> bool {
        match self {
            Rule::Value(value) => value.check_value(packet_info),
            Rule::Not(rule) => !rule.check(packet_info),
            Rule::And(rules) => rules.iter().all(|rule| rule.check(packet_info)),
            Rule::Or(rules) => rules.iter().any(|rule| rule.check(packet_info)),
        }
    }
}
