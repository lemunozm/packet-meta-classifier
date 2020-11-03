use crate::rules::expression::{Exp};
use crate::packet_info::{PacketInfo};

pub struct Rule<T> {
    exp: Exp,
    tag: T,
    priority: usize,
}

impl<T> Rule<T> {
    fn new(exp: Exp, tag: T, priority: usize) -> Rule<T> {
        Rule { exp, tag, priority }
    }

    pub fn expression(&self) -> &Exp {
        &self.exp
    }

    pub fn tag(&self) -> &T {
        &self.tag
    }

    pub fn priority(&self) -> usize {
        self.priority
    }
}

pub struct ClassificationRules<T> {
    rules: Vec<Rule<T>>,
}

impl<T> ClassificationRules<T> {
    pub fn new(tagged_exp: Vec<(Exp, T)>) -> ClassificationRules<T> {
        let rules = tagged_exp
            .into_iter()
            .enumerate()
            .map(|(index, (exp, tag))| Rule::new(exp, tag, index + 1))
            .collect();

        ClassificationRules {
            rules,
        }
    }

    pub fn classify(&self, packet_info: &PacketInfo) -> Option<&Rule<T>> {
        for rule in &self.rules {
            if rule.expression().check(&packet_info) {
                return Some(rule)
            }
        }
        None
    }

    pub fn rule(&self, priority: usize) -> Option<&Rule<T>> {
        self.rules.get(priority)
    }
}
