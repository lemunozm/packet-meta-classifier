use crate::rules::expression::{Exp};

pub struct Rule<T, C> {
    exp: Exp<C>,
    tag: T,
    priority: usize,
}

impl<T, C> Rule<T, C> {
    fn new(exp: Exp<C>, tag: T, priority: usize) -> Rule<T, C> {
        Rule { exp, tag, priority }
    }

    pub fn expression(&self) -> &Exp<C> {
        &self.exp
    }

    pub fn tag(&self) -> &T {
        &self.tag
    }

    pub fn priority(&self) -> usize {
        self.priority
    }
}

pub struct ClassificationRules<T, C> {
    rules: Vec<Rule<T, C>>,
}

impl<T, C> ClassificationRules<T, C> {
    pub fn new(tagged_exp: Vec<(Exp<C>, T)>) -> ClassificationRules<T, C> {
        let rules = tagged_exp
            .into_iter()
            .enumerate()
            .map(|(index, (exp, tag))| Rule::new(exp, tag, index + 1))
            .collect();

        ClassificationRules { rules }
    }

    pub fn classify(&self, analyzer: &C) -> Option<&Rule<T, C>> {
        for rule in &self.rules {
            if rule.expression().check(&analyzer) {
                return Some(rule)
            }
        }
        None
    }

    pub fn rule(&self, priority: usize) -> Option<&Rule<T, C>> {
        self.rules.get(priority)
    }
}
