use crate::rules::expression::{Exp};

pub struct Rule<T, A> {
    exp: Exp<A>,
    tag: T,
    priority: usize,
}

impl<T, A> Rule<T, A> {
    fn new(exp: Exp<A>, tag: T, priority: usize) -> Rule<T, A> {
        Rule { exp, tag, priority }
    }

    pub fn expression(&self) -> &Exp<A> {
        &self.exp
    }

    pub fn tag(&self) -> &T {
        &self.tag
    }

    pub fn priority(&self) -> usize {
        self.priority
    }
}

pub struct ClassificationRules<T, A> {
    rules: Vec<Rule<T, A>>,
}

impl<T, A> ClassificationRules<T, A> {
    pub fn new(tagged_exp: Vec<(Exp<A>, T)>) -> ClassificationRules<T, A> {
        let rules = tagged_exp
            .into_iter()
            .enumerate()
            .map(|(index, (exp, tag))| Rule::new(exp, tag, index + 1))
            .collect();

        ClassificationRules { rules }
    }

    pub fn classify(&self, analyzer: &A) -> Option<&Rule<T, A>> {
        for rule in &self.rules {
            if rule.expression().check(&analyzer) {
                return Some(rule)
            }
        }
        None
    }

    pub fn rule(&self, priority: usize) -> Option<&Rule<T, A>> {
        self.rules.get(priority)
    }
}
