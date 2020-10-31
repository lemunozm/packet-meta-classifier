use crate::rules::rules::{Rule};
use crate::rules::matching_rules::{MatchingRuleValues};

use std::collections::{HashMap};
use std::hash::{Hash};

pub struct ClassificationRules<T> {
    rules: Vec<(T, Rule)>, // Must remain inmutable
    indexes: HashMap<T, usize>,
}

impl<T> ClassificationRules<T>
where T: Hash + Clone + Eq {
    pub fn new(rules: Vec<(T, Rule)>) -> ClassificationRules<T> {
        let indexes = rules
            .iter()
            .enumerate()
            .map(|(index, (tag, _))| (tag.clone(), index)).collect();

        ClassificationRules {
            indexes,
            rules,
        }
    }

    pub fn classify(&self, rule_values: &MatchingRuleValues) -> Option<&T> {
        for (tag, rule) in &self.rules {
            if rule_values.match_rule(&rule) {
                return Some(tag)
            }
        }
        None
    }

    pub fn rule(&self, tag: &T) -> Option<&Rule> {
        self.indexes.get(&tag).map(|index| &self.rules[*index].1)
    }

    pub fn priority(&self, tag: &T) -> Option<&usize> {
        self.indexes.get(&tag)
    }
}
