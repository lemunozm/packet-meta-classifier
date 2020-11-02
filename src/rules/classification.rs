use crate::rules::rule::{Rule};
use crate::packet_info::{PacketInfo};

use std::collections::{HashMap};
use std::hash::{Hash};

pub struct ClassificationRules<T> {
    rules: Vec<(Rule, T)>, // Must remain inmutable
    indexes: HashMap<T, usize>,
}

impl<T> ClassificationRules<T>
where T: Hash + Clone + Eq {
    pub fn new(rules: Vec<(Rule, T)>) -> ClassificationRules<T> {
        let indexes = rules
            .iter()
            .enumerate()
            .map(|(index, (_, tag))| (tag.clone(), index)).collect();

        ClassificationRules {
            indexes,
            rules,
        }
    }

    pub fn classify(&self, packet_info: &PacketInfo) -> Option<&T> {
        for (rule, tag) in &self.rules {
            if rule.check(&packet_info) {
                return Some(tag)
            }
        }
        None
    }

    pub fn rule(&self, tag: &T) -> Option<&Rule> {
        self.indexes.get(&tag).map(|index| &self.rules[*index].0)
    }

    pub fn priority(&self, tag: &T) -> Option<&usize> {
        self.indexes.get(&tag)
    }
}
