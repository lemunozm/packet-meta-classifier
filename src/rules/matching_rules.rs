use crate::rules::rules::{Value, Rule};

use std::collections::{HashSet};

pub struct MatchingRuleValues {
    rules: HashSet<Value>
}

impl MatchingRuleValues {
    pub fn match_rule(&self, rule: &Rule) -> bool {
        true
    }
}
