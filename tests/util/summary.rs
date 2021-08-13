use packet_classifier::classifier::ClassificationResult;

use std::collections::{btree_map::Entry, BTreeMap};
use std::fmt;

#[derive(Default, Clone)]
struct RuleResult {
    packets: usize,
    bytes: usize,
}

impl RuleResult {
    fn from_packet(bytes: usize) -> RuleResult {
        Self { packets: 1, bytes }
    }
}

impl std::ops::AddAssign for RuleResult {
    fn add_assign(&mut self, other: Self) {
        self.packets += other.packets;
        self.bytes += other.bytes;
    }
}

#[derive(Clone, Default)]
pub struct Summary<T: Ord> {
    results: BTreeMap<T, RuleResult>,
    total_packets: usize,
    max_rule_tag_display_size: usize,
}

impl<T: fmt::Display + Eq + std::hash::Hash + Clone + Ord> Summary<T> {
    pub fn new(classifications: &Vec<ClassificationResult<T>>) -> Summary<T> {
        let mut results = BTreeMap::new();
        for classification in classifications {
            match results.entry(classification.rule.clone()) {
                Entry::Vacant(entry) => {
                    entry.insert(RuleResult::from_packet(classification.bytes));
                }
                Entry::Occupied(mut entry) => {
                    *entry.get_mut() += RuleResult::from_packet(classification.bytes);
                }
            };
        }

        let max_rule_tag_display_size = results
            .keys()
            .map(|tag| format!("{}", tag).len())
            .max()
            .unwrap_or(0);

        Self {
            results,
            total_packets: classifications.len(),
            max_rule_tag_display_size,
        }
    }
}

impl<T: fmt::Display + Default + Ord> fmt::Display for Summary<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Summary:\n")?;
        write!(f, "{:<4}Processed {} packets:\n", "", self.total_packets)?;

        let mut write_entry = |tag, rule_result: &RuleResult| {
            write!(
                f,
                "{:<4} · Rule: {:<tag_width$} -> {} packets, {} bytes\n",
                "",
                tag,
                rule_result.packets,
                rule_result.bytes,
                tag_width = self.max_rule_tag_display_size
            )
        };

        let mut default_result = RuleResult::default();
        for (tag, rule_result) in &self.results {
            if *tag == T::default() {
                default_result = rule_result.clone();
            } else {
                write_entry(tag, rule_result)?;
            }
        }

        write_entry(&T::default(), &default_result)
    }
}
