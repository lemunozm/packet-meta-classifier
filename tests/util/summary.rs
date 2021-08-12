use packet_classifier::classifier::ClassificationResult;

use std::collections::{btree_map::Entry, BTreeMap};
use std::fmt;

#[derive(Clone, Default)]
pub struct Summary<T: Ord> {
    rules_result: BTreeMap<T, usize>,
    total_packets: usize,
}

impl<T: Eq + std::hash::Hash + Clone + Ord> Summary<T> {
    pub fn new(classifications: &Vec<ClassificationResult<T>>) -> Summary<T> {
        let mut rules_result = BTreeMap::new();
        for classification in classifications {
            match rules_result.entry(classification.rule.clone()) {
                Entry::Vacant(entry) => {
                    entry.insert(classification.bytes);
                }
                Entry::Occupied(mut entry) => *entry.get_mut() += classification.bytes,
            };
        }

        Self {
            rules_result,
            total_packets: classifications.len(),
        }
    }
}

impl<T: fmt::Display + Default + Ord> fmt::Display for Summary<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Summary:\n")?;
        write!(f, "{:<4}Processed {} packets:\n", "", self.total_packets)?;

        let mut default_bytes = 0;
        for (tag, bytes) in &self.rules_result {
            if *tag == T::default() {
                default_bytes = *bytes;
            } else {
                write!(f, "{:<4}-> Rule: {} -> {} bytes\n", "", tag, bytes)?;
            }
        }

        write!(
            f,
            "{:<4}-> Rule: {} -> {} bytes\n",
            "",
            T::default(),
            default_bytes
        )
    }
}
