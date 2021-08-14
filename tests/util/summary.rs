use packet_classifier::classifier::ClassificationResult;

use std::fmt;

#[derive(Debug, Default, Clone)]
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
pub struct Summary<T> {
    results: Vec<(T, RuleResult)>,
    total_packets: usize,
    max_rule_tag_display_size: usize,
}

impl<T: fmt::Display + Eq + std::hash::Hash + Clone + Default> Summary<T> {
    pub fn new(
        mut rule_tags: Vec<T>,
        classifications: &Vec<ClassificationResult<T>>,
    ) -> Summary<T> {
        rule_tags.push(T::default());

        let results = rule_tags
            .iter()
            .map(|rule_tag| {
                let mut rule_result = RuleResult::default();
                for classification in classifications {
                    if classification.rule_tag == *rule_tag {
                        rule_result += RuleResult::from_packet(classification.bytes);
                    }
                }
                (rule_tag.clone(), rule_result)
            })
            .collect::<Vec<(T, RuleResult)>>();

        Self {
            results,
            total_packets: classifications.len(),
            max_rule_tag_display_size: rule_tags
                .iter()
                .map(|rule_tag| format!("{}", rule_tag).len())
                .max()
                .unwrap_or(0),
        }
    }
}

impl<T: fmt::Display + Default> fmt::Display for Summary<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Summary:\n")?;
        write!(f, "{:<4}Processed {} packets:\n", "", self.total_packets)?;
        for (tag, rule_result) in &self.results {
            write!(
                f,
                "{:<4} · Rule: {:<tag_width$} -> {} packets, {} bytes\n",
                "",
                tag,
                rule_result.packets,
                rule_result.bytes,
                tag_width = self.max_rule_tag_display_size
            )?;
        }
        Ok(())
    }
}
