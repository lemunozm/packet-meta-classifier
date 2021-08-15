use super::capture::Capture;
use super::logger;

use packet_classifier::classifier::{ClassificationResult, Classifier};

pub struct Injector<'a, T> {
    capture: &'a Capture,
    total_results: InjectionResult<T>,
}

impl<'a, T: std::fmt::Display + Default + Copy + Eq> Injector<'a, T> {
    pub fn new(capture: &'a Capture) -> Self {
        Self {
            capture,
            total_results: InjectionResult::default(),
        }
    }

    pub fn inject_packets(
        &mut self,
        classifier: &mut Classifier<T>,
        from_id: usize,
        to_id: usize,
    ) -> InjectionResult<T> {
        let mut result = InjectionResult::default();

        for packet in self.capture.iter_section(from_id, to_id) {
            logger::set_log_packet_number(Some(packet.id));

            let classification_result = classifier.classify_packet(&packet.data);
            log::info!(
                "Classified as {:<tag_width$} => {} bytes",
                classification_result.rule_tag,
                classification_result.bytes,
                tag_width = classifier
                    .rule_tags()
                    .iter()
                    .map(|rule_tag| format!("{}", rule_tag).len())
                    .max()
                    .unwrap_or(0),
            );

            result.add_packet_result(classification_result);
        }

        logger::set_log_packet_number(None);

        self.total_results.chain(&result);
        result
    }

    pub fn results(&self) -> &InjectionResult<T> {
        &self.total_results
    }
}

#[derive(Debug, Clone, Default)]
pub struct InjectionResult<T> {
    pub classifications: Vec<ClassificationResult<T>>,
}

impl<T: Copy> InjectionResult<T> {
    pub fn chain(&mut self, other: &InjectionResult<T>) {
        self.classifications.extend(other.classifications.clone());
    }

    pub fn add_packet_result(&mut self, classification: ClassificationResult<T>) {
        self.classifications.push(classification);
    }

    pub fn tags(&self) -> Vec<T> {
        self.classifications
            .iter()
            .map(|result| result.rule_tag)
            .collect::<Vec<T>>()
    }
}

impl<T: PartialEq + Copy> PartialEq<Vec<T>> for InjectionResult<T> {
    fn eq(&self, other: &Vec<T>) -> bool {
        self.classifications
            .iter()
            .map(|result| result.rule_tag)
            .collect::<Vec<T>>()
            == *other
    }
}
