use super::capture::Capture;
use super::logger;

use packet_classifier::classifier::{ClassificationResult, Classifier};

pub struct Injector<'a, T> {
    classifier: &'a mut Classifier<T>,
    capture: &'a Capture,
}

impl<'a, T: std::fmt::Display + Default + Clone> Injector<'a, T> {
    pub fn new(classifier: &'a mut Classifier<T>, capture: &'a Capture) -> Self {
        Self {
            classifier,
            capture,
        }
    }

    pub fn inject_packets<'b>(&'b mut self, from_id: usize, to_id: usize) -> InjectionResult<T> {
        let mut result = InjectionResult {
            condensed: Vec::new(),
            extended: Vec::new(),
        };

        for packet in self.capture.iter_section(from_id, to_id) {
            logger::set_log_packet_number(Some(packet.id));

            let classification_result = self.classifier.classify_packet(&packet.data);
            log::info!(
                target: "framework",
                "Classified at rule {}",
                classification_result.rule
            );

            result.condensed.push(classification_result.rule.clone());
            result.extended.push(classification_result);
        }

        logger::set_log_packet_number(None);

        result
    }
}

pub struct InjectionResult<T> {
    pub condensed: Vec<T>,
    pub extended: Vec<ClassificationResult<T>>,
}
