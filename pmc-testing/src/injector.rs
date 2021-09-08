use crate::capture::CaptureIterator;
use crate::logger::{self, PacketProps};

use pmc_core::base::id::ClassifierId;
use pmc_core::engine::{ClassificationResult, ClassifierEngine};
use pmc_core::packet::{Direction, Packet};

use colored::Colorize;

pub struct Injector<T> {
    total_results: InjectionResult<T>,
    expected_classification: Vec<T>,
}

impl<T: std::fmt::Display + Default + Copy + Eq> Injector<T> {
    pub fn new(expected_classification: &[T]) -> Self {
        Self {
            total_results: InjectionResult::default(),
            expected_classification: expected_classification.to_owned(),
        }
    }

    pub fn inject_packets<C, I: ClassifierId>(
        &mut self,
        classifier: &mut ClassifierEngine<C, T, I>,
        capture_section: CaptureIterator,
    ) -> InjectionResult<T> {
        let mut current_injection_result = InjectionResult::default();

        for captured_packet in capture_section {
            logger::set_log_packet_number(Some(PacketProps {
                number: captured_packet.id,
                uplink: captured_packet.uplink,
            }));

            let packet = Packet {
                data: &captured_packet.data,
                direction: Direction::from(captured_packet.uplink),
            };

            let classification_result = classifier.classify_packet(packet);

            self.log(
                classifier.rule_tags(),
                &classification_result,
                &current_injection_result,
            );

            current_injection_result.add_packet_result(classification_result);
        }

        logger::set_log_packet_number(None);

        self.total_results.chain(&current_injection_result);
        current_injection_result
    }

    pub fn results(&self) -> &InjectionResult<T> {
        &self.total_results
    }

    fn log(
        &self,
        rule_tags: Vec<T>,
        classification_result: &ClassificationResult<T>,
        current_injection_result: &InjectionResult<T>,
    ) {
        let expected_rule_tag = self
            .expected_classification
            .get(self.total_results.len() + current_injection_result.len())
            .expect("The number of processed packet must be equals to expected");

        log::info!(
            "{} bytes classified as {} -> {}",
            format!("{:>4}", classification_result.payload_bytes).bright_magenta(),
            format!(
                "{:<tag_width$}",
                classification_result.rule_tag,
                tag_width = rule_tags
                    .iter()
                    .map(|rule_tag| format!("{}", rule_tag).len())
                    .max()
                    .unwrap_or(0),
            )
            .bright_blue(),
            if *expected_rule_tag == classification_result.rule_tag {
                format!("{}", "OK".bright_green())
            } else {
                format!(
                    "{}, expected {}",
                    "ERR".bright_red(),
                    format!("{}", expected_rule_tag).bright_blue(),
                )
            },
        );
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

    pub fn len(&self) -> usize {
        self.classifications.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn tags(&self) -> Vec<T> {
        self.classifications
            .iter()
            .map(|result| result.rule_tag)
            .collect::<Vec<T>>()
    }
}
