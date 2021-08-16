use packet_classifier::core::base::id::ClassifierId;
use packet_classifier::core::classifier::Classifier;
use packet_classifier::core::expression::Expr;
use packet_classifier::core::loader::AnalyzerLoader;

use super::logger;
use super::Capture;
use super::Injector;
use super::Summary;

use std::fmt;

pub struct CaptureData {
    pub name: &'static str,
    pub sections: Vec<(usize, usize)>,
}

pub struct TestConfig<C, T, I: ClassifierId> {
    pub loader: AnalyzerLoader<I>,
    pub config: C,
    pub rules: Vec<(T, Expr<I>)>,
    pub captures: Vec<CaptureData>,
    pub expected_classification: Vec<T>,
}

pub fn run_classification_test<C, T, I>(test_config: TestConfig<C, T, I>)
where
    T: fmt::Debug + fmt::Display + Default + Copy + Eq,
    I: ClassifierId,
{
    logger::init();

    for rule_tag in &test_config.expected_classification {
        test_config
            .rules
            .iter()
            .find(|(tag, _)| tag == rule_tag)
            .expect(&format!(
                "The expected classification rule '{}' must be a defined rule",
                rule_tag,
            ));
    }

    let mut classifier = Classifier::new(test_config.config, test_config.rules, test_config.loader);
    let mut injector = Injector::new(&test_config.expected_classification);

    for capture_data in test_config.captures {
        let capture = Capture::open(capture_data.name);
        for (first, last) in &capture_data.sections {
            injector.inject_packets(&mut classifier, capture.section(*first, *last));
        }
    }

    log::info!(
        "{}",
        Summary::new(classifier.rule_tags(), &injector.results().classifications)
    );

    for (index, classification) in injector.results().classifications.iter().enumerate() {
        assert_eq!(
            classification.rule_tag,
            test_config.expected_classification[index]
        );
    }
}
