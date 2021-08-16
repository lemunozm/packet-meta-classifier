use packet_classifier::classifier::id::ClassifierIdTrait;
use packet_classifier::classifier::loader::AnalyzerLoader;
use packet_classifier::classifier::Classifier;
use packet_classifier::expression::Expr;

use super::logger;
use super::Capture;
use super::Injector;
use super::Summary;

use std::fmt;

pub struct CaptureData {
    pub name: &'static str,
    pub sections: Vec<(usize, usize)>,
}

pub struct TestConfig<C, T, I: ClassifierIdTrait> {
    pub loader: AnalyzerLoader<I>,
    pub config: C,
    pub rules: Vec<(T, Expr<I>)>,
    pub captures: Vec<CaptureData>,
    pub expected_classification: Vec<T>,
}

pub fn run_classification_test<
    C,
    T: fmt::Debug + fmt::Display + Default + Copy + Eq,
    I: ClassifierIdTrait,
>(
    test_config: TestConfig<C, T, I>,
) {
    logger::init();

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
