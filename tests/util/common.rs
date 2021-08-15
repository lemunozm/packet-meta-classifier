use packet_classifier::classifier::Classifier;
use packet_classifier::config::Config;
use packet_classifier::expression::Expr;

use super::logger;
use super::Capture;
use super::Summary;
use super::{InjectionResult, Injector};

use std::fmt;

pub struct CaptureData {
    pub name: &'static str,
    pub sections: Vec<(usize, usize)>,
}

pub struct TestConfig<T> {
    pub config: Config,
    pub rules: Vec<(T, Expr)>,
    pub captures: Vec<CaptureData>,
    pub expected_classification: Vec<T>,
}

pub fn run_classification_test<T: fmt::Debug + fmt::Display + Default + Copy + Eq>(
    test_config: TestConfig<T>,
) {
    logger::init();

    let mut classifier = Classifier::new(test_config.config, test_config.rules);
    let mut test_results = InjectionResult::default();

    for capture_data in test_config.captures {
        let capture = Capture::open(capture_data.name);
        let mut injector = Injector::new(&capture);
        for (first, last) in &capture_data.sections {
            injector.inject_packets(&mut classifier, *first, *last);
        }
        test_results.chain(injector.results());
    }

    assert_eq!(test_results, test_config.expected_classification);
    log::info!(
        "{}",
        Summary::new(classifier.rule_tags(), &test_results.classifications)
    );
}
