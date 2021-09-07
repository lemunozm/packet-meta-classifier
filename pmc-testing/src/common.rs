use pmc_core::base::id::ClassifierId;
use pmc_core::engine::ClassifierEngine;
use pmc_core::expression::Expr;
use pmc_core::loader::ClassifierLoader;

use crate::capture::Capture;
use crate::injector::Injector;
use crate::logger::{self};
use crate::summary::Summary;

use std::fmt::{self};

pub struct CaptureData<R: Capture> {
    pub capture: R,
    pub sections: Vec<(usize, usize)>,
}

pub struct TestConfig<C, T, I: ClassifierId, R: Capture> {
    pub loader: ClassifierLoader<I>,
    pub config: C,
    pub rules: Vec<(T, Expr<I>)>,
    pub captures: Vec<CaptureData<R>>,
    pub expected_classification: Vec<T>,
}

pub fn run_classification_test<C, T, I, R>(test_config: TestConfig<C, T, I, R>)
where
    T: fmt::Debug + fmt::Display + Default + Copy + Eq,
    I: ClassifierId,
    R: Capture,
{
    logger::init();

    for rule_tag in &test_config.expected_classification {
        if *rule_tag != T::default() {
            test_config
                .rules
                .iter()
                .find(|(tag, _)| tag == rule_tag)
                .unwrap_or_else(|| {
                    panic!(
                        "The expected classification rule '{}' must be a defined rule",
                        rule_tag,
                    )
                });
        }
    }

    let mut classifier =
        ClassifierEngine::<C, T, I>::new(test_config.config, test_config.rules, test_config.loader);
    let mut injector = Injector::new(&test_config.expected_classification);

    for capture_data in test_config.captures {
        for (first, last) in &capture_data.sections {
            injector.inject_packets(&mut classifier, capture_data.capture.section(*first, *last));
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
