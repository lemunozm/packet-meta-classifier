use pmc_core::base::config::Config;
use pmc_core::engine::{ClassifierEngine, Rule};
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

pub struct TestConfig<C: Config, T, R: Capture> {
    pub loader: ClassifierLoader<C>,
    pub config: C,
    pub rules: Vec<Rule<T, C>>,
    pub captures: Vec<CaptureData<R>>,
    pub expected_classification: Vec<T>,
}

pub fn run_classification_test<C, T, R>(test_config: TestConfig<C, T, R>)
where
    T: fmt::Debug + fmt::Display + Default + Copy + Eq,
    C: Config,
    R: Capture,
{
    logger::init();

    for rule_tag in &test_config.expected_classification {
        if *rule_tag != T::default() {
            test_config
                .rules
                .iter()
                .find(|rule| rule.tag() == *rule_tag)
                .unwrap_or_else(|| {
                    panic!(
                        "The expected classification rule '{}' must be a defined rule",
                        rule_tag,
                    )
                });
        }
    }

    let mut classifier =
        ClassifierEngine::<C, T>::new(test_config.loader, test_config.config, test_config.rules);
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
