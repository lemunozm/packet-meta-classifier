use crate::analyzer_cache::AnalyzerCache;
use crate::base::analyzer::Analyzer;
use crate::base::classifier::Classifier;
use crate::base::config::{ClassifierId, Config};
use crate::controller::classifier::ClassifierController;
use crate::dependency_checker::DependencyChecker;

pub struct ClassifierLoader<C: Config> {
    classifiers: Vec<Option<Box<dyn ClassifierController<C>>>>,
    ids_relations: Vec<(C::ClassifierId, C::ClassifierId)>,
    last_id: usize,
}

impl<C: Config> Default for ClassifierLoader<C> {
    fn default() -> Self {
        Self {
            classifiers: (0..C::ClassifierId::TOTAL).map(|_| None).collect(),
            ids_relations: Vec::default(),
            last_id: 0,
        }
    }
}

impl<C: Config> ClassifierLoader<C> {
    pub fn with<B>(mut self, classifier: B) -> Self
    where
        B: for<'a> Classifier<'a, C> + 'static,
    {
        assert!(
            B::Analyzer::ID > self.last_id.into(),
            "Expected ID with higher value than {:?}",
            B::Analyzer::ID
        );

        self.classifiers[B::Analyzer::ID.inner()] =
            Some(<dyn ClassifierController<C>>::new(classifier));

        self.ids_relations
            .push((B::Analyzer::ID, B::Analyzer::PREV_ID));
        self
    }

    pub(crate) fn split(self) -> (AnalyzerCache<C>, DependencyChecker<C::ClassifierId>) {
        (
            AnalyzerCache::new(self.classifiers),
            DependencyChecker::new(self.ids_relations),
        )
    }
}
