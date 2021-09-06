use crate::analyzer_cache::AnalyzerCache;
use crate::base::analyzer::Analyzer;
use crate::base::classifier::Classifier;
use crate::base::id::ClassifierId;
use crate::dependency_checker::DependencyChecker;
use crate::handler::builder::GenericBuilderHandler;

pub struct ClassifierLoader<I: ClassifierId> {
    builders: Vec<Option<Box<dyn GenericBuilderHandler<I>>>>,
    ids_relations: Vec<(I, I)>,
    last_id: usize,
}

impl<I: ClassifierId> Default for ClassifierLoader<I> {
    fn default() -> Self {
        Self {
            builders: (0..I::TOTAL).map(|_| None).collect(),
            ids_relations: Vec::default(),
            last_id: 0,
        }
    }
}

impl<I: ClassifierId> ClassifierLoader<I> {
    pub fn with<C>(mut self, classifier: C) -> Self
    where
        C: for<'a> Classifier<'a, I> + 'static,
    {
        assert!(
            C::Analyzer::ID > self.last_id.into(),
            "Expected ID with higher value than {:?}",
            C::Analyzer::ID
        );

        self.builders[C::Analyzer::ID.inner()] =
            Some(<dyn GenericBuilderHandler<I>>::new(classifier));

        self.ids_relations
            .push((C::Analyzer::ID, C::Analyzer::PREV_ID));
        self
    }

    pub(crate) fn split(self) -> (AnalyzerCache<I>, DependencyChecker<I>) {
        (
            AnalyzerCache::new(self.builders),
            DependencyChecker::new(self.ids_relations),
        )
    }
}
