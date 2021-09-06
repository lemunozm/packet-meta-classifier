use crate::analyzer_cache::AnalyzerCache;
use crate::base::analyzer::Analyzer;
use crate::base::builder::Builder;
use crate::base::id::ClassifierId;
use crate::dependency_checker::DependencyChecker;
use crate::handler::builder::GenericBuilderHandler;

pub struct AnalyzerFactory<I: ClassifierId> {
    builders: Vec<Option<Box<dyn GenericBuilderHandler<I>>>>,
    ids_relations: Vec<(I, I)>,
    last_id: usize,
}

impl<I: ClassifierId> Default for AnalyzerFactory<I> {
    fn default() -> Self {
        Self {
            builders: (0..I::TOTAL).map(|_| None).collect(),
            ids_relations: Vec::default(),
            last_id: 0,
        }
    }
}

impl<I: ClassifierId> AnalyzerFactory<I> {
    pub fn builder<B>(mut self, builder: B) -> Self
    where
        B: for<'a> Builder<'a, I> + 'static,
    {
        assert!(
            B::Analyzer::ID > self.last_id.into(),
            "Expected ID with higher value than {:?}",
            B::Analyzer::ID
        );

        self.builders[B::Analyzer::ID.inner()] = Some(<dyn GenericBuilderHandler<I>>::new(builder));

        self.ids_relations
            .push((B::Analyzer::ID, B::Analyzer::PREV_ID));
        self
    }

    pub(crate) fn split(self) -> (AnalyzerCache<I>, DependencyChecker<I>) {
        (
            AnalyzerCache::new(self.builders),
            DependencyChecker::new(self.ids_relations),
        )
    }
}
