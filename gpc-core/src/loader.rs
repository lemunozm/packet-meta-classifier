use crate::analyzer_cache::{AnalyzerBuilderHandler, AnalyzerCache, GenericAnalyzerBuilder};
use crate::base::analyzer::{Analyzer, AnalyzerBuilder};
use crate::base::flow::Flow;
use crate::base::id::ClassifierId;
use crate::dependency_checker::DependencyChecker;

pub struct AnalyzerFactory<I: ClassifierId> {
    builders: Vec<Option<Box<dyn GenericAnalyzerBuilder<I>>>>,
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
    pub fn builder<B, A, F>(mut self) -> Self
    where
        B: for<'b> AnalyzerBuilder<'b, I, Analyzer = A> + 'static,
        A: for<'b> Analyzer<'b, I, Flow = F>,
        F: Flow<I, Analyzer = A> + 'static,
    {
        assert!(
            A::ID > self.last_id.into(),
            "Expected ID with higher value than {:?}",
            A::ID
        );

        self.builders[B::Analyzer::ID.inner()] =
            Some(Box::new(AnalyzerBuilderHandler::<I, B>::new()));

        self.ids_relations.push((A::ID, A::PREV_ID));
        self
    }

    pub(crate) fn split(self) -> (AnalyzerCache<I>, DependencyChecker<I>) {
        (
            AnalyzerCache::new(self.builders),
            DependencyChecker::new(self.ids_relations),
        )
    }
}
