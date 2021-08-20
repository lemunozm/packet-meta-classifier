use crate::analyzer_cache::{AnalyzerBuilderHandler, AnalyzerCache, GenericAnalyzerBuilder};
use crate::base::analyzer::{Analyzer, AnalyzerBuilder};
use crate::base::flow::Flow;
use crate::base::id::ClassifierId;

struct AnalyzerFactory<I: ClassifierId> {
    builders: Vec<Option<Box<dyn GenericAnalyzerBuilder<I>>>>,
    last_id: usize,
}

impl<I: ClassifierId> Default for AnalyzerFactory<I> {
    fn default() -> Self {
        Self {
            builders: (0..I::TOTAL).map(|_| None).collect(),
            last_id: 0,
        }
    }
}

impl<I: ClassifierId> AnalyzerFactory<I> {
    fn builder<B, A, F>(mut self) -> Self
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
        self
    }

    pub(crate) fn into_cache(self) -> AnalyzerCache<I> {
        AnalyzerCache::new(self.builders)
    }
}
