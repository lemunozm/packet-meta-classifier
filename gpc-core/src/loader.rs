/*
use crate::base::analyzer::Analyzer;
use crate::base::flow::Flow;
use crate::base::id::ClassifierId;
use crate::handler::analyzer::GenericAnalyzerHandler;

pub trait AnalyzerBuilder<I: ClassifierId>: Sized {
    type Analyzer: Analyzer<I>;
}

pub struct AnalyzerLoader<I: ClassifierId> {
    analyzers: Vec<Box<dyn GenericAnalyzerHandler<I>>>,
}

impl<I: ClassifierId> Default for AnalyzerLoader<I> {
    fn default() -> Self {
        Self {
            analyzers: Vec::default(),
        }
    }
}

impl<I: ClassifierId> AnalyzerLoader<I> {
    pub fn load<A, F>(mut self, analyzer: A) -> Self
    where
        A: Analyzer<I, Flow = F> + 'static,
        F: Flow<A>,
    {
        let last_id = self
            .analyzers
            .last()
            .map(|analyzer| analyzer.id())
            .unwrap_or(I::NONE);

        assert!(
            A::ID > last_id,
            "Expected ID with higher value than {:?}",
            A::ID
        );

        let analyzer = <dyn GenericAnalyzerHandler<I>>::new(analyzer);
        self.analyzers.push(analyzer);
        self
    }

    pub fn list(self) -> Vec<Box<dyn GenericAnalyzerHandler<I>>> {
        self.analyzers
    }
}
*/

use crate::analyzer_cache::AnalyzerCache;
use crate::base::analyzer::Analyzer;
use crate::base::builder::Builder;
use crate::base::flow::Flow;
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
    pub fn builder<B, A, F>(mut self, builder: B) -> Self
    where
        B: Builder<I, Analyzer = A> + 'static,
        A: Analyzer<I, Flow = F>,
        F: Flow<A> + 'static,
    {
        assert!(
            A::ID > self.last_id.into(),
            "Expected ID with higher value than {:?}",
            A::ID
        );

        self.builders[B::Analyzer::ID.inner()] = Some(<dyn GenericBuilderHandler<I>>::new(builder));

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
