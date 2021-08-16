use crate::analyzer::{Analyzer, GenericAnalyzer, GenericAnalyzerImpl};
use crate::classifier::ClassifierIdTrait;
use crate::flow::Flow;

pub struct AnalyzerLoader<I: ClassifierIdTrait> {
    analyzers: Vec<Box<dyn GenericAnalyzer<I>>>,
}

impl<I: ClassifierIdTrait> AnalyzerLoader<I> {
    pub fn new() -> Self {
        Self {
            analyzers: Vec::new(),
        }
    }

    pub fn load<A, F>(mut self, analyzer: A) -> Self
    where
        A: Analyzer<I, Flow = F> + 'static,
        F: Flow<I, Analyzer = A> + 'static,
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

        self.analyzers
            .push(Box::new(GenericAnalyzerImpl::new(analyzer)));
        self
    }

    pub fn list(self) -> Vec<Box<dyn GenericAnalyzer<I>>> {
        self.analyzers
    }
}
