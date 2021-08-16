use crate::base::analyzer::Analyzer;
use crate::base::flow::Flow;
use crate::base::id::ClassifierId;
use crate::handler::analyzer::{AnalyzerHandler, GenericAnalyzerHandler};

pub struct AnalyzerLoader<I: ClassifierId> {
    analyzers: Vec<Box<dyn GenericAnalyzerHandler<I>>>,
}

impl<I: ClassifierId> AnalyzerLoader<I> {
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
            .push(Box::new(AnalyzerHandler::new(analyzer)));
        self
    }

    pub fn list(self) -> Vec<Box<dyn GenericAnalyzerHandler<I>>> {
        self.analyzers
    }
}
