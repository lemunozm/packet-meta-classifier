use crate::base::analyzer::Analyzer;
use crate::base::flow::Flow;
use crate::base::id::ClassifierId;
use crate::handler::analyzer::{AnalyzerHandler, GenericAnalyzerHandler};

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
        F: Flow<I, Analyzer = A>,
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
