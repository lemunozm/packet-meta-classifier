use super::base::analyzer::NoAnalyzer;
use super::base::id::ClassifierId;
use super::handler::analyzer::{AnalyzerHandler, GenericAnalyzerHandler};

pub struct AnalyzerCache<I: ClassifierId> {
    analyzers: Vec<Box<dyn GenericAnalyzerHandler<I>>>,
}

impl<I: ClassifierId> AnalyzerCache<I> {
    pub fn new(analyzer_list: Vec<Box<dyn GenericAnalyzerHandler<I>>>) -> Self {
        let mut analyzers = (0..I::TOTAL)
            .map(|_| {
                Box::new(AnalyzerHandler::new(NoAnalyzer)) as Box<dyn GenericAnalyzerHandler<I>>
            })
            .collect::<Vec<_>>();

        for analyzer in analyzer_list {
            analyzers.insert(analyzer.id().inner(), analyzer);
        }

        Self { analyzers }
    }

    pub fn get(&self, id: I) -> &dyn GenericAnalyzerHandler<I> {
        &*self.analyzers[id.inner()]
    }

    pub fn get_clean_mut(&mut self, id: I) -> &mut dyn GenericAnalyzerHandler<I> {
        self.analyzers[id.inner()].reset();
        &mut *self.analyzers[id.inner()]
    }
}
