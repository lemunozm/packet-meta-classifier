use crate::analyzer::{GenericAnalyzer, GenericAnalyzerImpl, NoAnalyzer};
use crate::classifier::id::ClassifierIdTrait;

pub struct AnalyzerCache<I: ClassifierIdTrait> {
    analyzers: Vec<Box<dyn GenericAnalyzer<I>>>,
}

impl<I: ClassifierIdTrait> AnalyzerCache<I> {
    pub fn new(analyzer_list: Vec<Box<dyn GenericAnalyzer<I>>>) -> Self {
        let mut analyzers = (0..I::TOTAL)
            .map(|_| Box::new(GenericAnalyzerImpl::new(NoAnalyzer)) as Box<dyn GenericAnalyzer<I>>)
            .collect::<Vec<_>>();

        for analyzer in analyzer_list {
            analyzers.insert(analyzer.id().inner(), analyzer);
        }

        Self { analyzers }
    }

    pub fn get(&self, id: I) -> &dyn GenericAnalyzer<I> {
        &*self.analyzers[id.inner()]
    }

    pub fn get_clean_mut(&mut self, id: I) -> &mut dyn GenericAnalyzer<I> {
        self.analyzers[id.inner()].reset();
        &mut *self.analyzers[id.inner()]
    }
}
