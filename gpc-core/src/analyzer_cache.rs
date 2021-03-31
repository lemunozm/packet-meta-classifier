use crate::base::analyzer::{Analyzer, AnalyzerResult};
use crate::base::flow::NoFlow;
use crate::base::id::ClassifierId;
use crate::handler::analyzer::GenericAnalyzerHandler;
use crate::packet::{Direction, Packet};

use std::io::Write;

pub struct AnalyzerCache<I: ClassifierId> {
    analyzers: Vec<Box<dyn GenericAnalyzerHandler<I>>>,
}

impl<I: ClassifierId> AnalyzerCache<I> {
    pub fn new(analyzer_list: Vec<Box<dyn GenericAnalyzerHandler<I>>>) -> Self {
        let mut analyzers = (0..I::TOTAL)
            .map(|_| <dyn GenericAnalyzerHandler<I>>::new(NoAnalyzer))
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
        &mut *self.analyzers[id.inner()]
    }
}

#[derive(Default)]
struct NoAnalyzer;
impl<I: ClassifierId> Analyzer<I> for NoAnalyzer {
    const ID: I = I::NONE;
    const PREV_ID: I = I::NONE;
    type Flow = NoFlow;

    fn build(_packet: &Packet) -> AnalyzerResult<Self, I> {
        unreachable!()
    }

    fn write_flow_signature(&self, _signature: impl Write, _direction: Direction) -> bool {
        unreachable!()
    }
}
