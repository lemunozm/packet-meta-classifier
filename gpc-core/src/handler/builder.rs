use crate::base::analyzer::{Analyzer, AnalyzerInfo, AnalyzerResult};
use crate::base::builder::Builder;
use crate::base::flow::Flow;
use crate::base::id::ClassifierId;
use crate::handler::analyzer::GenericAnalyzerHandler;
use crate::packet::Packet;

pub trait GenericBuilderHandler<I: ClassifierId> {
    fn build_from_packet(
        &mut self,
        packet: &Packet,
    ) -> AnalyzerResult<&mut dyn GenericAnalyzerHandler<I>, I>;

    fn get(&self) -> &dyn GenericAnalyzerHandler<I>;
}

impl<I: ClassifierId> dyn GenericBuilderHandler<I> {
    pub fn new<B: Builder<I> + 'static>(builder: B) -> Box<dyn GenericBuilderHandler<I>> {
        Box::new(BuilderHandler {
            _builder: builder,
            cached_analyzer: None,
        })
    }
}

pub struct BuilderHandler<B, I: ClassifierId> {
    _builder: B,
    cached_analyzer: Option<Box<dyn GenericAnalyzerHandler<I>>>,
}

impl<I, B, F, A> GenericBuilderHandler<I> for BuilderHandler<B, I>
where
    B: Builder<I, Analyzer = A, Flow = F> + 'static,
    A: Analyzer<I> + 'static,
    F: Flow<A> + 'static,
    I: ClassifierId,
{
    fn build_from_packet(
        &mut self,
        packet: &Packet,
    ) -> AnalyzerResult<&mut dyn GenericAnalyzerHandler<I>, I> {
        match A::build(packet) {
            Ok(info) => {
                match &mut self.cached_analyzer {
                    Some(analyzer) => analyzer.update::<A, F>(info.analyzer),
                    None => {
                        self.cached_analyzer
                            .insert(<dyn GenericAnalyzerHandler<I>>::new::<A, F>(info.analyzer));
                    }
                }

                Ok(AnalyzerInfo {
                    analyzer: self.cached_analyzer.as_deref_mut().unwrap(),
                    next_classifier_id: info.next_classifier_id,
                    bytes_parsed: info.bytes_parsed,
                })
            }
            Err(reason) => Err(reason),
        }
    }

    fn get(&self) -> &dyn GenericAnalyzerHandler<I> {
        self.cached_analyzer.as_deref().unwrap()
    }
}
