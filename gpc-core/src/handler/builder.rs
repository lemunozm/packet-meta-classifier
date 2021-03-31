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
        life_stamp: usize,
    ) -> AnalyzerResult<&mut dyn GenericAnalyzerHandler<I>, I>;

    /// This function is unsafe because the caller can choose an incorrect live_stamp that breaks
    /// the life_stamp precondition: the life_stamp parameter should be the same as the used in
    /// the last call to [`build_from_packet()`]
    unsafe fn get(&self, life_stamp: usize) -> &dyn GenericAnalyzerHandler<I>;
}

impl<I: ClassifierId> dyn GenericBuilderHandler<I> {
    pub fn new<B: Builder<I> + 'static>(builder: B) -> Box<dyn GenericBuilderHandler<I>> {
        Box::new(BuilderHandler {
            _builder: builder,
            cached_analyzer: None,
            life_stamp: 0,
        })
    }
}

pub struct BuilderHandler<B, I: ClassifierId> {
    _builder: B,
    cached_analyzer: Option<Box<dyn GenericAnalyzerHandler<I>>>,
    life_stamp: usize,
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
        life_stamp: usize,
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

                self.life_stamp = life_stamp;

                Ok(AnalyzerInfo {
                    analyzer: self.cached_analyzer.as_deref_mut().unwrap(),
                    next_classifier_id: info.next_classifier_id,
                    bytes_parsed: info.bytes_parsed,
                })
            }
            Err(reason) => Err(reason),
        }
    }

    unsafe fn get(&self, life_stamp: usize) -> &dyn GenericAnalyzerHandler<I> {
        if life_stamp != self.life_stamp {
            panic!(
                "Expected life stamp: {}, found: {}",
                self.life_stamp, life_stamp
            );
        }
        self.cached_analyzer.as_deref().unwrap()
    }
}
