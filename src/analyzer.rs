use crate::classifiers::ClassifierId;
use crate::flow::{FlowDef, GenericFlow};

pub enum AnalyzerStatus<'a> {
    Next(ClassifierId, &'a [u8]),
    Finished(&'a [u8]),
    Abort,
}

pub trait Analyzer {
    fn analyze<'a>(&mut self, data: &'a [u8]) -> AnalyzerStatus<'a>;
    fn identify_flow(&self) -> Option<FlowDef>;
    fn create_flow(&self) -> Box<dyn GenericFlow>;
    fn as_any(&self) -> &dyn std::any::Any;
}

#[derive(Default)]
pub struct AnalyzerRegistry {
    analyzers: Vec<Box<dyn Analyzer>>,
}

impl AnalyzerRegistry {
    pub fn add(&mut self, id: ClassifierId, analyzer: impl Analyzer + 'static) {
        self.analyzers.insert(id.into(), Box::new(analyzer));
    }

    pub fn get(&self, id: ClassifierId) -> &dyn Analyzer {
        &**self.analyzers.get(id as usize).unwrap()
    }

    pub fn get_mut(&mut self, id: ClassifierId) -> &mut dyn Analyzer {
        &mut **self.analyzers.get_mut(id as usize).unwrap()
    }

    pub fn contains(&self, id: ClassifierId) -> bool {
        self.analyzers.get(id as usize).is_some()
    }
}
