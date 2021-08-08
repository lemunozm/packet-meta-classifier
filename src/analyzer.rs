use crate::classifiers::ClassifierId;
use crate::flow::{FlowDef, GenericFlow};

use strum::EnumCount;

use std::collections::HashSet;

pub enum AnalyzerStatus<'a> {
    Next(ClassifierId, &'a [u8]),
    Finished(&'a [u8]),
    Abort,
}

pub trait Analyzer {
    fn analyze<'a>(&mut self, data: &'a [u8]) -> AnalyzerStatus<'a>;
    fn next_classifiers() -> Vec<ClassifierId>
    where
        Self: Sized;
    fn identify_flow(&self) -> Option<FlowDef>;
    fn create_flow(&self) -> Box<dyn GenericFlow>;
    fn as_any(&self) -> &dyn std::any::Any;
}

pub struct AnalyzerRegistry {
    analyzers: Vec<Box<dyn Analyzer>>,
    dependencies: Vec<HashSet<ClassifierId>>,
}

impl Default for AnalyzerRegistry {
    fn default() -> Self {
        Self {
            analyzers: (0..ClassifierId::COUNT)
                .map(|_| Box::new(NoAnalyzer) as Box<dyn Analyzer>)
                .collect::<Vec<_>>(),
            dependencies: (0..ClassifierId::COUNT)
                .map(|_| HashSet::default())
                .collect::<Vec<_>>(),
        }
    }
}

impl AnalyzerRegistry {
    pub fn add<A: Analyzer + 'static>(&mut self, id: ClassifierId, analyzer: A) {
        for classifier_id in A::next_classifiers() {
            self.dependencies[classifier_id as usize].insert(id.into());
        }
        self.analyzers.insert(id.into(), Box::new(analyzer));
    }

    pub fn get(&self, id: ClassifierId) -> &dyn Analyzer {
        &*self.analyzers[id as usize]
    }

    pub fn get_mut(&mut self, id: ClassifierId) -> &mut dyn Analyzer {
        &mut *self.analyzers[id as usize]
    }

    pub fn contains(&self, id: ClassifierId) -> bool {
        self.analyzers.get(id as usize).is_some()
    }

    pub fn exists_path(&self, from: ClassifierId, to: ClassifierId) -> bool {
        self.dependencies[from as usize].contains(&to)
    }
}

pub struct NoAnalyzer;
impl Analyzer for NoAnalyzer {
    fn analyze<'a>(&mut self, _data: &'a [u8]) -> AnalyzerStatus<'a> {
        unreachable!()
    }

    fn next_classifiers() -> Vec<ClassifierId>
    where
        Self: Sized,
    {
        unreachable!()
    }

    fn identify_flow(&self) -> Option<FlowDef> {
        unreachable!()
    }

    fn create_flow(&self) -> Box<dyn GenericFlow> {
        unreachable!()
    }

    fn as_any(&self) -> &dyn std::any::Any {
        unreachable!()
    }
}
