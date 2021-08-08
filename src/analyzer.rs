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
    fn classifier_id() -> ClassifierId
    where
        Self: Sized;
    fn next_classifiers() -> Vec<ClassifierId>
    where
        Self: Sized;
    fn identify_flow(&self) -> Option<FlowDef>;
    fn create_flow(&self) -> Box<dyn GenericFlow>;
    fn as_any(&self) -> &dyn std::any::Any;
    fn reset(&mut self);
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
    pub fn register<A: Analyzer + 'static>(&mut self, analyzer: A) {
        assert!(
            self.dependencies[A::classifier_id() as usize].is_empty(),
            "Analyzer already registered"
        );
        self.dependencies[A::classifier_id() as usize].insert(A::classifier_id());
        for classifier_id in A::next_classifiers() {
            self.dependencies[A::classifier_id() as usize].insert(classifier_id);
        }
        self.analyzers
            .insert(A::classifier_id().into(), Box::new(analyzer));
    }

    pub fn get(&self, id: ClassifierId) -> &dyn Analyzer {
        &*self.analyzers[id as usize]
    }

    pub fn get_clean_mut(&mut self, id: ClassifierId) -> &mut dyn Analyzer {
        self.analyzers[id as usize].reset();
        &mut *self.analyzers[id as usize]
    }

    pub fn contains(&self, id: ClassifierId) -> bool {
        self.analyzers.get(id as usize).is_some()
    }

    pub fn exists_path(&self, from: ClassifierId, to: ClassifierId) -> bool {
        dbg!(&self.dependencies);
        self.dependencies[from as usize].contains(&to)
    }
}

pub struct NoAnalyzer;
impl Analyzer for NoAnalyzer {
    fn analyze<'a>(&mut self, _data: &'a [u8]) -> AnalyzerStatus<'a> {
        unreachable!()
    }

    fn classifier_id() -> ClassifierId {
        unreachable!()
    }

    fn next_classifiers() -> Vec<ClassifierId> {
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

    fn reset(&mut self) {
        unreachable!()
    }
}
