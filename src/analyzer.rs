use crate::classifiers::ClassifierId;
use crate::flow::{Flow, GenericFlow, GenericFlowImpl, NoFlow};

use strum::EnumCount;

use std::collections::HashSet;

pub enum AnalyzerStatus<'a> {
    Next(ClassifierId, &'a [u8]),
    Finished(&'a [u8]),
    Abort,
}

pub trait Analyzer: Sized + Default {
    type PrevAnalyzer: Analyzer;
    type Flow: Flow;
    const ID: ClassifierId;
    fn analyze<'a>(&mut self, data: &'a [u8]) -> AnalyzerStatus<'a>;
}

#[derive(Default)]
pub struct NoAnalyzer;
impl Analyzer for NoAnalyzer {
    type PrevAnalyzer = NoAnalyzer;
    type Flow = NoFlow<NoAnalyzer>;
    const ID: ClassifierId = ClassifierId::None;

    fn analyze<'a>(&mut self, _data: &'a [u8]) -> AnalyzerStatus<'a> {
        unreachable!()
    }
}

pub trait GenericAnalyzer {
    fn id(&self) -> ClassifierId;
    fn prev_id(&self) -> ClassifierId;
    fn analyze<'a>(&mut self, data: &'a [u8]) -> AnalyzerStatus<'a>;
    fn as_any(&self) -> &dyn std::any::Any;
    fn reset(&mut self);
    fn update_flow_signature(&mut self, current_signature: &mut Vec<u8>) -> bool;
    fn create_flow(&self) -> Box<dyn GenericFlow>;
}

struct GenericAnalyzerImpl<A> {
    analyzer: A,
}

impl<A> GenericAnalyzerImpl<A> {
    fn new(analyzer: A) -> Self {
        Self { analyzer }
    }
}

impl<A, F> GenericAnalyzer for GenericAnalyzerImpl<A>
where
    A: Analyzer<Flow = F> + 'static,
    F: Flow<Analyzer = A> + 'static,
{
    fn id(&self) -> ClassifierId {
        A::ID
    }

    fn prev_id(&self) -> ClassifierId {
        A::PrevAnalyzer::ID
    }

    fn analyze<'a>(&mut self, data: &'a [u8]) -> AnalyzerStatus<'a> {
        self.analyzer.analyze(data)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn reset(&mut self) {
        self.analyzer = A::default();
    }

    fn update_flow_signature(&mut self, mut current_signature: &mut Vec<u8>) -> bool {
        let previous_len = current_signature.len();
        F::write_signature(&self.analyzer, &mut current_signature);
        previous_len != current_signature.len()
    }

    fn create_flow(&self) -> Box<dyn GenericFlow> {
        Box::new(GenericFlowImpl::new(F::create(&self.analyzer)))
    }
}

pub enum DependencyStatus {
    Ok,
    NeedAnalysis,
    None,
}

pub struct AnalyzerRegistry {
    analyzers: Vec<Box<dyn GenericAnalyzer>>,
    dependencies: Vec<HashSet<ClassifierId>>,
}

impl Default for AnalyzerRegistry {
    fn default() -> Self {
        Self {
            analyzers: (0..ClassifierId::COUNT)
                .map(|_| Box::new(GenericAnalyzerImpl::new(NoAnalyzer)) as Box<dyn GenericAnalyzer>)
                .collect::<Vec<_>>(),

            dependencies: (0..ClassifierId::COUNT)
                .map(|_| HashSet::default())
                .collect::<Vec<_>>(),
        }
    }
}

impl AnalyzerRegistry {
    pub fn register<A, F>(&mut self, analyzer: A)
    where
        A: Analyzer<Flow = F> + 'static,
        F: Flow<Analyzer = A> + 'static,
    {
        assert!(
            self.dependencies[A::ID as usize].is_empty(),
            "Analyzer already registered"
        );

        self.dependencies[A::ID as usize].insert(A::ID);
        self.dependencies[A::PrevAnalyzer::ID as usize].insert(A::ID);
        Self::dependency_tree_creation(&mut self.dependencies, A::ID, A::PrevAnalyzer::ID);

        self.analyzers
            .insert(A::ID as usize, Box::new(GenericAnalyzerImpl::new(analyzer)));
    }

    fn dependency_tree_creation<'a>(
        dependencies: &mut Vec<HashSet<ClassifierId>>,
        id: ClassifierId,
        looking: ClassifierId,
    ) {
        for selected_id in 0..dependencies.len() {
            let classifier_ids = &mut dependencies[selected_id];
            if selected_id != looking.into() && classifier_ids.contains(&looking) {
                classifier_ids.insert(id);
                Self::dependency_tree_creation(dependencies, id, selected_id.into());
                break;
            }
        }
    }

    pub fn get(&self, id: ClassifierId) -> &dyn GenericAnalyzer {
        &*self.analyzers[id as usize]
    }

    pub fn get_clean_mut(&mut self, id: ClassifierId) -> &mut dyn GenericAnalyzer {
        self.analyzers[id as usize].reset();
        &mut *self.analyzers[id as usize]
    }

    pub fn contains(&self, id: ClassifierId) -> bool {
        self.analyzers.get(id as usize).is_some()
    }

    pub fn check_dependencies(&self, next: ClassifierId, to: ClassifierId) -> DependencyStatus {
        if self.dependencies[next as usize].contains(&to) {
            DependencyStatus::NeedAnalysis
        } else if self.dependencies[to as usize].contains(&next) {
            DependencyStatus::Ok
        } else {
            DependencyStatus::None
        }
    }
}
