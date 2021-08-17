use crate::base::id::ClassifierId;

use std::collections::BTreeSet;

pub enum DependencyStatus {
    Ok,
    NeedAnalysis,
    None,
}

pub struct DependencyChecker<I: ClassifierId> {
    dependencies: Vec<BTreeSet<I>>,
    //TODO: PERF: make it as a table.
}

impl<I: ClassifierId> DependencyChecker<I> {
    pub fn new(dependency_list: Vec<(I, I)>) -> Self {
        let mut dependencies: Vec<BTreeSet<I>> =
            (0..I::TOTAL).map(|_| BTreeSet::default()).collect();

        for (id, prev_id) in dependency_list {
            assert!(
                dependencies[id.inner()].is_empty(),
                "Analyzer {:?} already registered",
                id
            );

            dependencies[id.inner()].insert(id);
            dependencies[prev_id.inner()].insert(id);
            Self::dependency_tree_creation(&mut dependencies, id, prev_id);
        }

        Self { dependencies }
    }

    fn dependency_tree_creation(dependencies: &mut Vec<BTreeSet<I>>, id: I, looking_id: I) {
        for selected_id in 0..dependencies.len() {
            let classifier_ids = &mut dependencies[selected_id];
            if selected_id != looking_id.into() && classifier_ids.contains(&looking_id) {
                classifier_ids.insert(id);
                Self::dependency_tree_creation(dependencies, id, selected_id.into());
            }
        }
    }

    pub fn check(&self, next: I, to: I) -> DependencyStatus {
        if self.dependencies[next.inner()].contains(&to) {
            DependencyStatus::NeedAnalysis
        } else if self.dependencies[to.inner()].contains(&next) {
            DependencyStatus::Ok
        } else {
            DependencyStatus::None
        }
    }
}
