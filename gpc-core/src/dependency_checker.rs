use crate::base::id::ClassifierId;

pub enum DependencyStatus {
    Predecessor,
    Descendant,
    NoPath,
}

pub struct DependencyChecker<I: ClassifierId> {
    dependency_matrix: Vec<bool>,
    _index_type: std::marker::PhantomData<I>,
}

impl<I: ClassifierId> DependencyChecker<I> {
    pub fn new(dependency_list: Vec<(I, I)>) -> Self {
        let mut checker = Self {
            dependency_matrix: vec![false; I::TOTAL * I::TOTAL],
            _index_type: std::marker::PhantomData::default(),
        };

        for (id, prev_id) in dependency_list {
            assert!(!checker.get(id, id), "Analyzer {:?} already registered", id);

            checker.set(id, id, true);
            checker.set(prev_id, id, true);
            for i in 0..prev_id.inner() {
                if checker.get(i.into(), prev_id) {
                    checker.set(i.into(), id, true);
                }
            }
        }

        checker
    }

    fn get(&self, x: I, y: I) -> bool {
        self.dependency_matrix[y.inner() * I::TOTAL + x.inner()]
    }

    fn set(&mut self, x: I, y: I, value: bool) {
        self.dependency_matrix[y.inner() * I::TOTAL + x.inner()] = value;
    }

    pub fn check(&self, next: I, to: I) -> DependencyStatus {
        if self.get(next, to) {
            DependencyStatus::Descendant
        } else if self.get(to, next) {
            DependencyStatus::Predecessor
        } else {
            DependencyStatus::NoPath
        }
    }
}
