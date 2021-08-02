use crate::rules::expression::Exp;

pub struct Rule<T> {
    exp: Exp,
    tag: T,
    priority: usize,
}

impl<T> Rule<T> {
    fn new(exp: Exp, tag: T, priority: usize) -> Rule<T> {
        Rule { exp, tag, priority }
    }

    pub fn expression(&self) -> &Exp {
        &self.exp
    }

    pub fn tag(&self) -> &T {
        &self.tag
    }

    pub fn priority(&self) -> usize {
        self.priority
    }
}

pub struct ClassificationRules<T> {
    rules: Vec<Rule<T>>,
}

impl<T> ClassificationRules<T> {
    pub fn new(tagged_expr: Vec<(Exp, T)>) -> ClassificationRules<T> {
        let rules = tagged_expr
            .into_iter()
            .enumerate()
            .map(|(index, (exp, tag))| Rule::new(exp, tag, index + 1))
            .collect();

        ClassificationRules { rules }
    }

    pub fn rule(&self, priority: usize) -> Option<&Rule<T>> {
        self.rules.get(priority)
    }

    pub fn classify(
        &self,
        analyzer_kind: AnalyzerKind,
        packet: &Packet,
        flow: &Flow,
    ) -> Option<&Rule<T>> {
        for rule in &self.rules {
            if rule.expression().check(&context) {
                return Some(rule);
            }
        }
        None
    }
}
