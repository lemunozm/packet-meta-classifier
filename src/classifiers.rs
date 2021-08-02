pub mod http;
pub mod ip;
pub mod tcp;
pub mod udp;

use crate::flow::{FlowDef, GenericFlow};

#[derive(Debug, Clone, Copy)]
pub enum AnalyzerKind {
    Ip = 1,
    Tcp = 2,
    Udp = 4,
    Http = 8,
}

impl AnalyzerKind {
    pub const START: Self = Self::Ip;
}

pub trait Analyzer {
    fn analyze<'a>(&mut self, data: &'a [u8]) -> (Option<AnalyzerKind>, &'a [u8]) {
        todo!()
    }

    fn identify_flow(&self) -> Option<FlowDef> {
        todo!()
    }

    fn create_flow(&self) -> Box<dyn GenericFlow> {
        todo!()
    }
}
