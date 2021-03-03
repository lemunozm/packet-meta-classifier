pub mod http;
pub mod ip;
pub mod tcp;
pub mod udp;

use crate::flow::{FlowDef, GenericFlow};

#[derive(Debug, Clone, Copy)]
pub enum AnalyzerId {
    Ip = 1,
    Tcp = 2,
    Udp = 4,
    Http = 8,
}

#[derive(Default)]
pub struct PacketInfo {
    pub ip: ip::analyzer::IpAnalyzer,
    pub tcp: tcp::analyzer::TcpAnalyzer,
}

impl PacketInfo {
    pub fn choose_analyzer<'a>(&mut self, id: AnalyzerId) -> &mut dyn Analyzer {
        log::trace!("Analyze for: {:?}", id);
        match id {
            AnalyzerId::Ip => {
                self.ip = ip::analyzer::IpAnalyzer::default();
                &mut self.ip
            }
            AnalyzerId::Tcp => {
                self.tcp = tcp::analyzer::TcpAnalyzer::default();
                &mut self.tcp
            }
            AnalyzerId::Udp => todo!(),
            AnalyzerId::Http => todo!(),
        }
    }
}

pub enum AnalyzerStatus<'a> {
    Next(AnalyzerId, &'a [u8]),
    Finished(&'a [u8]),
    Abort,
}

impl AnalyzerId {
    pub const START: Self = Self::Ip;
}

pub trait Analyzer {
    fn analyze<'a>(&mut self, data: &'a [u8]) -> AnalyzerStatus<'a>;
    fn identify_flow(&self) -> Option<FlowDef>;
    fn create_flow(&self) -> Box<dyn GenericFlow>;
    fn as_any(&self) -> &dyn std::any::Any;
}
