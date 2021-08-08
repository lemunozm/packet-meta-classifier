use crate::flow::{FlowDef, GenericFlow};

use crate::classifiers::ip;
use crate::classifiers::tcp;

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub enum AnalyzerId {
    None = 0,
    Ip = 1 << 0,
    Tcp = 1 << 1,
    Udp = 1 << 2,
    Http = 1 << 3,
    TcpHeur = 1 << 4, //really needed?
}

#[derive(Default)]
pub struct PacketInfo {
    pub ip: ip::analyzer::IpAnalyzer,
    pub tcp: tcp::analyzer::TcpAnalyzer,
}

impl PacketInfo {
    pub fn choose_analyzer<'a>(&mut self, id: AnalyzerId) -> &mut dyn Analyzer {
        match id {
            AnalyzerId::None => unreachable!(),
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
            AnalyzerId::TcpHeur => todo!(),
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
    fn id(&self) -> AnalyzerId;
}
