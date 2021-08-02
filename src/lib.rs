pub mod classifiers;
pub mod config;
pub mod engine;

/*
#[macro_use]
extern crate arrayref;

pub mod rules;
pub mod classifiers;
pub mod engine;
pub mod context;
pub mod analyzer;
pub mod flow;
pub mod util;
*/

use classifiers::{Analyzer, AnalyzerKind};
use std::net::SocketAddr;

#[derive(Default)]
pub struct IpPacket {}
impl Analyzer for IpPacket {}

#[derive(Default)]
pub struct UdpPacket {}
impl Analyzer for UdpPacket {}

#[derive(Default)]
pub struct HttpPacket {}
impl Analyzer for HttpPacket {}

use classifiers::tcp::analyzer::TcpAnalyzer;

#[derive(Default)]
pub struct PacketInfo {
    pub ip: IpPacket,
    pub tcp: TcpAnalyzer,
    pub udp: UdpPacket,
    pub http: HttpPacket,
}

impl PacketInfo {
    fn process_for<'a>(
        &mut self,
        kind: AnalyzerKind,
        data: &'a [u8],
    ) -> (Option<AnalyzerKind>, &'a [u8]) {
        log::trace!("Analyze for: {:?}", kind);
        match kind {
            AnalyzerKind::Ip => {
                self.ip = IpPacket::default();
                self.ip.analyze(data)
            }
            AnalyzerKind::Tcp => {
                self.tcp = TcpAnalyzer::default();
                self.tcp.analyze(data)
            }
            AnalyzerKind::Udp => {
                self.udp = UdpPacket::default();
                self.udp.analyze(data)
            }
            AnalyzerKind::Http => {
                self.http = HttpPacket::default();
                self.http.analyze(data)
            }
        }
    }

    fn flow_def(&self, kind: AnalyzerKind) -> Option<FlowDef> {
        match kind {
            AnalyzerKind::Udp => None,  //TODO
            AnalyzerKind::Tcp => None,  //TODO
            AnalyzerKind::Http => None, //TODO
            _ => None,
        }
    }
}

pub trait Flow {
    fn update(&mut self, last_packet: &PacketInfo) {}
}

#[derive(Default)]
pub struct UdpFlow {}
impl Flow for UdpFlow {}

#[derive(Default)]
pub struct HttpFlow {}
impl Flow for HttpFlow {}

#[derive(Hash, Clone, PartialEq, Eq)]
enum FlowKind {
    Udp,
    Tcp,
    Http,
}

#[derive(Hash, Clone, PartialEq, Eq)]
struct FlowDef {
    origin: SocketAddr,
    dest: SocketAddr,
    kind: FlowKind,
}

enum ClassificationState<'a, T> {
    None,
    Incompleted,
    Completed(&'a Rule<T>),
}

pub struct ClassificationRules<T> {
    t: T,
}

impl<T> ClassificationRules<T> {
    fn try_classify(
        &self,
        analyzers: u64,
        packet: &PacketInfo,
        flow: Option<&Box<dyn Flow>>,
    ) -> ClassificationState<T> {
        todo!()
    }
}

#[derive(Default)]
pub struct ClassificationResult<'a, T> {
    pub rule: Option<&'a Rule<T>>,
}

pub struct Rule<T> {
    t: T,
}

pub trait RuleValue: std::fmt::Debug {
    type Flow: Flow;
    type Analyzer: Analyzer;

    fn description(&self) -> String {
        todo!()
    }

    fn check(&self, analyzer: &Self::Analyzer, flow: &Self::Flow) -> bool {
        todo!()
    }
}

trait GenericValue {
    fn check(&self, analyzer: &Box<dyn Analyzer>, flow: Option<&Box<dyn Flow>>) -> bool {
        todo!()
    }
}

struct GenericValueImpl<A, F> {
    value: Box<dyn RuleValue<Analyzer = A, Flow = F>>,
}

impl<A, F> GenericValueImpl<A, F> {
    fn new(value: impl RuleValue<Analyzer = A, Flow = F> + 'static) -> Self {
        Self {
            value: Box::new(value),
        }
    }
}

impl<A: Analyzer + 'static, F: Flow + Default + 'static> GenericValue for GenericValueImpl<A, F> {
    fn check(&self, analyzer: &Box<dyn Analyzer>, flow: Option<&Box<dyn Flow>>) -> bool {
        let analyzer = (&*analyzer as &dyn std::any::Any)
            .downcast_ref::<A>()
            .unwrap();
        match flow {
            Some(flow) => {
                let flow = (&*flow as &dyn std::any::Any).downcast_ref::<F>().unwrap();
                self.value.check(analyzer, flow)
            }
            None => self.value.check(analyzer, &F::default()),
        }
    }
}

pub struct Exp;
impl Exp {
    fn value<F: Flow + Default + 'static>(
        value: impl RuleValue<Flow = F> + 'static,
    ) -> Box<dyn GenericValue> {
        Box::new(GenericValueImpl::new(value))
    }
}
