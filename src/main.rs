//mod rules;

use std::collections::HashMap;
use std::net::SocketAddr;

pub struct Config {}

trait Analyzer {
    fn analyze<'a>(&mut self, data: &'a [u8]) -> (Option<AnalyzerKind>, &'a [u8]) {
        todo!()
    }
}

#[derive(Default)]
pub struct IpPacket {}
impl Analyzer for IpPacket {}

#[derive(Default)]
pub struct TcpPacket {}
impl Analyzer for TcpPacket {}

#[derive(Default)]
pub struct UdpPacket {}
impl Analyzer for UdpPacket {}

#[derive(Default)]
pub struct HttpPacket {}
impl Analyzer for HttpPacket {}

#[derive(Debug, Clone, Copy)]
enum AnalyzerKind {
    Ip = 1,
    Tcp = 2,
    Udp = 4,
    Http = 8,
}

impl AnalyzerKind {
    fn has_flow(&self) -> bool {
        todo!()
    }
}

#[derive(Default)]
pub struct PacketInfo {
    pub ip: IpPacket,
    pub tcp: TcpPacket,
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
                self.tcp = TcpPacket::default();
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

enum State {
    Send,
    Recv,
    Established,
}

impl Default for State {
    fn default() -> Self {
        State::Send
    }
}

#[derive(Default)]
pub struct TcpFlow {
    state: State,
}
impl Flow for TcpFlow {}

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

pub struct Engine<T> {
    config: Config,
    rules: ClassificationRules<T>,
    packet: PacketInfo,
    flow_pool: HashMap<FlowDef, Box<dyn Flow>>,
}

impl<T> Engine<T> {
    pub fn new(config: Config, rules: ClassificationRules<T>) -> Engine<T> {
        Engine {
            config,
            rules,
            packet: PacketInfo::default(),
            flow_pool: HashMap::new(),
        }
    }

    fn process_packet(&mut self, mut data: &[u8]) -> ClassificationResult<T> {
        let mut analyzers: u64 = 0;
        let mut analyzer = AnalyzerKind::Ip;

        loop {
            let (next_analyzer, next_data) = self.packet.process_for(analyzer, data);
            let flow = match self.packet.flow_def(analyzer) {
                Some(flow_def) => {
                    let flow = self.flow_pool.entry(flow_def.clone()).or_insert_with(|| {
                        match flow_def.kind {
                            FlowKind::Udp => Box::new(UdpFlow::default()),
                            FlowKind::Tcp => Box::new(TcpFlow::default()),
                            FlowKind::Http => Box::new(HttpFlow::default()),
                        }
                    });

                    flow.update(&self.packet);
                    Some(&*flow)
                }
                None => None,
            };

            match self.rules.try_classify(analyzers, &self.packet, flow) {
                ClassificationState::None => return ClassificationResult { rule: None },
                ClassificationState::Incompleted => (),
                ClassificationState::Completed(rule) => {
                    return ClassificationResult { rule: Some(rule) }
                }
            };

            analyzers |= analyzer as u64;
            data = next_data;
            match next_analyzer {
                Some(next_analyzer) => analyzer = next_analyzer,
                None => break,
            }
        }

        ClassificationResult { rule: None }
    }
}

trait GenericValue {
    fn check(&self, packet: &PacketInfo, flow: Option<&Box<dyn Flow>>) -> bool {
        todo!()
    }
}

struct GenericValueImpl<F> {
    value: Box<dyn RuleValue<Flow = F>>,
}

impl<F> GenericValueImpl<F> {
    fn new(value: impl RuleValue<Flow = F> + 'static) -> Self {
        Self {
            value: Box::new(value),
        }
    }
}

impl<F: Flow + Default + 'static> GenericValue for GenericValueImpl<F> {
    fn check(&self, packet: &PacketInfo, flow: Option<&Box<dyn Flow>>) -> bool {
        match flow {
            Some(flow) => {
                let flow = (&*flow as &dyn std::any::Any).downcast_ref::<F>().unwrap();
                self.value.check(packet, flow)
            }
            None => self.value.check(packet, &F::default()),
        }
    }
}

pub trait RuleValue: std::fmt::Debug {
    type Flow: Flow;

    fn description(&self) -> String {
        todo!()
    }

    fn check(&self, packet: &PacketInfo, flow: &Self::Flow) -> bool {
        todo!()
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

#[derive(Debug, Clone, PartialEq, Eq)]
enum TcpState {
    Send,
    Recv,
    Established,
}

impl From<&State> for TcpState {
    fn from(state: &State) -> TcpState {
        match state {
            State::Send => Self::Send,
            State::Recv => Self::Recv,
            State::Established => Self::Established,
        }
    }
}

impl RuleValue for TcpState {
    type Flow = TcpFlow;

    fn check(&self, packet: &PacketInfo, tcp_flow: &Self::Flow) -> bool {
        TcpState::from(&tcp_flow.state) == *self
    }
}

fn main() {}
