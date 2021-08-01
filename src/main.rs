use std::collections::HashMap;
use std::net::SocketAddr;

struct Config {}

trait Analyzer {
    fn analyze<'a>(&mut self, data: &'a [u8]) -> (Option<AnalyzerKind>, &'a [u8]) {
        todo!()
    }
}

#[derive(Default)]
struct IpPacket {}
impl Analyzer for IpPacket {}

#[derive(Default)]
struct TcpPacket {}
impl Analyzer for TcpPacket {}

#[derive(Default)]
struct UdpPacket {}
impl Analyzer for UdpPacket {}

#[derive(Default)]
struct HttpPacket {}
impl Analyzer for HttpPacket {}

#[derive(Debug, Clone, Copy)]
enum AnalyzerKind {
    Ip = 0,
    Tcp,
    Udp,
    Http,
}

#[derive(Default)]
struct PacketInfo {
    ip: IpPacket,
    tcp: TcpPacket,
    udp: UdpPacket,
    http: HttpPacket,
}

impl PacketInfo {
    fn process_for<'a>(
        &mut self,
        kind: AnalyzerKind,
        data: &'a [u8],
    ) -> (Option<AnalyzerKind>, &'a [u8]) {
        log::trace!("Analyze for: {:?}", kind);
        match kind {
            AnalyzerKind::Ip => self.ip.analyze(data),
            AnalyzerKind::Tcp => self.tcp.analyze(data),
            AnalyzerKind::Udp => self.udp.analyze(data),
            AnalyzerKind::Http => self.http.analyze(data),
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

trait Flow {
    fn update(&mut self, last_packet: &PacketInfo) {}
}

#[derive(Default)]
struct UdpFlow {}
impl Flow for UdpFlow {}

#[derive(Default)]
struct TcpFlow {}
impl Flow for TcpFlow {}

#[derive(Default)]
struct HttpFlow {}
impl Flow for HttpFlow {}

#[derive(Hash, Clone, PartialEq, Eq)]
enum FlowKind {
    Tcp,
    Udp,
    Http,
}

#[derive(Hash, Clone, PartialEq, Eq)]
struct FlowDef {
    origin: SocketAddr,
    dest: SocketAddr,
    kind: FlowKind,
}

struct Engine {
    config: Config,
    analyzers: Vec<Box<dyn Analyzer>>,
    flow_pool: HashMap<FlowDef, Box<dyn Flow>>,
}

impl Engine {
    fn process_packet(&mut self, data: &[u8]) {
        let mut packet = PacketInfo::default();

        let mut analyzer = AnalyzerKind::Ip;
        let mut data = data;

        while let (Some(next_analyzer), next_data) = packet.process_for(analyzer, data) {
            if let Some(flow_def) = packet.flow_def(next_analyzer) {
                let flow = self
                    .flow_pool
                    .entry(flow_def.clone())
                    .or_insert_with(|| match flow_def.kind {
                        FlowKind::Udp => Box::new(UdpFlow::default()),
                        FlowKind::Tcp => Box::new(TcpFlow::default()),
                        FlowKind::Http => Box::new(HttpFlow::default()),
                    });

                flow.update(&packet);
            }

            analyzer = next_analyzer;
            data = next_data;
        }
    }
}

fn main() {}
