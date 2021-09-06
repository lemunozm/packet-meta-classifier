#[macro_use]
extern crate arrayref;

pub mod http;
pub mod ip;
pub mod tcp;
pub mod udp;

use pmc_core::base::id::ClassifierId as ClassifierIdTrait;
use pmc_core::loader::ClassifierLoader;

use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use strum::EnumCount;

use std::net::Ipv6Addr;

#[derive(EnumCount, FromPrimitive, Debug, Clone, Copy, Hash, PartialEq, PartialOrd, Eq, Ord)]
pub enum ClassifierId {
    None,
    Ip,
    Tcp,
    Udp,
    HttpStartLine,
    HttpHeader,
}

impl From<usize> for ClassifierId {
    fn from(value: usize) -> Self {
        Self::from_usize(value).expect("The value must be a valid ClassifierId")
    }
}

impl From<ClassifierId> for usize {
    fn from(id: ClassifierId) -> usize {
        id as usize
    }
}

#[derive(Clone, Hash, PartialEq, Eq, Debug)]
pub struct FlowSignature {
    source_ip: Ipv6Addr,
    dest_ip: Ipv6Addr,
    source_port: u16,
    dest_port: u16,
}

impl Default for FlowSignature {
    fn default() -> Self {
        Self {
            source_ip: Ipv6Addr::UNSPECIFIED,
            dest_ip: Ipv6Addr::UNSPECIFIED,
            source_port: 0,
            dest_port: 0,
        }
    }
}

impl ClassifierIdTrait for ClassifierId {
    const NONE: ClassifierId = ClassifierId::None;
    const INITIAL: ClassifierId = ClassifierId::Ip;
    const TOTAL: usize = ClassifierId::COUNT;

    type FlowId = FlowSignature;
}

pub fn loader() -> ClassifierLoader<ClassifierId> {
    ClassifierLoader::default()
        .with(ip::IpClassifier)
        .with(udp::UdpClassifier)
        .with(tcp::TcpClassifier)
        .with(http::HttpStartLineClassifier)
        .with(http::HttpHeaderClassifier)
}
