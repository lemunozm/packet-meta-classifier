#[macro_use]
extern crate arrayref;

pub mod http;
pub mod ip;
pub mod tcp;
pub mod udp;

use pmc_core::base::config::{
    BaseConfig, ClassifierId as ClassifierIdTrait, Config as ConfigTrait,
};
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

impl ClassifierIdTrait for ClassifierId {
    const NONE: ClassifierId = ClassifierId::None;
    const INITIAL: ClassifierId = ClassifierId::Ip;
    const TOTAL: usize = ClassifierId::COUNT;
}

#[derive(Clone, Hash, PartialEq, Eq, Debug)]
pub enum FlowKind {
    None,
    Tcp,
    Udp,
    Http,
}

#[derive(Clone, Hash, PartialEq, Eq, Debug)]
pub struct FlowSignature {
    source_ip: Ipv6Addr,
    dest_ip: Ipv6Addr,
    client_port: u16,
    server_port: u16,
    kind: FlowKind,
}

impl Default for FlowSignature {
    fn default() -> Self {
        Self {
            source_ip: Ipv6Addr::UNSPECIFIED,
            dest_ip: Ipv6Addr::UNSPECIFIED,
            client_port: 0,
            server_port: 0,
            kind: FlowKind::None,
        }
    }
}

pub struct Config {
    pub base: BaseConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            base: BaseConfig {
                skip_analyzer_bytes: 1, // Skip bytes from IP analyzer
                flow_pool_initial_size: 100,
            },
        }
    }
}

impl ConfigTrait for Config {
    type FlowId = FlowSignature;
    type ClassifierId = ClassifierId;

    fn base(&self) -> &BaseConfig {
        &self.base
    }
}

pub fn loader() -> ClassifierLoader<Config> {
    ClassifierLoader::default()
        .with(ip::IpClassifier)
        .with(udp::UdpClassifier)
        .with(tcp::TcpClassifier)
        .with(http::HttpStartLineClassifier)
        .with(http::HttpHeaderClassifier)
}
