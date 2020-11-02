use crate::rules::rule::{RuleValue};
use crate::packet_info::{PacketInfo, L4};

#[derive(Debug)]
pub enum Ip {
    Origin(String),
    Destination(String),
    L4(L4),
}

impl RuleValue for Ip {
    fn check_value(&self, packet_info: &PacketInfo) -> bool {
        if let Some(ip) = &packet_info.ip {
            return match self {
                Ip::Origin(regex) => match ip.ip_origin {
                    Some(ip) => true,
                    None => false,
                }
                Ip::Destination(regex) => match ip.ip_destination {
                    Some(ip) => true,
                    None => false,
                }
                Ip::L4(l4) => match l4 {
                    L4::Tcp => ip.l4 == L4::Tcp,
                    L4::Udp => ip.l4 == L4::Udp,
                }
            }
        }
        false
    }
}

#[derive(Debug)]
pub enum Tcp {
    SynFlood,
    Teardown,
}

impl RuleValue for Tcp {
    fn check_value(&self, packet_info: &PacketInfo) -> bool {
        if let Some(tcp) = &packet_info.tcp {
            return match self {
                Tcp::SynFlood => tcp.is_syn_flood,
                Tcp::Teardown => tcp.is_teardown,
            }
        }
        false
    }
}
