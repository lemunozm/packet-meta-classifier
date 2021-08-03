use pcap_file::pcap::PcapReader;
use std::fs::File;

pub struct IpPacket {
    pub data: Vec<u8>,
}

pub struct IpCapture {
    ip_packets: Vec<IpPacket>,
}

impl IpCapture {
    pub fn open(file_name: &str) -> IpCapture {
        let pcap_file = File::open(file_name).expect("Error opening file");
        let pcap_reader = PcapReader::new(pcap_file).unwrap();

        let ip_packets = pcap_reader
            .map(|pcap| {
                let pcap = pcap.unwrap();
                match pcap.data[12..14] {
                    [0x08, 0x00] => IpPacket {
                        data: Vec::from(&pcap.data[14..pcap.data.len() - 4]),
                    },
                    _ => panic!("The packet must be an IP packet"),
                }
            })
            .collect();

        IpCapture { ip_packets }
    }
}

use std::ops::Index;
use std::slice::SliceIndex;

impl<I: SliceIndex<[IpPacket]>> Index<I> for IpCapture {
    type Output = I::Output;

    #[inline]
    fn index(&self, index: I) -> &Self::Output {
        Index::index(&*self.ip_packets, index)
    }
}
