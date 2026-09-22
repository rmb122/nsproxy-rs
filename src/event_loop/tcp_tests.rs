//! Packet-level regression for large-MSS forwarding with delayed peer ACKs.

use super::{TCP_BUF_SIZE, new_tcp_socket};
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{ChecksumCapabilities, Device, Loopback, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{
    HardwareAddress, IpCidr, IpProtocol, Ipv4Address, Ipv4Packet, Ipv4Repr, TcpControl, TcpPacket,
    TcpRepr, TcpSeqNumber,
};

const LOCAL: Ipv4Address = Ipv4Address::new(192, 0, 2, 1);
const PEER: Ipv4Address = Ipv4Address::new(192, 0, 2, 2);
const NOW: Instant = Instant::ZERO;

fn inject(device: &mut Loopback, tcp: &TcpRepr<'_>) {
    let ip = Ipv4Repr {
        src_addr: PEER,
        dst_addr: LOCAL,
        next_header: IpProtocol::Tcp,
        payload_len: tcp.buffer_len(),
        hop_limit: 64,
    };
    let checksum = ChecksumCapabilities::ignored();
    device
        .transmit(NOW)
        .unwrap()
        .consume(ip.buffer_len() + ip.payload_len, |bytes| {
            let mut packet = Ipv4Packet::new_unchecked(bytes);
            ip.emit(&mut packet, &checksum);
            tcp.emit(
                &mut TcpPacket::new_unchecked(packet.payload_mut()),
                &PEER.into(),
                &LOCAL.into(),
                &checksum,
            );
        });
}

fn take_packet(device: &mut Loopback) -> Vec<u8> {
    device
        .receive(NOW)
        .expect("expected an emitted TCP segment")
        .0
        .consume(|bytes| bytes.to_vec())
}

#[test]
fn large_mss_tail_is_sent_without_waiting_for_an_ack() {
    let mut device = Loopback::new(Medium::Ip);
    let mut interface = Interface::new(Config::new(HardwareAddress::Ip), &mut device, NOW);
    interface.update_ip_addrs(|addresses| addresses.push(IpCidr::new(LOCAL.into(), 24)).unwrap());
    let mut sockets = SocketSet::new(vec![]);
    let mut socket = new_tcp_socket();
    socket.listen(5201).unwrap();
    let handle = sockets.add(socket);
    let mut peer = TcpRepr {
        src_port: 40000,
        dst_port: 5201,
        control: TcpControl::Syn,
        seq_number: TcpSeqNumber(100),
        ack_number: None,
        window_len: u16::MAX,
        window_scale: Some(1),
        max_seg_size: Some(64960),
        sack_permitted: false,
        sack_ranges: [None; 3],
        timestamp: None,
        payload: &[],
    };
    inject(&mut device, &peer);
    interface.poll_ingress_single(NOW, &mut device, &mut sockets);
    interface.poll_egress(NOW, &mut device, &mut sockets);
    let syn_ack = take_packet(&mut device);
    let ip = Ipv4Packet::new_checked(&syn_ack[..]).unwrap();
    let syn_ack = TcpPacket::new_checked(ip.payload()).unwrap();
    assert!(syn_ack.syn() && syn_ack.ack());
    peer.control = TcpControl::None;
    peer.seq_number += 1;
    peer.ack_number = Some(syn_ack.seq_number() + 1);
    peer.max_seg_size = None;
    peer.window_scale = None;
    inject(&mut device, &peer);
    interface.poll_ingress_single(NOW, &mut device, &mut sockets);
    let socket = sockets.get_mut::<tcp::Socket>(handle);
    assert_eq!(socket.state(), tcp::State::Established);
    assert_eq!(
        socket.send_slice(&vec![0x5a; TCP_BUF_SIZE]).unwrap(),
        TCP_BUF_SIZE
    );

    // Never acknowledge the first segment or advance to a delayed-ACK timer.
    // Both the full MSS and the short tail must nevertheless be emitted.
    let mut lengths = Vec::new();
    for _ in 0..2 {
        interface.poll_egress(NOW, &mut device, &mut sockets);
        while let Some((rx, _)) = device.receive(NOW) {
            rx.consume(|bytes| {
                let ip = Ipv4Packet::new_checked(bytes).unwrap();
                let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
                assert!(tcp.payload().iter().all(|&byte| byte == 0x5a));
                lengths.push(tcp.payload().len());
            });
        }
    }
    assert_eq!(lengths, [64960, 576]);
}
