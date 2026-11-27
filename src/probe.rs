// SPDX-License-Identifier: LGPL-2.1
//
//! ICMP echo probing for the self-test.
//!
//! The client has no TUN in `--self-test` mode, so the only way to prove the
//! tunnel actually carries traffic is to send a hand-built ICMP echo request
//! to the WireGuard server's own address and wait for the reply. This is the
//! same trick the reference client's users apply with `ping`, but without
//! requiring root or a real interface.

use std::net::Ipv4Addr;

/// Internet checksum (RFC 1071) over a byte slice.
pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let [last] = chunks.remainder() {
        sum += u16::from_be_bytes([*last, 0]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Builds a complete IPv4 + ICMP echo request packet.
pub fn echo_request(src: Ipv4Addr, dst: Ipv4Addr, id: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    let icmp_len = 8 + payload.len();
    let total_len = 20 + icmp_len;
    let mut packet = vec![0u8; total_len];

    // IPv4 header.
    packet[0] = 0x45; // version 4, IHL 5
    packet[1] = 0; // DSCP/ECN
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[4..6].copy_from_slice(&(id).to_be_bytes()); // identification
    packet[6..8].copy_from_slice(&0u16.to_be_bytes()); // flags + fragment
    packet[8] = 64; // TTL
    packet[9] = 1; // protocol ICMP
    packet[12..16].copy_from_slice(&src.octets());
    packet[16..20].copy_from_slice(&dst.octets());
    let header_checksum = checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());

    // ICMP echo request.
    packet[20] = 8; // type: echo request
    packet[21] = 0; // code
    packet[24..26].copy_from_slice(&id.to_be_bytes());
    packet[26..28].copy_from_slice(&seq.to_be_bytes());
    packet[28..].copy_from_slice(payload);
    let icmp_checksum = checksum(&packet[20..]);
    packet[22..24].copy_from_slice(&icmp_checksum.to_be_bytes());

    packet
}

/// Parses an ICMP echo reply out of a plaintext IP packet.
///
/// Returns the sequence number of the reply, if the packet is one.
pub fn echo_reply_seq(packet: &[u8]) -> Option<u16> {
    if packet.len() < 28 {
        return None;
    }
    // Only IPv4, IHL 5 (no options).
    if packet[0] >> 4 != 4 {
        return None;
    }
    let ihl = (packet[0] & 0x0F) as usize * 4;
    if ihl < 20 || packet.len() < ihl + 8 {
        return None;
    }
    if packet[9] != 1 {
        return None; // not ICMP
    }
    let icmp = &packet[ihl..];
    if icmp[0] != 0 {
        return None; // not an echo reply
    }
    Some(u16::from_be_bytes([icmp[6], icmp[7]]))
}

/// Derives the WireGuard server address from the client's assigned address.
///
/// The WDTT server always takes the first host of the client's /24, e.g.
/// client `10.66.66.2` → server `10.66.66.1`, client `10.9.0.52` → server
/// `10.9.0.1`.
pub fn server_address(client: Ipv4Addr) -> Ipv4Addr {
    let octets = client.octets();
    Ipv4Addr::new(octets[0], octets[1], octets[2], 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_matches_a_known_packet() {
        // The IPv4 header checksum of a well-known ping packet.
        let mut header = [
            0x45, 0x00, 0x00, 0x54, 0x00, 0x00, 0x40, 0x00, 0x40, 0x01, 0x00, 0x00, 0xc0, 0xa8,
            0x01, 0x01, 0xc0, 0xa8, 0x01, 0x02,
        ];
        let sum = checksum(&header);
        header[10] = (sum >> 8) as u8;
        header[11] = sum as u8;
        // A correct header checksums to zero.
        assert_eq!(checksum(&header), 0);
    }

    #[test]
    fn builds_a_valid_echo_request() {
        let src = Ipv4Addr::new(10, 9, 0, 52);
        let dst = Ipv4Addr::new(10, 9, 0, 1);
        let packet = echo_request(src, dst, 0x1234, 1, b"wdtt-selftest");

        assert_eq!(packet[0], 0x45);
        assert_eq!(packet[8], 64, "TTL");
        assert_eq!(packet[9], 1, "ICMP");
        assert_eq!(&packet[12..16], &src.octets());
        assert_eq!(&packet[16..20], &dst.octets());
        assert_eq!(packet[20], 8, "echo request");
        // Both checksums must validate.
        assert_eq!(checksum(&packet[..20]), 0);
        assert_eq!(checksum(&packet[20..]), 0);
        assert_eq!(&packet[28..], b"wdtt-selftest");
    }

    #[test]
    fn parses_echo_replies() {
        let src = Ipv4Addr::new(10, 9, 0, 1);
        let dst = Ipv4Addr::new(10, 9, 0, 52);
        let request = echo_request(src, dst, 7, 42, b"ping");
        // Turn the request into a reply by flipping the ICMP type and fixing
        // the checksum.
        let mut reply = request.clone();
        reply[20] = 0;
        reply[22] = 0;
        reply[23] = 0;
        let sum = checksum(&reply[20..]);
        reply[22..24].copy_from_slice(&sum.to_be_bytes());

        assert_eq!(echo_reply_seq(&reply), Some(42));
        // A request is not a reply.
        assert_eq!(echo_reply_seq(&request), None);
        // Garbage is ignored.
        assert_eq!(echo_reply_seq(&[]), None);
        assert_eq!(echo_reply_seq(&[0u8; 10]), None);
    }

    #[test]
    fn derives_the_server_address() {
        assert_eq!(
            server_address(Ipv4Addr::new(10, 66, 66, 2)),
            Ipv4Addr::new(10, 66, 66, 1)
        );
        assert_eq!(
            server_address(Ipv4Addr::new(10, 9, 0, 52)),
            Ipv4Addr::new(10, 9, 0, 1)
        );
    }
}
