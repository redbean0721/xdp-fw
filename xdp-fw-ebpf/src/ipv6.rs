use crate::utils::ptr_at;
use aya_ebpf::{bindings::xdp_action, programs::XdpContext};
use network_types::ip::{IpProto, Ipv6Hdr};

#[inline(always)]
pub fn handle_ipv6(ctx: &XdpContext, offset: usize) -> Result<u32, ()> {
    let ipv6_hdr: *const Ipv6Hdr = ptr_at(ctx, offset)?;

    let next_hdr = unsafe { (*ipv6_hdr).next_hdr };
    let l4_offset = offset + Ipv6Hdr::LEN;

    if next_hdr == IpProto::Tcp as u8 {
        crate::l4::tcp::handle_tcp(ctx, l4_offset)
    } else if next_hdr == IpProto::Udp as u8 {
        crate::l4::udp::handle_udp(ctx, l4_offset)
    } else if next_hdr == IpProto::Ipv6Icmp as u8 {
        Ok(xdp_action::XDP_PASS)
    } else {
        Ok(xdp_action::XDP_PASS)
    }
}
