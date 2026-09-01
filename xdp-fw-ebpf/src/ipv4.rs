use crate::utils::ptr_at;
use aya_ebpf::{bindings::xdp_action, programs::XdpContext};
use network_types::ip::{IpError, IpProto, Ipv4Hdr};

#[inline(always)]
pub fn handle_ipv4(ctx: &XdpContext, offset: usize) -> Result<u32, ()> {
    let ipv4_hdr: *const Ipv4Hdr = ptr_at(ctx, offset)?;

    let proto = unsafe { (*ipv4_hdr).proto() }.map_err(|IpError::InvalidProto(_)| ())?;

    let l4_offset = offset + Ipv4Hdr::LEN;

    match proto {
        IpProto::Tcp => crate::l4::tcp::handle_tcp(ctx, l4_offset),
        IpProto::Udp => crate::l4::udp::handle_udp(ctx, l4_offset),
        IpProto::Icmp => Ok(xdp_action::XDP_PASS),
        _ => Ok(xdp_action::XDP_PASS),
    }
}
