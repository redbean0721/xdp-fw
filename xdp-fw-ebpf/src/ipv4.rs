use crate::utils::ptr_at;
use aya_ebpf::{bindings::xdp_action, programs::XdpContext};
use network_types::ip::{IpError, IpProto, Ipv4Hdr};

#[inline(always)]
pub fn handle_ipv4(ctx: &XdpContext, offset: usize) -> Result<u32, ()> {
    let ipv4_hdr: *const Ipv4Hdr = ptr_at(ctx, offset)?;

    let proto = unsafe { (*ipv4_hdr).proto() }.map_err(|IpError::InvalidProto(_)| ())?;

    let _l4_offset = offset + Ipv4Hdr::LEN;

    match proto {
        IpProto::Tcp => {}
        IpProto::Udp => {}
        IpProto::Icmp => {}
        _ => {}
    }

    Ok(xdp_action::XDP_PASS)
}
