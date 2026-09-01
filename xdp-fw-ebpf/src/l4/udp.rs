use crate::utils::ptr_at;
use aya_ebpf::{bindings::xdp_action, programs::XdpContext};
use network_types::udp::UdpHdr;

#[inline(always)]
pub fn handle_udp(ctx: &XdpContext, l4_offset: usize) -> Result<u32, ()> {
    let udp_hdr: *const UdpHdr = ptr_at(ctx, l4_offset)?;

    let src_port = u16::from_be_bytes(unsafe { (*udp_hdr).src });
    let dst_port = u16::from_be_bytes(unsafe { (*udp_hdr).dst });

    let payload_offset = l4_offset + UdpHdr::LEN;

    Ok(xdp_action::XDP_PASS)
}
