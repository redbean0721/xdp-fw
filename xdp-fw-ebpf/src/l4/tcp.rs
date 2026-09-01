use crate::utils::ptr_at;
use aya_ebpf::{bindings::xdp_action, programs::XdpContext};
use network_types::tcp::TcpHdr;

#[inline(always)]
pub fn handle_tcp(ctx: &XdpContext, l4_offset: usize) -> Result<u32, ()> {
    let tcp_hdr: *const TcpHdr = ptr_at(ctx, l4_offset)?;

    let src_port = u16::from_be_bytes(unsafe { (*tcp_hdr).source });
    let dst_port = u16::from_be_bytes(unsafe { (*tcp_hdr).dest });

    let data_offset = unsafe { (*tcp_hdr).doff() };
    let tcp_hdr_len = (data_offset as usize) * 4; // TCP header length in bytes

    let payload_offset = l4_offset + tcp_hdr_len;

    Ok(xdp_action::XDP_PASS)
}
