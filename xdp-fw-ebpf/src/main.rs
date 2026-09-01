#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)]

mod ipv4;
mod ipv6;
mod utils;

use crate::utils::ptr_at;
use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use network_types::eth::{EthHdr, EtherType};

#[xdp]
pub fn xdp_fw(ctx: XdpContext) -> u32 {
    match try_xdp_fw(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_xdp_fw(ctx: XdpContext) -> Result<u32, ()> {
    let eth_hdr: *const EthHdr = ptr_at(&ctx, 0)?;
    let eth_type = unsafe { (*eth_hdr).ether_type() };

    let l3_offset = EthHdr::LEN;

    match eth_type {
        Ok(EtherType::Ipv4) => ipv4::handle_ipv4(&ctx, l3_offset),
        Ok(EtherType::Ipv6) => ipv6::handle_ipv6(&ctx, l3_offset),
        _ => Ok(xdp_action::XDP_PASS),
    }
}

#[cfg(target_arch = "bpf")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
