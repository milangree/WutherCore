//! core-outbound —— 出站协议适配器。
//!
//! §11.2 关键 trait [`OutboundAdapter`]：所有出站使用统一接口。
//! MVP 阶段实现 direct / block / http / socks5 / shadowsocks（基础 AEAD）。
//! 其它协议（vmess / vless / trojan / hysteria2 / tuic / wireguard / ssh）
//! 提供 stub 适配器，并在 dial 时返回"协议尚未实现"。

#![forbid(unsafe_code)]

pub mod adapter;
pub mod loopback;
pub mod registry;

pub mod block;
pub mod direct;
pub mod dns_hijack;
pub mod http;
pub mod socks5;
pub mod stub;

pub mod proto;
pub mod transport;

pub use adapter::{
    apply_outbound_mark, apply_outbound_mark_for_addr, bind_to_device,
    create_outbound_udp_socket, global_dial_resolver, has_socket_protector, next_dial_id,
    outbound_fwmark, outbound_interface, prepare_outbound_udp_socket,
    prepare_outbound_udp_socket_for_addr, protect_socket, resolve_host, set_global_dial_resolver,
    set_outbound_fwmark, set_outbound_interface, set_socket_protector, should_mark_outbound_addr,
    BoxedStream, BoxedUdp, Capabilities, DialContext, DialResolver, OutboundAdapter,
    ProtectedSocket, ProxyStream, SocketProtector, UdpSocketLike,
};
pub use dns_hijack::{
    global_dns_responder, set_global_dns_responder, DnsHijackOutbound, DnsResponder,
};
pub use loopback::{
    is_loopback_tcp_source, is_loopback_udp_source, register_tcp, register_udp, LoopbackTcpGuard,
    LoopbackUdpGuard, TrackedTcpStream,
};
pub use registry::{OutboundRegistry, ResolveFn};
