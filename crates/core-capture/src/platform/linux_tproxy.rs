//! Linux 完整 TPROXY socket —— 真正接管被 nftables / iptables `TPROXY` 标记
//! 重定向到本地端口的连接。
//!
//! ## 工作流
//!
//! 1. nftables / iptables 已经在 prerouting 链插入 `tproxy ... to :7894 mark 1`；
//! 2. 路由表把 fwmark 1 的流量送到 lo；
//! 3. 本模块创建带 `IP_TRANSPARENT` 的 listening socket，监听 `:7894`；
//! 4. accept TCP / recv UDP；用 `getsockopt(SOL_IP, SO_ORIGINAL_DST)`
//!    （TCP redirect 模式）或 `IP_RECVORIGDSTADDR`（UDP TPROXY 模式）拿到
//!    *原始目标地址*；
//! 5. 把 (5-tuple, payload) 通过 [`CaptureEvent`] 推给 supervisor。
//!
//! ## unsafe 政策
//!
//! `unsafe` 仅用于 libc socket/setsockopt/bind/recvmsg 与地址结构转换；每个调用点
//! 都维持单一 fd 所有权并就地说明指针、缓冲区或结构体布局前提。

#![cfg(any(target_os = "linux", target_os = "android"))]

use std::{
    future::Future,
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    sync::Arc,
    time::{Duration, Instant},
};

use core_observe::ConnectionGuard;
use core_outbound::adapter::BoxedUdp;
use core_runtime::{InboundMetadata, ListenerHandler};
use dashmap::DashMap;
use parking_lot::Mutex;
use tokio::{
    net::{TcpListener, UdpSocket},
    sync::{mpsc, oneshot, watch},
    task::JoinSet,
};
use tracing::{debug, info, warn};

use crate::{
    engine::{CaptureError, CaptureEvent},
    udp_session::UdpFlowKey,
};

const SO_ORIGINAL_DST: libc::c_int = 80;

type TproxyUdpSessionTable = Arc<DashMap<UdpFlowKey, Arc<TproxyUdpSession>>>;

struct TproxyUdpSession {
    socket: BoxedUdp,
    guard: ConnectionGuard,
    return_socket: Arc<UdpSocket>,
    target_host: String,
    target_port: u16,
    peer: SocketAddr,
    last_seen: Mutex<Instant>,
}

impl TproxyUdpSession {
    fn touch(&self) {
        *self.last_seen.lock() = Instant::now();
    }
}

pub(crate) struct TproxyListeners {
    tcp: TcpListener,
    udp: UdpSocket,
    bind: SocketAddr,
}

impl TproxyListeners {
    pub(crate) fn into_parts(self) -> (TcpListener, UdpSocket, SocketAddr) {
        (self.tcp, self.udp, self.bind)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransparentSocketKind {
    Tcp,
    Udp,
}

trait TransparentSocketOps {
    type Socket;

    fn socket(&mut self, addr: SocketAddr, kind: TransparentSocketKind)
    -> io::Result<Self::Socket>;
    fn set_ip_transparent(&mut self, socket: &Self::Socket) -> io::Result<()>;
    fn set_recv_original_dst(&mut self, socket: &Self::Socket, addr: SocketAddr) -> io::Result<()>;
    fn set_reuse_addr(&mut self, socket: &Self::Socket) -> io::Result<()>;
    fn bind(&mut self, socket: &Self::Socket, addr: SocketAddr) -> io::Result<()>;
    fn listen(&mut self, socket: &Self::Socket) -> io::Result<()>;
}

fn configure_transparent_socket<O: TransparentSocketOps>(
    ops: &mut O,
    addr: SocketAddr,
    kind: TransparentSocketKind,
) -> io::Result<O::Socket> {
    let socket = ops.socket(addr, kind)?;
    ops.set_ip_transparent(&socket)?;
    if kind == TransparentSocketKind::Udp {
        ops.set_recv_original_dst(&socket, addr)?;
    }
    ops.set_reuse_addr(&socket)?;
    ops.bind(&socket, addr)?;
    if kind == TransparentSocketKind::Tcp {
        ops.listen(&socket)?;
    }
    Ok(socket)
}

struct LibcTransparentSocketOps;

impl TransparentSocketOps for LibcTransparentSocketOps {
    type Socket = OwnedFd;

    #[allow(unsafe_code)]
    fn socket(
        &mut self,
        addr: SocketAddr,
        kind: TransparentSocketKind,
    ) -> io::Result<Self::Socket> {
        let domain = if addr.is_ipv4() {
            libc::AF_INET
        } else {
            libc::AF_INET6
        };
        let socket_type = match kind {
            TransparentSocketKind::Tcp => libc::SOCK_STREAM,
            TransparentSocketKind::Udp => libc::SOCK_DGRAM,
        };
        let fd = unsafe { libc::socket(domain, socket_type | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fd was just returned by socket() and this OwnedFd is its sole owner.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    fn set_ip_transparent(&mut self, socket: &Self::Socket) -> io::Result<()> {
        set_ip_transparent(socket.as_raw_fd())
    }

    fn set_recv_original_dst(&mut self, socket: &Self::Socket, addr: SocketAddr) -> io::Result<()> {
        set_ip_recvorigdstaddr(socket.as_raw_fd())?;
        if addr.is_ipv6() {
            set_ipv6_recvorigdstaddr(socket.as_raw_fd())?;
        }
        Ok(())
    }

    fn set_reuse_addr(&mut self, socket: &Self::Socket) -> io::Result<()> {
        set_reuse_addr(socket.as_raw_fd())
    }

    fn bind(&mut self, socket: &Self::Socket, addr: SocketAddr) -> io::Result<()> {
        bind_socket_fd(socket.as_raw_fd(), addr)
    }

    #[allow(unsafe_code)]
    fn listen(&mut self, socket: &Self::Socket) -> io::Result<()> {
        let rc = unsafe { libc::listen(socket.as_raw_fd(), libc::SOMAXCONN) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

pub(crate) fn ipv4_tproxy_bind_addr(port: u16) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port))
}

pub(crate) fn bind_tproxy_listeners(bind: SocketAddr) -> Result<TproxyListeners, CaptureError> {
    let mut ops = LibcTransparentSocketOps;
    let tcp_fd =
        configure_transparent_socket(&mut ops, bind, TransparentSocketKind::Tcp).map_err(|e| {
            CaptureError::DeviceFailed(format!("prepare transparent TCP listener {bind}: {e}"))
        })?;
    let tcp_std: std::net::TcpListener = tcp_fd.into();
    tcp_std.set_nonblocking(true)?;
    let tcp = TcpListener::from_std(tcp_std)?;

    let udp_fd =
        configure_transparent_socket(&mut ops, bind, TransparentSocketKind::Udp).map_err(|e| {
            CaptureError::DeviceFailed(format!("prepare transparent UDP listener {bind}: {e}"))
        })?;
    let udp_std: std::net::UdpSocket = udp_fd.into();
    udp_std.set_nonblocking(true)?;
    let udp = UdpSocket::from_std(udp_std)?;

    Ok(TproxyListeners { tcp, udp, bind })
}

/// 启动一个 TPROXY TCP listener；accept 后立即 dial 出站并双向 splice，
/// 同时推一条事件给 supervisor 用于 NAT / 调试日志。
///
/// 之前的实现 `drop(stream)` 是 bug：客户端跟我们建了 TCP，但我们从未把
/// 对应的入站字节流接到代理出站上 —— 表现为"拨号成功但应用收不到任何数据"。
pub(crate) async fn run_tcp_tproxy(
    listener: TcpListener,
    events: mpsc::Sender<CaptureEvent>,
    runtime: Arc<core_runtime::Runtime>,
    mut stop: oneshot::Receiver<()>,
) -> Result<(), CaptureError> {
    let bind = listener.local_addr()?;
    // JoinSet owns every accepted relay. The engine stop path drops this
    // listener future, and JoinSet::drop aborts all relays so none survive a
    // reported TPROXY shutdown.
    let mut connections = JoinSet::new();
    info!(target: "capture::tproxy", addr = %bind, "tcp tproxy listening (dial+splice inline)");

    loop {
        let accepted = tokio::select! {
            _ = &mut stop => {
                connections.shutdown().await;
                return Ok(());
            }
            accepted = listener.accept() => Some(accepted),
            joined = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(error)) = joined {
                    debug!(target: "capture::tproxy", %error, "tcp relay task ended unexpectedly");
                }
                None
            }
        };
        let Some(accepted) = accepted else {
            continue;
        };
        let (stream, peer) = match accepted {
            Ok(p) => p,
            Err(e) => {
                warn!(target: "capture::tproxy", error = %e, "accept failed");
                continue;
            }
        };
        let fd = stream.as_raw_fd();
        let original_dst = match get_orig_dst_v4(fd) {
            Ok(addr) => SocketAddr::V4(addr),
            Err(e) => {
                debug!(target: "capture::tproxy", error = %e, "SO_ORIGINAL_DST failed; using local_addr");
                stream.local_addr()?
            }
        };
        let evt = CaptureEvent {
            original_dst,
            source: peer,
            network: "tcp",
            fake_host: None,
        };
        let _ = events.try_send(evt);

        let runtime = runtime.clone();
        let bind_local = bind;
        connections.spawn(async move {
            let host = original_dst.ip().to_string();
            let port = original_dst.port();
            let handler = ListenerHandler::new(runtime);
            let metadata =
                InboundMetadata::tcp("tproxy", "TPROXY", peer, bind_local, host.clone(), port)
                    .with_destination_ip(Some(original_dst.ip()))
                    .with_route_ip(Some(original_dst.ip()));
            match handler.prepare_tcp(metadata).await {
                Ok(prepared) => {
                    let outbound = prepared.result.outbound.clone();
                    if let Err(e) = handler.relay_prepared_tcp(stream, prepared).await {
                        debug!(
                            target: "capture::tproxy",
                            %host, port, outbound = %outbound,
                            error = %e,
                            "splice ended (inbound/outbound EOF or error)"
                        );
                    }
                }
                Err(e) => {
                    warn!(
                        target: "capture::tproxy",
                        %host, port,
                        error = %e,
                        "tproxy dial failed; closing inbound"
                    );
                }
            }
        });
    }
}

/// UDP TPROXY —— `IP_TRANSPARENT` + `IP_RECVORIGDSTADDR`，`recvmsg` 解析 cmsg
/// 拿到原始目标地址（`IP_ORIGDSTADDR` / `IPV6_ORIGDSTADDR`）。
pub(crate) async fn run_udp_tproxy(
    socket: UdpSocket,
    events: mpsc::Sender<CaptureEvent>,
    runtime: Arc<core_runtime::Runtime>,
    mut stop: oneshot::Receiver<()>,
) -> Result<(), CaptureError> {
    let bind = socket.local_addr()?;
    let sock = Arc::new(socket);
    info!(target: "capture::tproxy", addr = %bind, "udp tproxy listening (handler.NewPacket)");

    let handler = ListenerHandler::new(runtime);
    let sessions: TproxyUdpSessionTable = Arc::new(DashMap::new());
    // Only this listener future owns the sender. Engine stop drops the future,
    // closing the channel and waking every per-flow return loop. This avoids
    // a sessions-map/task ownership cycle that would otherwise keep forwarding
    // UDP after `LinuxTproxy::stop` returned.
    let (shutdown_tx, shutdown_rx) = watch::channel(());
    let mut shutdown_tx = Some(shutdown_tx);
    let mut return_loops = JoinSet::new();
    let mut gc = tokio::time::interval(Duration::from_secs(30));
    gc.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut buf = vec![0u8; 65535];
    loop {
        tokio::select! {
            _ = &mut stop => {
                shutdown_udp_return_loops(
                    &mut shutdown_tx,
                    &mut return_loops,
                    &sessions,
                ).await;
                return Ok(());
            }
            joined = return_loops.join_next(), if !return_loops.is_empty() => {
                if let Some(Err(error)) = joined {
                    debug!(target: "capture::tproxy", %error, "udp return task ended unexpectedly");
                }
            }
            _ = gc.tick() => {
                let removed = purge_tproxy_udp_sessions(&sessions, Duration::from_secs(90));
                if removed > 0 {
                    debug!(target: "capture::tproxy", removed, remaining = sessions.len(), "udp session gc");
                }
            }
            ready = sock.readable() => {
                ready?;
                let r = sock.try_io(tokio::io::Interest::READABLE, || {
                    recvmsg_with_origdst(sock.as_raw_fd(), &mut buf)
                });
                let (n, peer, original_dst) = match r {
                    Ok((n, peer, dst)) => match require_udp_original_dst(peer, dst) {
                        Ok(dst) => (n, peer, dst),
                        Err(error) => {
                            warn!(target: "capture::tproxy", %peer, %error, "dropping UDP packet");
                            continue;
                        }
                    },
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Err(e) => {
                        warn!(target: "capture::tproxy", error = %e, "recvmsg failed");
                        continue;
                    }
                };
                if n == 0 {
                    continue;
                }
                let payload = buf[..n].to_vec();
                let evt = CaptureEvent {
                    original_dst,
                    source: peer,
                    network: "udp",
                    fake_host: None,
                };
                let _ = events.try_send(evt);

                let key = UdpFlowKey { src: peer, dst: original_dst };
                if let Some(session) = sessions.get(&key).map(|s| s.value().clone()) {
                    let Some(sent) = udp_operation_or_stop(
                        &mut stop,
                        session.socket.send_to(
                            &payload,
                            &session.target_host,
                            session.target_port,
                        ),
                    )
                    .await
                    else {
                        shutdown_udp_return_loops(
                            &mut shutdown_tx,
                            &mut return_loops,
                            &sessions,
                        )
                        .await;
                        return Ok(());
                    };
                    match sent {
                        Ok(_) => {
                            handler.record_upload(&session.guard, n as u64);
                            session.touch();
                        }
                        Err(e) => {
                            debug!(target: "capture::tproxy", error = %e, "udp reuse send failed; remove session");
                            remove_tproxy_udp_session(&sessions, &key);
                        }
                    }
                    continue;
                }

                let target_host = original_dst.ip().to_string();
                let target_port = original_dst.port();
                let metadata = InboundMetadata::udp(
                    "tproxy",
                    "TPROXY",
                    peer,
                    Some(bind),
                    target_host.clone(),
                    target_port,
                )
                .with_destination_ip(Some(original_dst.ip()))
                .with_route_ip(Some(original_dst.ip()));
                let Some(prepared_result) =
                    udp_operation_or_stop(&mut stop, handler.new_packet(metadata)).await
                else {
                    shutdown_udp_return_loops(
                        &mut shutdown_tx,
                        &mut return_loops,
                        &sessions,
                    )
                    .await;
                    return Ok(());
                };
                let prepared = match prepared_result {
                    Ok(prepared) => prepared,
                    Err(e) => {
                        debug!(
                            target: "capture::tproxy",
                            %target_host,
                            target_port,
                            error = %e,
                            "udp dial failed"
                        );
                        continue;
                    }
                };
                let return_socket = match bind_transparent_udp(original_dst) {
                    Ok(sock) => Arc::new(sock),
                    Err(e) => {
                        warn!(
                            target: "capture::tproxy",
                            %original_dst,
                            error = %e,
                            "udp transparent return socket bind failed"
                        );
                        continue;
                    }
                };
                let session = Arc::new(TproxyUdpSession {
                    socket: prepared.socket,
                    guard: prepared.guard,
                    return_socket,
                    target_host: prepared.target_host,
                    target_port: prepared.target_port,
                    peer,
                    last_seen: Mutex::new(Instant::now()),
                });
                sessions.insert(key, session.clone());
                spawn_tproxy_udp_return_loop(
                    &mut return_loops,
                    key,
                    sessions.clone(),
                    session.clone(),
                    handler.runtime().metrics.clone(),
                    shutdown_rx.clone(),
                );
                let Some(sent) = udp_operation_or_stop(
                    &mut stop,
                    session.socket.send_to(
                        &payload,
                        &session.target_host,
                        session.target_port,
                    ),
                )
                .await
                else {
                    shutdown_udp_return_loops(
                        &mut shutdown_tx,
                        &mut return_loops,
                        &sessions,
                    )
                    .await;
                    return Ok(());
                };
                match sent {
                    Ok(_) => {
                        handler.record_upload(&session.guard, n as u64);
                        session.touch();
                    }
                    Err(e) => {
                        debug!(
                            target: "capture::tproxy",
                            host = %session.target_host,
                            port = session.target_port,
                            error = %e,
                            "udp first send failed"
                        );
                        remove_tproxy_udp_session(&sessions, &key);
                    }
                }
            }
        }
    }
}

async fn udp_operation_or_stop<T>(
    stop: &mut oneshot::Receiver<()>,
    operation: impl Future<Output = T>,
) -> Option<T> {
    tokio::select! {
        _ = stop => None,
        output = operation => Some(output),
    }
}

async fn shutdown_udp_return_loops(
    shutdown_tx: &mut Option<watch::Sender<()>>,
    return_loops: &mut JoinSet<()>,
    sessions: &TproxyUdpSessionTable,
) {
    // Closing the watch channel wakes every return loop even if it has not yet
    // observed a value change. Join them before reporting the listener stopped.
    drop(shutdown_tx.take());
    while let Some(joined) = return_loops.join_next().await {
        if let Err(error) = joined {
            debug!(target: "capture::tproxy", %error, "udp return task ended unexpectedly");
        }
    }
    sessions.clear();
}

fn require_udp_original_dst(
    peer: SocketAddr,
    original_dst: Option<SocketAddr>,
) -> io::Result<SocketAddr> {
    original_dst.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("missing original-destination control message from {peer}"),
        )
    })
}

fn spawn_tproxy_udp_return_loop(
    return_loops: &mut JoinSet<()>,
    key: UdpFlowKey,
    sessions: TproxyUdpSessionTable,
    session: Arc<TproxyUdpSession>,
    metrics: Arc<core_observe::Metrics>,
    mut shutdown: watch::Receiver<()>,
) {
    return_loops.spawn(async move {
        metrics.inc_connection();
        let cancel = session.guard.cancel.clone();
        let mut buf = vec![0u8; 65535];
        loop {
            tokio::select! {
                _ = shutdown.changed() => break,
                _ = cancel.notified() => break,
                r = session.socket.recv_from(&mut buf) => {
                    let n = match r {
                        Ok(n) => n,
                        Err(e) => {
                            debug!(target: "capture::tproxy", error = %e, "udp outbound recv ended");
                            break;
                        }
                    };
                    if n == 0 {
                        break;
                    }
                    let returned = tokio::select! {
                        _ = shutdown.changed() => break,
                        _ = cancel.notified() => break,
                        returned = session.return_socket.send_to(&buf[..n], session.peer) => returned,
                    };
                    if let Err(e) = returned {
                        warn!(
                            target: "capture::tproxy",
                            peer = %session.peer,
                            error = %e,
                            "udp transparent return failed"
                        );
                        break;
                    }
                    session.guard.record_download(n as u64);
                    metrics.add_down(n as u64);
                    session.touch();
                }
            }
        }
        remove_tproxy_udp_session(&sessions, &key);
        metrics.dec_connection();
    });
}

fn remove_tproxy_udp_session(sessions: &TproxyUdpSessionTable, key: &UdpFlowKey) {
    if let Some((_, session)) = sessions.remove(key) {
        // There is exactly one return loop per session. notify_one stores a
        // permit when the loop is between awaits, avoiding notify_waiters'
        // lost-wakeup race during purge or first-send failure.
        session.guard.cancel.notify_one();
    }
}

fn purge_tproxy_udp_sessions(sessions: &TproxyUdpSessionTable, idle: Duration) -> usize {
    let cutoff = Instant::now() - idle;
    let keys: Vec<UdpFlowKey> = sessions
        .iter()
        .filter_map(|entry| {
            let last_seen = *entry.value().last_seen.lock();
            if last_seen < cutoff {
                Some(*entry.key())
            } else {
                None
            }
        })
        .collect();
    let removed = keys.len();
    for key in keys {
        remove_tproxy_udp_session(sessions, &key);
    }
    removed
}

/* ---------------- unsafe 区 ---------------- */

#[allow(unsafe_code)]
fn bind_transparent_udp(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    let domain = if addr.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    let fd = unsafe { libc::socket(domain, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let result = (|| {
        set_reuse_addr_port(fd)?;
        set_ip_transparent(fd)?;
        bind_socket_fd(fd, addr)?;
        Ok::<(), std::io::Error>(())
    })();
    if let Err(e) = result {
        unsafe {
            libc::close(fd);
        }
        return Err(e);
    }
    let std_sock = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
    std_sock.set_nonblocking(true)?;
    UdpSocket::from_std(std_sock)
}

#[allow(unsafe_code)]
fn set_reuse_addr(fd: RawFd) -> std::io::Result<()> {
    let one: libc::c_int = 1;
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[allow(unsafe_code)]
fn set_reuse_addr_port(fd: RawFd) -> std::io::Result<()> {
    set_reuse_addr(fd)?;
    let one: libc::c_int = 1;
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEPORT,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[allow(unsafe_code)]
fn bind_socket_fd(fd: RawFd, addr: SocketAddr) -> std::io::Result<()> {
    let rc = match addr {
        SocketAddr::V4(v4) => {
            let raw = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: v4.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(v4.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            unsafe {
                libc::bind(
                    fd,
                    &raw as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            }
        }
        SocketAddr::V6(v6) => {
            let raw = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: v6.port().to_be(),
                sin6_flowinfo: v6.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: v6.ip().octets(),
                },
                sin6_scope_id: v6.scope_id(),
            };
            unsafe {
                libc::bind(
                    fd,
                    &raw as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                )
            }
        }
    };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[allow(unsafe_code)]
fn set_ip_transparent(fd: RawFd) -> std::io::Result<()> {
    let one: libc::c_int = 1;
    // SAFETY: setsockopt 平凡；指针指向栈上 c_int。
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_IP,
            libc::IP_TRANSPARENT,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[allow(unsafe_code)]
fn set_ipv6_recvorigdstaddr(fd: RawFd) -> std::io::Result<()> {
    let one: libc::c_int = 1;
    // SAFETY: setsockopt 平凡；指针指向栈上 c_int。
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_RECVORIGDSTADDR,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[allow(unsafe_code)]
fn set_ip_recvorigdstaddr(fd: RawFd) -> std::io::Result<()> {
    let one: libc::c_int = 1;
    // SAFETY: 同上。
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_IP,
            libc::IP_RECVORIGDSTADDR,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// `recvmsg` + `IP_ORIGDSTADDR` / `IPV6_ORIGDSTADDR` cmsg 解析。
#[allow(unsafe_code)]
fn recvmsg_with_origdst(
    fd: RawFd,
    buf: &mut [u8],
) -> std::io::Result<(usize, SocketAddr, Option<SocketAddr>)> {
    let mut name: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    // 控制缓冲：足够装一个 IPv6 cmsg（IPv4 cmsg 更小）。
    let mut control = [0u8; 128];
    let mut hdr: libc::msghdr = unsafe { std::mem::zeroed() };
    hdr.msg_name = &mut name as *mut _ as *mut libc::c_void;
    hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    hdr.msg_iov = &mut iov;
    hdr.msg_iovlen = 1;
    hdr.msg_control = control.as_mut_ptr() as *mut libc::c_void;
    hdr.msg_controllen = control.len() as libc::size_t;

    // SAFETY: msghdr 字段全部初始化；recvmsg 写入 name/iov/control 不超过提供长度。
    let n = unsafe { libc::recvmsg(fd, &mut hdr, 0) };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let peer = sockaddr_storage_to_socket_addr(&name)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad peer addr"))?;

    // 遍历 cmsg 找 IP_ORIGDSTADDR / IPV6_ORIGDSTADDR
    let original_dst = unsafe { extract_origdst(&hdr) };

    Ok((n as usize, peer, original_dst))
}

#[allow(unsafe_code)]
unsafe fn extract_origdst(hdr: &libc::msghdr) -> Option<SocketAddr> {
    // SAFETY: 调用方保证 hdr 指向 recvmsg 刚返回的有效 msghdr，cmsg 链由内核填写。
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(hdr) };
    while !cmsg.is_null() {
        let level = unsafe { (*cmsg).cmsg_level };
        let typ = unsafe { (*cmsg).cmsg_type };
        if level == libc::SOL_IP && typ == libc::IP_ORIGDSTADDR {
            let data = unsafe { libc::CMSG_DATA(cmsg) } as *const libc::sockaddr_in;
            let sa = unsafe { std::ptr::read_unaligned(data) };
            let ip = Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr));
            let port = u16::from_be(sa.sin_port);
            return Some(SocketAddr::V4(SocketAddrV4::new(ip, port)));
        }
        if level == libc::IPPROTO_IPV6 && typ == libc::IPV6_ORIGDSTADDR {
            let data = unsafe { libc::CMSG_DATA(cmsg) } as *const libc::sockaddr_in6;
            let sa = unsafe { std::ptr::read_unaligned(data) };
            let ip = Ipv6Addr::from(sa.sin6_addr.s6_addr);
            let port = u16::from_be(sa.sin6_port);
            return Some(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)));
        }
        cmsg = unsafe { libc::CMSG_NXTHDR(hdr, cmsg) };
    }
    None
}

#[allow(unsafe_code)]
fn sockaddr_storage_to_socket_addr(s: &libc::sockaddr_storage) -> Option<SocketAddr> {
    let family = s.ss_family as i32;
    if family == libc::AF_INET {
        // SAFETY: 当 ss_family=AF_INET 时 layout 是 sockaddr_in。
        let v4: &libc::sockaddr_in = unsafe { &*(s as *const _ as *const libc::sockaddr_in) };
        let ip = Ipv4Addr::from(u32::from_be(v4.sin_addr.s_addr));
        Some(SocketAddr::V4(SocketAddrV4::new(
            ip,
            u16::from_be(v4.sin_port),
        )))
    } else if family == libc::AF_INET6 {
        // SAFETY: 同理。
        let v6: &libc::sockaddr_in6 = unsafe { &*(s as *const _ as *const libc::sockaddr_in6) };
        let ip = Ipv6Addr::from(v6.sin6_addr.s6_addr);
        Some(SocketAddr::V6(SocketAddrV6::new(
            ip,
            u16::from_be(v6.sin6_port),
            0,
            0,
        )))
    } else {
        None
    }
}

#[allow(unsafe_code)]
fn get_orig_dst_v4(fd: RawFd) -> std::io::Result<SocketAddrV4> {
    // SAFETY: getsockopt 写入 sockaddr_in；len 初始化为结构体大小，调用后被内核更新。
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut len: libc::socklen_t = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_IP,
            SO_ORIGINAL_DST,
            &mut addr as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let ip = u32::from_be(addr.sin_addr.s_addr);
    let port = u16::from_be(addr.sin_port);
    Ok(SocketAddrV4::new(Ipv4Addr::from(ip), port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum SocketStep {
        Socket,
        Transparent,
        RecvOriginalDst,
        ReuseAddr,
        Bind,
        Listen,
    }

    #[derive(Default)]
    struct RecordingSocketOps {
        steps: Vec<SocketStep>,
    }

    impl TransparentSocketOps for RecordingSocketOps {
        type Socket = ();

        fn socket(
            &mut self,
            _addr: SocketAddr,
            _kind: TransparentSocketKind,
        ) -> io::Result<Self::Socket> {
            self.steps.push(SocketStep::Socket);
            Ok(())
        }

        fn set_ip_transparent(&mut self, _socket: &Self::Socket) -> io::Result<()> {
            self.steps.push(SocketStep::Transparent);
            Ok(())
        }

        fn set_recv_original_dst(
            &mut self,
            _socket: &Self::Socket,
            _addr: SocketAddr,
        ) -> io::Result<()> {
            self.steps.push(SocketStep::RecvOriginalDst);
            Ok(())
        }

        fn set_reuse_addr(&mut self, _socket: &Self::Socket) -> io::Result<()> {
            self.steps.push(SocketStep::ReuseAddr);
            Ok(())
        }

        fn bind(&mut self, _socket: &Self::Socket, _addr: SocketAddr) -> io::Result<()> {
            self.steps.push(SocketStep::Bind);
            Ok(())
        }

        fn listen(&mut self, _socket: &Self::Socket) -> io::Result<()> {
            self.steps.push(SocketStep::Listen);
            Ok(())
        }
    }

    struct UnprivilegedSocketOps {
        inner: LibcTransparentSocketOps,
    }

    impl TransparentSocketOps for UnprivilegedSocketOps {
        type Socket = OwnedFd;

        fn socket(
            &mut self,
            addr: SocketAddr,
            kind: TransparentSocketKind,
        ) -> io::Result<Self::Socket> {
            self.inner.socket(addr, kind)
        }

        fn set_ip_transparent(&mut self, _socket: &Self::Socket) -> io::Result<()> {
            Ok(())
        }

        fn set_recv_original_dst(
            &mut self,
            _socket: &Self::Socket,
            _addr: SocketAddr,
        ) -> io::Result<()> {
            Ok(())
        }

        fn set_reuse_addr(&mut self, socket: &Self::Socket) -> io::Result<()> {
            self.inner.set_reuse_addr(socket)
        }

        fn bind(&mut self, socket: &Self::Socket, addr: SocketAddr) -> io::Result<()> {
            self.inner.bind(socket, addr)
        }

        fn listen(&mut self, socket: &Self::Socket) -> io::Result<()> {
            self.inner.listen(socket)
        }
    }

    #[test]
    fn tcp_transparent_options_are_set_before_bind() {
        let bind = ipv4_tproxy_bind_addr(7894);
        let mut ops = RecordingSocketOps::default();

        configure_transparent_socket(&mut ops, bind, TransparentSocketKind::Tcp).unwrap();

        assert!(bind.ip().is_unspecified());
        assert_eq!(
            ops.steps,
            [
                SocketStep::Socket,
                SocketStep::Transparent,
                SocketStep::ReuseAddr,
                SocketStep::Bind,
                SocketStep::Listen,
            ]
        );
    }

    #[test]
    fn udp_transparent_options_are_set_before_bind() {
        let mut ops = RecordingSocketOps::default();

        configure_transparent_socket(
            &mut ops,
            ipv4_tproxy_bind_addr(7894),
            TransparentSocketKind::Udp,
        )
        .unwrap();

        assert_eq!(
            ops.steps,
            [
                SocketStep::Socket,
                SocketStep::Transparent,
                SocketStep::RecvOriginalDst,
                SocketStep::ReuseAddr,
                SocketStep::Bind,
            ]
        );
    }

    #[test]
    fn occupied_port_is_reported_without_requiring_transparent_socket_privileges() {
        let occupied = std::net::TcpListener::bind(ipv4_tproxy_bind_addr(0)).unwrap();
        let bind = occupied.local_addr().unwrap();
        let mut ops = UnprivilegedSocketOps {
            inner: LibcTransparentSocketOps,
        };

        let error =
            configure_transparent_socket(&mut ops, bind, TransparentSocketKind::Tcp).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
    }

    #[test]
    fn udp_packet_without_original_destination_is_rejected() {
        let peer: SocketAddr = "192.0.2.10:54321".parse().unwrap();

        let error = require_udp_original_dst(peer, None).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("original-destination"));
    }

    #[tokio::test]
    async fn stop_interrupts_a_pending_udp_operation() {
        let (stop_tx, mut stop_rx) = oneshot::channel();
        tokio::spawn(async move {
            tokio::task::yield_now().await;
            let _ = stop_tx.send(());
        });

        let result = tokio::time::timeout(
            Duration::from_secs(1),
            udp_operation_or_stop(&mut stop_rx, std::future::pending::<()>()),
        )
        .await
        .expect("stop must interrupt a pending outbound operation");

        assert!(result.is_none());
    }
}
