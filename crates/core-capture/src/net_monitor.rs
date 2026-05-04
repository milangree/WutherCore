//! Network interface change monitor — detects physical NIC state changes
//! and triggers outbound socket rebinding + DNS connection reset.
//!
//! ## Detection
//!
//! - **Linux/Android root TUN**: polls `/proc/net/route` for default route changes.
//!   Uses `/sys/class/net/<iface>/operstate` for link up/down detection.
//! - **Android VpnService**: Java app calls `notifyNetworkChanged()` via JNI
//!   from `ConnectivityManager.NetworkCallback`.
//! - **Manual**: any code can call `notify_network_changed()`.
//!
//! ## Actions on network change
//!
//! 1. `core_outbound::set_outbound_interface(new_iface)` — new sockets `SO_BINDTODEVICE`.
//! 2. Broadcast `NetworkChangeEvent` — supervisor calls `resolver.reset_connections()`
//!    which tears down DoT pools + DoQ sessions, clears DNS cache.
//! 3. Next outbound connection automatically binds to the new physical interface.

use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::RwLock;
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

static MONITOR: once_cell::sync::Lazy<NetworkMonitor> =
    once_cell::sync::Lazy::new(NetworkMonitor::new);

pub struct NetworkMonitor {
    generation: AtomicU64,
    tx: broadcast::Sender<NetworkChangeEvent>,
    default_interface: RwLock<Option<String>>,
}

#[derive(Debug, Clone)]
pub struct NetworkChangeEvent {
    pub generation: u64,
    pub new_interface: Option<String>,
}

impl NetworkMonitor {
    fn new() -> Self {
        let (tx, _) = broadcast::channel(16);
        Self {
            generation: AtomicU64::new(0),
            tx,
            default_interface: RwLock::new(None),
        }
    }

    pub fn notify_changed(&self, new_interface: Option<String>) {
        let gen = self.generation.fetch_add(1, Ordering::Relaxed) + 1;
        *self.default_interface.write() = new_interface.clone();
        info!(
            target: "capture::net_monitor",
            generation = gen,
            interface = ?new_interface,
            "network interface changed — rebinding outbound"
        );

        // Rebind all future outbound sockets to the new interface
        core_outbound::set_outbound_interface(new_interface.clone());

        // Broadcast to listeners (DNS reset, connection teardown)
        let event = NetworkChangeEvent {
            generation: gen,
            new_interface,
        };
        let _ = self.tx.send(event);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<NetworkChangeEvent> {
        self.tx.subscribe()
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Relaxed)
    }

    pub fn default_interface(&self) -> Option<String> {
        self.default_interface.read().clone()
    }

    pub fn set_default_interface(&self, iface: Option<String>) {
        let changed = {
            let current = self.default_interface.read();
            *current != iface
        };
        if changed {
            self.notify_changed(iface);
        }
    }
}

pub fn global() -> &'static NetworkMonitor {
    &MONITOR
}

pub fn notify_network_changed(new_interface: Option<String>) {
    global().set_default_interface(new_interface);
}

pub fn subscribe() -> broadcast::Receiver<NetworkChangeEvent> {
    global().subscribe()
}

/// Start the platform-native network interface watcher.
/// Linux/Android: polls /proc/net/route every 2s for default route changes.
pub fn start_watcher() {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        tokio::spawn(route_poll_watcher());
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        debug!(target: "capture::net_monitor", "no native network watcher on this platform");
    }
}

// ──── Linux/Android: poll /proc/net/route ────

#[cfg(any(target_os = "linux", target_os = "android"))]
async fn route_poll_watcher() {
    use std::time::Duration;

    let mut last_iface = detect_default_interface();

    // Set initial interface
    if let Some(ref iface) = last_iface {
        debug!(target: "capture::net_monitor", interface = %iface, "initial default interface");
        core_outbound::set_outbound_interface(Some(iface.clone()));
        *global().default_interface.write() = Some(iface.clone());
    }

    info!(target: "capture::net_monitor", "route poll watcher started (2s interval)");

    let mut interval = tokio::time::interval(Duration::from_secs(2));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        interval.tick().await;

        let current_iface = detect_default_interface();
        if current_iface != last_iface {
            info!(
                target: "capture::net_monitor",
                old = ?last_iface,
                new = ?current_iface,
                "default route interface changed"
            );
            last_iface = current_iface.clone();
            global().notify_changed(current_iface);
        }

        // Also check link operstate for the current interface
        if let Some(ref iface) = last_iface {
            if !is_interface_up(iface) {
                debug!(
                    target: "capture::net_monitor",
                    interface = %iface,
                    "interface link down, waiting for new default route"
                );
            }
        }
    }
}

/// Read /proc/net/route to find the default route interface.
/// Default route = destination 00000000, mask 00000000.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn detect_default_interface() -> Option<String> {
    let content = std::fs::read_to_string("/proc/net/route").ok()?;
    // Find lowest-metric default route
    let mut best: Option<(String, u32)> = None;
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 11 {
            continue;
        }
        let destination = fields[1];
        let mask = fields[7];
        if destination == "00000000" && mask == "00000000" {
            let iface = fields[0].to_string();
            let metric = fields[6].parse::<u32>().unwrap_or(u32::MAX);
            match &best {
                Some((_, m)) if metric < *m => best = Some((iface, metric)),
                None => best = Some((iface, metric)),
                _ => {}
            }
        }
    }
    best.map(|(iface, _)| iface)
}

/// Check if an interface is operationally up via /sys/class/net/<iface>/operstate.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn is_interface_up(iface: &str) -> bool {
    let path = format!("/sys/class/net/{iface}/operstate");
    std::fs::read_to_string(path)
        .map(|s| {
            let state = s.trim();
            state == "up" || state == "unknown"
        })
        .unwrap_or(false)
}
