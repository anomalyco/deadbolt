//! Which process holds the client end of a loopback TCP connection, looked
//! for only in one process tree.
//!
//! `deadbolt broker` listens on `127.0.0.1` for one `deadbolt run`. On each
//! `accept()` it knows the connection's two ports; [`owner_in_subtree`]
//! walks the run's process and its live descendants (a handful of pids, not
//! the whole system) and answers which of them holds the socket whose local
//! end is `127.0.0.1:<client_port>` and remote end `127.0.0.1:<server_port>`.
//! None of them: the caller is some other process, the same user's or not,
//! and the broker refuses it.
//!
//! - macOS: `proc_listchildpids` for the tree, then each process's open
//!   files (`proc_pidinfo(PROC_PIDLISTFDS)`) and their socket facts
//!   (`proc_pidfdinfo(PROC_PIDFDSOCKETINFO)`), which `libc` declares but
//!   nothing wraps. `struct socket_fdinfo` is read at hand-kept offsets,
//!   the same on arm64 and x86_64; the tests match a real connection
//!   through them.
//! - Linux, no `unsafe`: the socket's inode from one exact
//!   `NETLINK_SOCK_DIAG` lookup, or from `/proc/net/tcp` and `tcp6` on a
//!   kernel without `CONFIG_INET_DIAG` (or a sandbox without netlink),
//!   which costs milliseconds: the kernel walks its whole connection hash
//!   table to print them. Then the tree from
//!   `/proc/<pid>/task/<tid>/children`, then `socket:[<inode>]` among each
//!   process's `/proc/<pid>/fd` links. A process that made itself
//!   undumpable hides its fds, and so is never found: the lookup fails
//!   closed.
//!
//! What escapes: a descendant that double-forks and reparents to launchd or
//! init leaves the tree, and its connections are refused. A process in the
//! tree can hand its socket to an outsider (`SCM_RIGHTS`); it could hand
//! over its placeholder just as well.

#![cfg_attr(
    target_os = "macos",
    expect(unsafe_code, reason = "libproc calls nothing wraps safely")
)]

use std::collections::{HashSet, VecDeque};

/// A connection to a server on `127.0.0.1`, as the server's `accept()` saw
/// it: the client's port and the server's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LoopbackConnection {
    pub client_port: u16,
    pub server_port: u16,
}

/// The most processes a tree walk visits.
pub const MAX_SUBTREE: usize = 4096;

/// `root` and its live descendants, `root` first, breadth first, at most
/// [`MAX_SUBTREE`].
pub fn subtree(root: u32) -> Vec<u32> {
    let mut order = Vec::new();
    walk(root, |pid| {
        order.push(pid);
        false
    });
    order
}

/// The process in `root`'s tree (itself included) that holds the client
/// end of `connection`, if any.
pub fn owner_in_subtree(root: u32, connection: LoopbackConnection) -> Option<u32> {
    let socket = Socket::find(connection)?;
    // Most connections come from the root or its first children: check
    // each pid as the walk reaches it instead of listing the tree first.
    walk(root, |pid| socket.held_by(pid))
}

/// Like [`owner_in_subtree`], but the owner must pass `confirm` and then,
/// asked again of the same socket, still hold it: whatever `confirm` read
/// about the owner (its start time, its ancestry) is about the process that
/// holds the socket now, not one whose pid was reused mid-check. The socket
/// is found once.
pub fn owner_in_subtree_confirmed(
    root: u32,
    connection: LoopbackConnection,
    confirm: &mut dyn FnMut(u32) -> bool,
) -> Option<u32> {
    let socket = Socket::find(connection)?;
    let owner = walk(root, |pid| socket.held_by(pid))?;
    (confirm(owner) && socket.held_by(owner)).then_some(owner)
}

/// Whether `pid` holds the client end of `connection`.
pub fn holds(pid: u32, connection: LoopbackConnection) -> bool {
    Socket::find(connection).is_some_and(|socket| socket.held_by(pid))
}

/// Visits `root` and its descendants breadth first until `stop` says so,
/// and returns the pid it stopped at. A pid listed twice (a race with
/// exits and forks) is visited once.
fn walk(root: u32, mut stop: impl FnMut(u32) -> bool) -> Option<u32> {
    let mut seen = HashSet::from([root]);
    let mut queue = VecDeque::from([root]);
    while let Some(pid) = queue.pop_front() {
        if stop(pid) {
            return Some(pid);
        }
        for child in children(pid) {
            if seen.len() >= MAX_SUBTREE {
                break;
            }
            if child != 0 && seen.insert(child) {
                queue.push_back(child);
            }
        }
    }
    None
}

/// `127.0.0.1` as `in_addr`'s bytes.
const LOOPBACK: [u8; 4] = [127, 0, 0, 1];
/// `::ffff:127.0.0.1`, a dual-stack socket's view of it.
const MAPPED_LOOPBACK: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1];

#[cfg(target_os = "macos")]
use macos::{Socket, children};

#[cfg(target_os = "linux")]
use linux::{Socket, children};

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
use other::{Socket, children};

#[cfg(target_os = "macos")]
mod macos {
    use std::ffi::{c_int, c_void};

    use super::{LOOPBACK, LoopbackConnection, MAPPED_LOOPBACK};

    /// `PROC_PIDFDSOCKETINFO`, which `libc` doesn't declare.
    const PROC_PIDFDSOCKETINFO: c_int = 3;
    /// `SOCKINFO_TCP`, `soi_kind` for a TCP socket.
    const SOCKINFO_TCP: i32 = 2;
    /// `INI_IPV4` and `INI_IPV6`, `insi_vflag`'s bits.
    const INI_IPV4: u8 = 1;
    const INI_IPV6: u8 = 2;

    /// `struct socket_fdinfo`'s size and the offsets of the fields read
    /// (`<sys/proc_info.h>`: `psi` follows the 24-byte `proc_fileinfo`,
    /// `soi_proto.pri_tcp.tcpsi_ini` starts at 264).
    const SOCKET_FDINFO_SIZE: usize = 792;
    const SOI_FAMILY: usize = 184;
    const SOI_KIND: usize = 256;
    const INSI_FPORT: usize = 264;
    const INSI_LPORT: usize = 268;
    const INSI_VFLAG: usize = 288;
    const INSI_FADDR: usize = 296;
    const INSI_FADDR4: usize = 308;
    const INSI_LADDR: usize = 312;
    const INSI_LADDR4: usize = 324;

    /// The connection to look for; macOS reads each process's sockets.
    pub(super) struct Socket(LoopbackConnection);

    impl Socket {
        pub(super) fn find(connection: LoopbackConnection) -> Option<Self> {
            Some(Self(connection))
        }

        pub(super) fn held_by(&self, pid: u32) -> bool {
            let Ok(pid) = c_int::try_from(pid) else {
                return false;
            };
            fds(pid)
                .into_iter()
                .filter(|fd| i64::from(fd.proc_fdtype) == i64::from(libc::PROX_FDTYPE_SOCKET))
                .filter_map(|fd| socket_info(pid, fd.proc_fd))
                .any(|info| info.is(self.0))
        }
    }

    /// `pid`'s live children.
    pub(super) fn children(pid: u32) -> Vec<u32> {
        let Ok(pid) = c_int::try_from(pid) else {
            return Vec::new();
        };
        let mut capacity = 64usize;
        loop {
            let mut buffer = vec![0 as c_int; capacity];
            let Ok(bytes) = c_int::try_from(capacity * size_of::<c_int>()) else {
                return Vec::new();
            };
            // SAFETY: `buffer` is writable for `bytes` bytes of pids; the
            // call writes at most that many and returns how many pids.
            let count = unsafe {
                libc::proc_listchildpids(pid, buffer.as_mut_ptr().cast::<c_void>(), bytes)
            };
            let Ok(count) = usize::try_from(count) else {
                return Vec::new();
            };
            if count < capacity || capacity >= super::MAX_SUBTREE {
                buffer.truncate(count.min(capacity));
                return buffer
                    .into_iter()
                    .filter_map(|child| u32::try_from(child).ok())
                    .collect();
            }
            capacity *= 4;
        }
    }

    /// `pid`'s open files, by number and kind.
    fn fds(pid: c_int) -> Vec<libc::proc_fdinfo> {
        // SAFETY: a null buffer of size 0 asks only for the size needed;
        // the call writes nothing.
        let needed =
            unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
        let Ok(needed) = usize::try_from(needed) else {
            return Vec::new();
        };
        let entry = size_of::<libc::proc_fdinfo>();
        // Room for files opened between the two calls.
        let capacity = needed / entry + 32;
        let blank = libc::proc_fdinfo {
            proc_fd: 0,
            proc_fdtype: 0,
        };
        let mut buffer = vec![blank; capacity];
        let Ok(bytes) = c_int::try_from(capacity * entry) else {
            return Vec::new();
        };
        // SAFETY: `buffer` is writable for `bytes` bytes of `proc_fdinfo`,
        // the flavor's struct; the call writes at most that and returns the
        // bytes written.
        let written = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDLISTFDS,
                0,
                buffer.as_mut_ptr().cast::<c_void>(),
                bytes,
            )
        };
        let Ok(written) = usize::try_from(written) else {
            return Vec::new();
        };
        buffer.truncate(written / entry);
        buffer
    }

    /// A `socket_fdinfo`, as bytes.
    struct SocketInfo([u8; SOCKET_FDINFO_SIZE]);

    impl SocketInfo {
        fn i32_at(&self, at: usize) -> i32 {
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(&self.0[at..at + 4]);
            i32::from_ne_bytes(bytes)
        }

        /// A port, which the kernel keeps in network order in an `int`.
        fn port_at(&self, at: usize) -> u16 {
            let [a, b, ..] = self.0[at..at + 4] else {
                return 0;
            };
            u16::from_be_bytes([a, b])
        }

        fn address_is_loopback(&self, v4: usize, v6: usize) -> bool {
            let vflag = self.0[INSI_VFLAG];
            (vflag & INI_IPV4 != 0 && self.0[v4..v4 + 4] == LOOPBACK)
                || (vflag & INI_IPV6 != 0 && self.0[v6..v6 + 16] == MAPPED_LOOPBACK)
        }

        fn is(&self, connection: LoopbackConnection) -> bool {
            let family = self.i32_at(SOI_FAMILY);
            (family == libc::AF_INET || family == libc::AF_INET6)
                && self.i32_at(SOI_KIND) == SOCKINFO_TCP
                && self.port_at(INSI_LPORT) == connection.client_port
                && self.port_at(INSI_FPORT) == connection.server_port
                && self.address_is_loopback(INSI_LADDR4, INSI_LADDR)
                && self.address_is_loopback(INSI_FADDR4, INSI_FADDR)
        }
    }

    fn socket_info(pid: c_int, fd: i32) -> Option<SocketInfo> {
        let mut buffer = [0u8; SOCKET_FDINFO_SIZE];
        let size = c_int::try_from(SOCKET_FDINFO_SIZE).ok()?;
        // SAFETY: `buffer` is writable for `size` bytes, exactly a
        // `socket_fdinfo`; the call writes at most that and returns the
        // bytes written.
        let written = unsafe {
            libc::proc_pidfdinfo(
                pid,
                fd,
                PROC_PIDFDSOCKETINFO,
                buffer.as_mut_ptr().cast::<c_void>(),
                size,
            )
        };
        (usize::try_from(written).ok() == Some(SOCKET_FDINFO_SIZE)).then_some(SocketInfo(buffer))
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::fs;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use rustix::net::netlink::{self, SocketAddrNetlink};
    use rustix::net::sockopt::{Timeout, set_socket_timeout};
    use rustix::net::{AddressFamily, RecvFlags, SendFlags, SocketFlags, SocketType};

    use super::{LOOPBACK, LoopbackConnection, MAPPED_LOOPBACK};

    /// Set once netlink has missed a socket the tables then found: a
    /// kernel without `INET_DIAG` answers every lookup with `ENOENT`.
    static NO_NETLINK: AtomicBool = AtomicBool::new(false);

    /// The connection's socket, by inode.
    pub(super) struct Socket {
        link: String,
    }

    impl Socket {
        pub(super) fn find(connection: LoopbackConnection) -> Option<Self> {
            let of = |inode: u64| Self {
                link: format!("socket:[{inode}]"),
            };
            if !NO_NETLINK.load(Ordering::Relaxed)
                && let Ok(Some(inode)) = by_netlink(connection)
            {
                return Some(of(inode));
            }
            let inode = ["/proc/net/tcp", "/proc/net/tcp6"]
                .into_iter()
                .filter_map(|table| fs::read_to_string(table).ok())
                .find_map(|text| inode_in(&text, connection))?;
            NO_NETLINK.store(true, Ordering::Relaxed);
            Some(of(inode))
        }

        pub(super) fn held_by(&self, pid: u32) -> bool {
            let Ok(fds) = fs::read_dir(format!("/proc/{pid}/fd")) else {
                return false;
            };
            fds.flatten().any(|fd| {
                fs::read_link(fd.path())
                    .is_ok_and(|target| target.as_os_str() == self.link.as_str())
            })
        }
    }

    /// `SOCK_DIAG_BY_FAMILY`, `NLM_F_REQUEST` and `NLMSG_ERROR` (`<linux/netlink.h>`,
    /// `<linux/sock_diag.h>`).
    const SOCK_DIAG_BY_FAMILY: u16 = 20;
    const NLM_F_REQUEST: u16 = 1;
    const NLMSG_ERROR: u16 = 2;
    const AF_INET: u8 = 2;
    const AF_INET6: u8 = 10;
    const IPPROTO_TCP: u8 = 6;
    const ENOENT: i32 = 2;
    /// A request: `nlmsghdr` (16 bytes) and `inet_diag_req_v2` (56), whose
    /// `inet_diag_sockid` starts at 24.
    const REQUEST: usize = 72;
    /// In a reply's `inet_diag_msg` (after the 16-byte header): the ports at
    /// 20 and 22, the inode at 84.
    const REPLY_SPORT: usize = 20;
    const REPLY_DPORT: usize = 22;
    const REPLY_INODE: usize = 84;

    fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
        Some(u16::from_ne_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
    }

    fn port_at(bytes: &[u8], at: usize) -> Option<u16> {
        Some(u16::from_be_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
    }

    fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
        Some(u32::from_ne_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
    }

    /// The client socket's inode by one exact `NETLINK_SOCK_DIAG` lookup,
    /// as IPv4 then as a dual-stack socket's v4-mapped address. `Ok(None)`
    /// is `ENOENT`: no such socket, or no `INET_DIAG` in this kernel.
    fn by_netlink(connection: LoopbackConnection) -> rustix::io::Result<Option<u64>> {
        let fd = rustix::net::socket_with(
            AddressFamily::NETLINK,
            SocketType::DGRAM,
            SocketFlags::CLOEXEC,
            Some(netlink::SOCK_DIAG),
        )?;
        set_socket_timeout(&fd, Timeout::Recv, Some(Duration::from_millis(500)))?;
        for (family, address) in [(AF_INET, &LOOPBACK[..]), (AF_INET6, &MAPPED_LOOPBACK[..])] {
            let mut request = [0u8; REQUEST];
            request[0..4].copy_from_slice(&(REQUEST as u32).to_ne_bytes());
            request[4..6].copy_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
            request[6..8].copy_from_slice(&NLM_F_REQUEST.to_ne_bytes());
            request[8..12].copy_from_slice(&1u32.to_ne_bytes());
            request[16] = family;
            request[17] = IPPROTO_TCP;
            // Every state.
            request[20..24].copy_from_slice(&u32::MAX.to_ne_bytes());
            // The socket's own end, then its peer, then no interface or cookie.
            request[24..26].copy_from_slice(&connection.client_port.to_be_bytes());
            request[26..28].copy_from_slice(&connection.server_port.to_be_bytes());
            request[28..28 + address.len()].copy_from_slice(address);
            request[44..44 + address.len()].copy_from_slice(address);
            request[64..72].copy_from_slice(&[0xff; 8]);
            rustix::net::sendto(
                &fd,
                &request,
                SendFlags::empty(),
                &SocketAddrNetlink::new(0, 0),
            )?;
            let mut reply = [0u8; 4096];
            let (length, _) = rustix::net::recv(&fd, &mut reply[..], RecvFlags::empty())?;
            let reply = &reply[..length.min(reply.len())];
            match u16_at(reply, 4) {
                Some(SOCK_DIAG_BY_FAMILY)
                    if port_at(reply, REPLY_SPORT) == Some(connection.client_port)
                        && port_at(reply, REPLY_DPORT) == Some(connection.server_port) =>
                {
                    return Ok(u32_at(reply, REPLY_INODE)
                        .filter(|i| *i != 0)
                        .map(u64::from));
                }
                Some(NLMSG_ERROR) => {
                    let errno = u32_at(reply, 16).map_or(0, |e| (e as i32).wrapping_neg());
                    if errno != ENOENT {
                        return Err(rustix::io::Errno::from_raw_os_error(errno));
                    }
                }
                _ => return Err(rustix::io::Errno::PROTO),
            }
        }
        Ok(None)
    }

    /// A `/proc/net/tcp{,6}` address, `0100007F:1F90`: the address as the
    /// kernel's native-order words, then the port.
    fn address(text: &str) -> Option<(Vec<u8>, u16)> {
        let (address, port) = text.split_once(':')?;
        if address.is_empty() || address.len() % 8 != 0 {
            return None;
        }
        let mut bytes = Vec::with_capacity(address.len() / 2);
        for word in address.as_bytes().chunks(8) {
            let word = std::str::from_utf8(word).ok()?;
            bytes.extend(u32::from_str_radix(word, 16).ok()?.to_ne_bytes());
        }
        Some((bytes, u16::from_str_radix(port, 16).ok()?))
    }

    fn is_loopback(bytes: &[u8]) -> bool {
        bytes == LOOPBACK || bytes == MAPPED_LOOPBACK
    }

    /// The inode of the socket whose local end is `127.0.0.1:client_port`
    /// and remote end `127.0.0.1:server_port`, from a `/proc/net/tcp` table.
    pub(super) fn inode_in(table: &str, connection: LoopbackConnection) -> Option<u64> {
        table.lines().skip(1).find_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let (local, local_port) = address(fields.get(1)?)?;
            let (remote, remote_port) = address(fields.get(2)?)?;
            let inode: u64 = fields.get(9)?.parse().ok()?;
            (inode != 0
                && local_port == connection.client_port
                && remote_port == connection.server_port
                && is_loopback(&local)
                && is_loopback(&remote))
            .then_some(inode)
        })
    }

    /// `pid`'s live children, from every thread's `children` list.
    pub(super) fn children(pid: u32) -> Vec<u32> {
        let Ok(tasks) = fs::read_dir(format!("/proc/{pid}/task")) else {
            return Vec::new();
        };
        let mut children = Vec::new();
        let mut listed = false;
        for task in tasks.flatten() {
            if let Ok(text) = fs::read_to_string(task.path().join("children")) {
                listed = true;
                children.extend(
                    text.split_whitespace()
                        .filter_map(|c| c.parse::<u32>().ok()),
                );
            }
        }
        if listed {
            children
        } else {
            // A kernel without `CONFIG_PROC_CHILDREN`: every process's parent.
            scan_children(pid)
        }
    }

    fn scan_children(parent: u32) -> Vec<u32> {
        let Ok(entries) = fs::read_dir("/proc") else {
            return Vec::new();
        };
        entries
            .flatten()
            .filter_map(|entry| entry.file_name().to_str()?.parse::<u32>().ok())
            .filter(|pid| {
                fs::read_to_string(format!("/proc/{pid}/stat"))
                    .ok()
                    .and_then(|stat| {
                        // The name may hold spaces and parentheses.
                        let rest = &stat[stat.rfind(')')? + 1..];
                        rest.split_whitespace().nth(1)?.parse::<u32>().ok()
                    })
                    == Some(parent)
            })
            .collect()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn a_tcp_table_names_the_client_end_by_inode() {
            let le = cfg!(target_endian = "little");
            let local = if le { "0100007F" } else { "7F000001" };
            let table = format!(
                "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
                 0: {local}:1F90 {local}:C350 01 00000000:00000000 00:00000000 00000000  1000        0 111 1 0\n\
                 1: {local}:C350 {local}:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 222 1 0\n\
                 2: {local}:C351 {local}:1F90 06 00000000:00000000 00:00000000 00000000  1000        0 0 1 0\n"
            );
            let connection = |client_port, server_port| LoopbackConnection {
                client_port,
                server_port,
            };
            assert_eq!(inode_in(&table, connection(50000, 8080)), Some(222));
            assert_eq!(inode_in(&table, connection(8080, 50000)), Some(111));
            // TIME_WAIT has no inode, and no owner.
            assert_eq!(inode_in(&table, connection(50001, 8080)), None);
        }

        /// Netlink and the table name the same socket, and netlink is fast.
        #[test]
        fn netlink_finds_what_the_table_finds() {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let server_port = listener.local_addr().unwrap().port();
            let _client = std::net::TcpStream::connect(("127.0.0.1", server_port)).unwrap();
            let (_server, peer) = listener.accept().unwrap();
            let connection = LoopbackConnection {
                client_port: peer.port(),
                server_port,
            };
            let table = fs::read_to_string("/proc/net/tcp").unwrap();
            let start = std::time::Instant::now();
            let found = by_netlink(connection);
            eprintln!("netlink lookup: {:?}", start.elapsed());
            let Ok(Some(found)) = found else {
                // A kernel without INET_DIAG, or a sandbox: the tables answer.
                // One with it (built in or loaded by this request) must find it.
                assert!(
                    !std::path::Path::new("/sys/module/inet_diag").exists(),
                    "INET_DIAG is here but netlink didn't find the socket: {found:?}"
                );
                eprintln!("netlink can't look sockets up here: {found:?}");
                return;
            };
            assert_eq!(Some(found), inode_in(&table, connection));
            let none = LoopbackConnection {
                client_port: peer.port(),
                server_port: server_port.wrapping_add(1),
            };
            assert_eq!(by_netlink(none).unwrap(), None);
        }
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod other {
    use super::LoopbackConnection;

    /// No lookup on this platform: nothing is found, so the broker refuses.
    pub(super) struct Socket;

    impl Socket {
        pub(super) fn find(_connection: LoopbackConnection) -> Option<Self> {
            None
        }

        pub(super) fn held_by(&self, _pid: u32) -> bool {
            false
        }
    }

    pub(super) fn children(_pid: u32) -> Vec<u32> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    use super::*;

    const CHILD: &str = "DEADBOLT_OS_NET_CONNECT";

    fn listen() -> (TcpListener, u16) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        (listener, port)
    }

    /// `accept`, giving up after 30 seconds.
    fn accept(listener: &TcpListener) -> (TcpStream, SocketAddr) {
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            match listener.accept() {
                Ok(accepted) => return accepted,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "nobody connected");
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => panic!("{e}"),
            }
        }
    }

    #[test]
    fn this_process_holds_its_own_connection() {
        let (listener, server_port) = listen();
        let _client = TcpStream::connect(("127.0.0.1", server_port)).unwrap();
        let (_server, peer) = accept(&listener);
        let connection = LoopbackConnection {
            client_port: peer.port(),
            server_port,
        };
        let me = std::process::id();
        assert!(holds(me, connection));
        assert_eq!(owner_in_subtree(me, connection), Some(me));
        assert_eq!(subtree(me).first(), Some(&me));
        // A connection nobody holds.
        let other = LoopbackConnection {
            client_port: peer.port(),
            server_port: server_port.wrapping_add(1),
        };
        assert_eq!(owner_in_subtree(me, other), None);

        let mut times: Vec<Duration> = (0..100)
            .map(|_| {
                let start = Instant::now();
                assert_eq!(owner_in_subtree(me, connection), Some(me));
                start.elapsed()
            })
            .collect();
        times.sort();
        eprintln!("owner_in_subtree: p50 {:?}, p95 {:?}", times[49], times[94]);
        assert!(times[94] < Duration::from_millis(50), "{:?}", times[94]);
    }

    /// Run by [`a_process_is_found_only_in_its_own_tree`]: connects, and
    /// holds the connection until its stdin closes.
    #[test]
    fn connecting_child() {
        let Some(port) = std::env::var_os(CHILD) else {
            return;
        };
        let port: u16 = port.to_str().unwrap().parse().unwrap();
        let stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let mut rest = Vec::new();
        std::io::stdin().read_to_end(&mut rest).unwrap();
        drop(stream);
    }

    #[test]
    fn a_process_is_found_only_in_its_own_tree() {
        let (listener, server_port) = listen();
        // An unrelated process: the authorized root in this test.
        let mut outsider = Command::new("sleep").arg("30").spawn().unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "net::tests::connecting_child", "--nocapture"])
            .env(CHILD, server_port.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        let (_server, peer) = accept(&listener);
        let connection = LoopbackConnection {
            client_port: peer.port(),
            server_port,
        };
        let me = std::process::id();
        let child_pid = child.id();
        assert_eq!(owner_in_subtree(outsider.id(), connection), None);
        assert!(!holds(me, connection));
        assert!(!holds(outsider.id(), connection));
        assert_eq!(owner_in_subtree(child_pid, connection), Some(child_pid));
        // It is this process's descendant, so this tree finds it too.
        assert_eq!(owner_in_subtree(me, connection), Some(child_pid));
        // The owner is handed to the check, and refused if it fails it.
        let mut asked = Vec::new();
        let mut confirm = |pid| {
            asked.push(pid);
            true
        };
        assert_eq!(
            owner_in_subtree_confirmed(me, connection, &mut confirm),
            Some(child_pid)
        );
        assert_eq!(asked, [child_pid]);
        assert_eq!(
            owner_in_subtree_confirmed(me, connection, &mut |_| false),
            None
        );
        assert!(subtree(me).contains(&child_pid));
        assert!(!subtree(outsider.id()).contains(&child_pid));

        drop(child.stdin.take());
        assert!(child.wait().unwrap().success());
        outsider.kill().unwrap();
        outsider.wait().unwrap();
    }
}
