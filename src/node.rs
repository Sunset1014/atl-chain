//! 节点：TCP 监听 + 每连接一线程 + 握手/同步/广播 + 可选挖矿。
//! 锁的约定：持锁时只做内存操作和 `write_all`（对端已设写超时），不做 accept/connect。
use crate::chain::{Chain, Mempool};
use crate::codec::hex;
use crate::net::{self, Msg};
use crate::store;
use std::io::{self, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// peers: (写端, 是否本端发起, 连接 id)
struct St {
    c: Chain,
    m: Mempool,
    peers: Vec<(TcpStream, bool, u64)>,
    dir: String,
    port: u16,
    rid: u64,
}
type Shared = Arc<Mutex<St>>;

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn log(s: &str) {
    let mut o = io::stdout().lock();
    let _ = writeln!(o, "[node] {s}");
    let _ = o.flush();  // qa 的 e2e 会实时解析 stdout
}

fn lock(t: &Mutex<St>) -> MutexGuard<'_, St> { t.lock().unwrap_or_else(|e| e.into_inner()) }

fn h(t: &Mutex<St>) -> u64 { lock(t).c.height() }

/// 发给全部 peer（`skip` 为发送者连接 id；本端挖矿用 0，因为 id 从 1 起）。
fn out(t: &Mutex<St>, skip: u64, m: &Msg) {
    let mut g = lock(t);
    for (s, _, id) in g.peers.iter_mut() {
        if *id != skip { let _ = net::send(s, m); }
    }
}

fn out_one(t: &Mutex<St>, id: u64, m: &Msg) {
    let mut g = lock(t);
    if let Some((s, _, _)) = g.peers.iter_mut().find(|p| p.2 == id) { let _ = net::send(s, m); }
}

fn on_msg(sh: &Shared, id: u64, m: Msg) {
    match m {
        Msg::Version { height, port: _ } => {
            let hh = h(sh);
            if height > hh { out_one(sh, id, &Msg::GetBlocks { from: hh + 1 }); }
        }
        Msg::GetBlocks { from } => {
            let bs = {
                let g = lock(sh);
                if from > g.c.height() { Vec::new() } else {
                    g.c.blocks[from as usize..].iter().take(64).cloned().collect()
                }
            };
            out_one(sh, id, &Msg::Blocks(bs));
        }
        Msg::Blocks(bs) => {
            let mut last = 0;
            for b in bs {
                if let Err(e) = { let mut g = lock(sh); g.c.add_block(&b) } {
                    log(&format!("reject block: {e}"));
                    continue;
                }
                let hash = hex(&b.hash());
                let (hh, sv) = { let g = lock(sh); (g.c.height(), store::save(&g.dir, &g.c)) };
                if let Err(e) = sv { log(&format!("save error: {e}")); }
                log(&format!("block {hh} {hash}"));
                out(sh, id, &Msg::Blocks(vec![b]));
                last = hh;
            }
            if last > 0 { out_one(sh, id, &Msg::GetBlocks { from: last + 1 }); }  // 仍落后就继续拉
        }
        Msg::Tx(t) => {
            let ok = { let mut g = lock(sh); let St { c, m, .. } = &mut *g; m.add(c, t.clone()).is_ok() };
            if ok { out(sh, id, &Msg::Tx(t)); }
        }
        Msg::Ping => out_one(sh, id, &Msg::Pong),
        Msg::Pong => {}
    }
}

/// 一条连接的全生命周期：发 Version -> (出站去重) -> 注册 -> 收 Version -> 读循环 -> 注销。
fn serve(sh: Shared, sock: TcpStream, init: bool) {
    let mut s = sock;
    let w = match s.try_clone() { Ok(w) => w, Err(_) => return };
    let _ = s.set_write_timeout(Some(Duration::from_secs(5)));
    let (port, hh) = { let g = lock(&sh); (g.port, g.c.height()) };
    if net::send(&mut s, &Msg::Version { height: hh, port }).is_err() { return }
    if init {
        // 同一地址已有出站连接就走这条，丢掉的入站/重复连接不用
        let a = s.peer_addr().ok().map(|x| x.to_string());
        let dup = { let g = lock(&sh); g.peers.iter().any(|p| p.1 && p.0.peer_addr().ok().map(|x| x.to_string()) == a) };
        if dup { return }
    }
    let id = { let mut g = lock(&sh); let id = g.rid; g.rid += 1; g.peers.push((w, init, id)); id };
    match net::recv(&mut s) {
        Ok(Some(Msg::Version { height, .. })) => {
            let hh = h(&sh);
            if height > hh { out_one(&sh, id, &Msg::GetBlocks { from: hh + 1 }); }
        }
        Ok(Some(_)) => log("peer: first message not Version"),
        _ => {}
    }
    loop {
        match net::recv(&mut s) {
            Ok(Some(m)) => on_msg(&sh, id, m),
            Ok(None) => break,
            Err(e) => { log(&format!("peer error: {e}")); break }
        }
    }
    let mut g = lock(&sh);
    if let Some(i) = g.peers.iter().position(|p| p.2 == id) { g.peers.remove(i); }
}

fn dial(addr: &str) -> io::Result<TcpStream> {
    use std::net::ToSocketAddrs;
    let mut last = io::Error::new(io::ErrorKind::AddrNotAvailable, "no address");
    for a in addr.to_socket_addrs()? {
        match TcpStream::connect_timeout(&a, Duration::from_secs(2)) { Ok(s) => return Ok(s), Err(e) => last = e }
    }
    Err(last)
}

/// 出站连接：失败按 200ms 起、每次 x2、封顶 2s 退避重试，永不退出进程。
fn connect_loop(sh: Shared, addr: String) {
    let mut back = 200;
    loop {
        let dup = {
            let g = lock(&sh);
            g.peers.iter().any(|p| p.1 && p.0.peer_addr().ok().map(|x| x.to_string()).as_deref() == Some(addr.as_str()))
        };
        if !dup {
            match dial(&addr) {
                Ok(s) => { log(&format!("peer {addr} up")); back = 200; serve(sh.clone(), s, true); log(&format!("peer {addr} down")); }
                Err(e) => log(&format!("connect {addr} failed: {e}")),
            }
        }
        thread::sleep(Duration::from_millis(back));
        back = (back * 2).min(2000);
    }
}

/// 挖矿循环。build+mine 在锁内完成（简化；默认难度是微秒级）。
fn mine_loop(sh: Shared, addr: [u8; 20], interval: u64) {
    loop {
        thread::sleep(Duration::from_secs(if interval == 0 { 1 } else { interval }));
        let b = {
            let mut g = lock(&sh);
            let St { c, m, .. } = &mut *g;
            m.clean(c);
            let txs = m.select(c);
            let mut b = c.build_block(&addr, &txs, now());
            c.mine_block(&mut b);
            b
        };
        if let Err(e) = { let mut g = lock(&sh); g.c.add_block(&b) } {
            log(&format!("mine reject: {e}"));
            continue;
        }
        let ids: Vec<[u8; 32]> = b.txs.iter().skip(1).map(|t| t.id()).collect();
        let (hh, sv) = {
            let mut g = lock(&sh);
            g.m.remove(&ids);
            let hh = g.c.height();
            (hh, store::save(&g.dir, &g.c))
        };
        if let Err(e) = sv { log(&format!("save error: {e}")); }
        log(&format!("mined {hh} {}", hex(&b.hash())));
        out(&sh, 0, &Msg::Blocks(vec![b]));
    }
}

pub fn run(dir: &str, port: u16, connect: &[String], mine: Option<[u8; 20]>, interval: u64) -> io::Result<()> {
    let c = store::load_or_init(dir)?;
    let l = TcpListener::bind(("127.0.0.1", port))?;
    let real = l.local_addr()?.port();
    log(&format!("listening 127.0.0.1:{real}"));
    let sh: Shared = Arc::new(Mutex::new(St { c, m: Mempool::new(), peers: Vec::new(), dir: dir.to_string(), port: real, rid: 1 }));
    for a in connect {
        let (s, a) = (sh.clone(), a.clone());
        thread::spawn(move || connect_loop(s, a));
    }
    if let Some(addr) = mine {
        let s = sh.clone();
        thread::spawn(move || mine_loop(s, addr, interval));
    }
    for sock in l.incoming() {
        match sock {
            Ok(s) => { let s2 = sh.clone(); thread::spawn(move || serve(s2, s, false)); }
            Err(e) => log(&format!("accept error: {e}")),
        }
    }
    Ok(())
}
