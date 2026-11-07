//! CLI 入口（SPEC §9）：init / info / balance / newkey / mine / send / node。
use blockchain::chain::{Chain, Tx, COIN};
use blockchain::codec::{hex, unhex};
use blockchain::net::{self, Msg};
use blockchain::store;
use blockchain::wallet::{self, Key};
use blockchain::{chain, node};
use std::io::Write;
use std::net::TcpStream;
use std::process::exit;
use std::time::{SystemTime, UNIX_EPOCH};

fn die(m: &str) -> ! {
    let _ = writeln!(std::io::stderr(), "error: {m}");
    exit(1)
}

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// 从 `--flag value` 序列取值；同名多次出现时全部收集。
fn args(argv: &[String], flag: &str) -> Vec<String> {
    let mut v = Vec::new();
    let mut i = 0;
    while i + 1 < argv.len() {
        if argv[i] == flag {
            v.push(argv[i + 1].clone());
            i += 2;
        } else {
            i += 1;
        }
    }
    v
}

fn one(argv: &[String], flag: &str) -> Option<String> { args(argv, flag).into_iter().next() }

fn req(argv: &[String], flag: &str) -> String {
    one(argv, flag).unwrap_or_else(|| die(&format!("missing {flag}")))
}

fn hash20(s: &str) -> [u8; 20] {
    unhex(s).and_then(|v| v.try_into().ok()).unwrap_or_else(|| die(&format!("bad address: {s}")))
}

fn u64arg(argv: &[String], flag: &str, default: u64) -> u64 {
    match one(argv, flag) {
        None => default,
        Some(s) => s.parse().unwrap_or_else(|_| die(&format!("bad {flag}: {s}"))),
    }
}

/// 严格参数校验（SPEC §9.1：参数解析失败一律 `error: ...` + exit 1）。
/// 未知 `--flag`、悬空 `--flag`（缺值）、多余的位置参数都拒绝。
fn check(argv: &[String], known: &[&str]) {
    let mut i = 0;
    while i < argv.len() {
        let t = &argv[i];
        if !t.starts_with("--") {
            die(&format!("unexpected argument {t}"));
        }
        if !known.contains(&t.as_str()) {
            die(&format!("unknown flag {t}"));
        }
        if i + 1 >= argv.len() {
            die(&format!("missing value for {t}"));
        }
        i += 2;
    }
}

const MP: &str = "mempool.bin";

/// 内存池落盘（侧车文件，与 chain 的 blocks.bin 分离）。
fn mp_load(dir: &str) -> Vec<Tx> {
    let p = std::path::Path::new(dir).join(MP);
    let b = match std::fs::read(p) { Ok(b) => b, Err(_) => return Vec::new() };
    let mut r = blockchain::codec::Rd::new(&b);
    let mut v = Vec::new();
    while let Some(raw) = r.bytes() {
        match Tx::dec(&mut blockchain::codec::Rd::new(raw)) {
            Some(t) => v.push(t),
            None => break,
        }
    }
    v
}

fn mp_save(dir: &str, txs: &[Tx]) {
    let p = std::path::Path::new(dir).join(MP);
    let mut b = Vec::new();
    for t in txs {
        blockchain::codec::put_bytes(&mut b, &t.enc());
    }
    let _ = std::fs::write(p, b);
}

fn load(dir: &str) -> Chain {
    store::load(dir).unwrap_or_else(|e| die(&format!("no chain in {dir} ({e})")))
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let cmd = argv.first().map(|s| s.as_str()).unwrap_or("");
    let rest = if argv.is_empty() { &argv[..] } else { &argv[1..] };
    match cmd {
        "newkey" => {
            check(rest, &["--seed", "--index"]);
            let key = match one(rest, "--seed") {
                Some(s) => Key::from_seed(&unhex(&s).unwrap_or_else(|| die("bad --seed")), u64arg(rest, "--index", 0) as u32),
                None => Key::from_seed(&wallet::new_seed(), 0),
            };
            println!("sk {}", key.hex());
            println!("pk {}", hex(&key.pk));
            println!("addr {}", hex(&key.addr));
        }
        "init" => {
            check(rest, &["--dir"]);
            let dir = req(rest, "--dir");
            if store::exists(&dir) {
                die("already initialized");
            }
            let c = store::load_or_init(&dir).unwrap_or_else(|e| die(&e.to_string()));
            println!("init ok {}", hex(&c.tip()));
        }
        "info" => {
            check(rest, &["--dir"]);
            let c = load(&req(rest, "--dir"));
            println!("height {}", c.height());
            println!("tip {}", hex(&c.tip()));
            println!("bits {:08x}", c.blocks.last().map(|b| b.bits).unwrap_or(0));
            println!("utxos {}", c.utxo.len());
        }
        "balance" => {
            check(rest, &["--dir", "--addr"]);
            let dir = req(rest, "--dir");
            let a = hash20(&req(rest, "--addr"));
            let c = load(&dir);
            println!("balance {} {}", hex(&a), c.balance(&a));
        }
        "mine" => {
            check(rest, &["--dir", "--addr", "--tx"]);
            let dir = req(rest, "--dir");
            let addr = hash20(&req(rest, "--addr"));
            let mut c = load(&dir);
            let mut txs: Vec<Tx> = mp_load(&dir);
            for h in args(rest, "--tx") {
                let raw = unhex(&h).unwrap_or_else(|| die(&format!("bad --tx hex: {h}")));
                let t = Tx::dec(&mut blockchain::codec::Rd::new(&raw)).unwrap_or_else(|| die("bad --tx encoding"));
                txs.push(t);
            }
            let t = now().max(c.tip_time() + 1);
            let mut b = c.build_block(&addr, &txs, t);
            c.mine_block(&mut b);
            c.add_block(&b).unwrap_or_else(|e| die(&e));
            store::save(&dir, &c).unwrap_or_else(|e| die(&e.to_string()));
            // 已确认的交易移出内存池
            let done: Vec<[u8; 32]> = b.txs.iter().filter(|t| !t.is_coinbase()).map(|t| t.id()).collect();
            let left: Vec<Tx> = mp_load(&dir).into_iter().filter(|t| !done.contains(&t.id())).collect();
            mp_save(&dir, &left);
            println!("mined {} {}", c.height(), hex(&b.hash()));
        }
        "send" => {
            check(rest, &["--dir", "--key", "--to", "--amount", "--fee", "--peer"]);
            let dir = req(rest, "--dir");
            let key = Key::from_hex(&req(rest, "--key")).unwrap_or_else(|| die("bad --key"));
            let to = hash20(&req(rest, "--to"));
            let amount = u64arg(rest, "--amount", 0);
            let fee = u64arg(rest, "--fee", 0);
            let c = load(&dir);
            let t = now().max(c.tip_time() + 1);
            let tx = wallet::send(&c, &key, to, amount, fee, t).unwrap_or_else(|e| die(&e));
            if let Some(peer) = one(rest, "--peer") {
                let mut s = TcpStream::connect(&peer).unwrap_or_else(|e| die(&format!("connect {peer}: {e}")));
                net::send(&mut s, &Msg::Version { height: c.height(), port: 0 }).unwrap_or_else(|e| die(&e.to_string()));
                net::send(&mut s, &Msg::Tx(tx.clone())).unwrap_or_else(|e| die(&e.to_string()));
            }
            // 交易进本地内存池，等 mine/node 打包；send 只负责广播与返回 txid
            let mut m = mp_load(&dir);
            if !m.iter().any(|x| x.id() == tx.id()) { m.push(tx.clone()); }
            mp_save(&dir, &m);
            println!("{}", hex(&tx.id()));
        }
        "node" => {
            check(rest, &["--dir", "--port", "--connect", "--mine", "--interval"]);
            let dir = req(rest, "--dir");
            let port = u64arg(rest, "--port", 0) as u16;
            let connects = args(rest, "--connect");
            let mine = one(rest, "--mine").map(|s| hash20(&s));
            let interval = u64arg(rest, "--interval", 5).max(1);
            if let Err(e) = node::run(&dir, port, &connects, mine, interval) {
                die(&e.to_string());
            }
        }
        _ => {
            let _ = COIN;
            die("usage: blockchain {init|info|balance|newkey|mine|send|node} [flags]")
        }
    }
}

#[allow(dead_code)]
fn unused(_: chain::Mempool) {}
