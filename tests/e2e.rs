//! 端到端测试 —— SPEC §8（P2P 同步）与 §9.1（CLI 精确输出格式）。
//!
//! 全部通过真实二进制 `env!("CARGO_BIN_EXE_blockchain")` 运行，不依赖外网：
//! 节点只监听 127.0.0.1 的临时端口（`--port 0`），难度用 `ATL_BITS=207fffff` 临时降低。
//! 每条测试用独立临时目录，结束（含 panic）后由 guard 的 Drop 清理子进程与目录。

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// 测试用的极低难度（target 约 2^255，期望 2 次哈希即出块）。
const EASY_BITS: &str = "207fffff";
/// 单条测试最长的同步轮询时间。
const LIMIT: Duration = Duration::from_secs(20);

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_blockchain")
}

/// 独立临时目录：`atl-<测试名>-<进程 id>-<纳秒>`。
///
/// 放在 `CARGO_TARGET_TMPDIR`（默认为 `<repo>/target/tmp`）而不是 `std::env::temp_dir()`：
/// 本环境下工作区外的写入会被主机安全策略拒绝（`os error 5`，拒绝访问），
/// 而 `target/` 本来就是构建输出，既在可写范围内又不污染仓库源码树。
fn tmp_dir(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "atl-{}-{}-{}",
        name,
        std::process::id(),
        nanos
    ))
}

/// 运行 CLI 并收集输出（低难度：`ATL_BITS` 直接挂在子进程环境上）。
fn cli(args: &[&str]) -> Output {
    run_with(true, args)
}

/// 运行 CLI，不覆盖 `ATL_BITS`：子进程与测试进程都用 SPEC §4.5 的默认难度，
/// 这样测试进程里的 `store::load` 与 CLI 写出的创世块才对得上（创世哈希含 bits）。
fn cli_default_bits(args: &[&str]) -> Output {
    run_with(false, args)
}

/// `easy == true` 时给子进程注入 `ATL_BITS=207fffff`（极低难度，秒出块）。
fn run_with(easy: bool, args: &[&str]) -> Output {
    let mut c = Command::new(bin());
    c.args(args);
    if easy {
        c.env("ATL_BITS", EASY_BITS);
    }
    c.output()
        .unwrap_or_else(|e| panic!("无法启动 {} {:?}: {e}", bin(), args))
}

fn stdout_lines(o: &Output) -> Vec<String> {
    String::from_utf8_lossy(&o.stdout)
        .lines()
        .map(|s| s.trim_end_matches('\r').to_string())
        .collect()
}

fn stderr_text(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).trim().to_string()
}

/// 断言命令成功，失败时把 stdout/stderr 一起打出来。
fn ok(o: &Output, what: &str) -> Vec<String> {
    assert!(
        o.status.success(),
        "{what} 应以 exit 0 结束，实际 {:?}\nstdout:\n{}\nstderr:\n{}",
        o.status.code(),
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    stdout_lines(o)
}

/// 断言命令失败且退出码为 1。
fn failed(o: &Output, what: &str) -> String {
    assert_eq!(
        o.status.code(),
        Some(1),
        "{what} 应以 exit 1 结束\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    stderr_text(o)
}

fn is_hex(s: &str, n: usize) -> bool {
    s.len() == n && s.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

fn assert_hex(s: &str, n: usize, what: &str) {
    assert!(
        is_hex(s, n),
        "{what} 必须是 {n} 个小写十六进制字符，实际: {s:?}"
    );
}

/// `newkey` 的输出三元组。
struct KeyOut {
    sk: String,
    pk: String,
    addr: String,
}

fn newkey(extra: &[&str]) -> KeyOut {
    let mut args = vec!["newkey"];
    args.extend_from_slice(extra);
    let lines = ok(&cli(&args), "newkey");
    assert_eq!(lines.len(), 3, "newkey 必须恰好输出 3 行，实际: {lines:?}");
    let (sk, pk, addr) = (&lines[0], &lines[1], &lines[2]);
    assert!(sk.starts_with("sk "), "第 1 行必须以 \"sk \" 开头: {sk:?}");
    assert!(pk.starts_with("pk "), "第 2 行必须以 \"pk \" 开头: {pk:?}");
    assert!(
        addr.starts_with("addr "),
        "第 3 行必须以 \"addr \" 开头: {addr:?}"
    );
    let (sk, pk, addr) = (sk[3..].to_string(), pk[3..].to_string(), addr[5..].to_string());
    assert_hex(&sk, 64, "newkey 的 sk");
    assert_hex(&pk, 66, "newkey 的 pk");
    assert_hex(&addr, 40, "newkey 的 addr");
    KeyOut { sk, pk, addr }
}

// ---------------------------------------------------------------------------
// 子进程 guard：任何情况下（含 panic 展开）都要 kill，避免测试进程泄漏。
// ---------------------------------------------------------------------------

struct NodeProc {
    child: Child,
    log: Arc<Mutex<Vec<String>>>,
    closed: Arc<AtomicBool>,
    port: u16,
}

impl NodeProc {
    fn lines(&self) -> Vec<String> {
        self.log.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn dump(&self, name: &str) {
        let all = self.lines();
        eprintln!(
            "===== {name} stdout ({} 行, stdout 已关闭: {}) =====",
            all.len(),
            self.closed.load(Ordering::SeqCst)
        );
        for l in &all {
            eprintln!("{l}");
        }
        eprintln!("===== {name} end =====");
    }

    fn alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    /// 等待出现满足 `pred` 的日志行，最多 20 秒。
    fn wait_line(&self, what: &str, pred: impl Fn(&str) -> bool) -> String {
        let start = Instant::now();
        loop {
            if let Some(hit) = self.lines().into_iter().find(|l| pred(l)) {
                return hit;
            }
            if start.elapsed() > LIMIT {
                self.dump(what);
                panic!("等待节点出现 {what:?} 超时（{} 秒）", LIMIT.as_secs());
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for NodeProc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// 读取子进程的一路输出到共享缓冲，直到 EOF。
fn pump(stream: impl std::io::Read + Send + 'static, sink: Arc<Mutex<Vec<String>>>, closed: Arc<AtomicBool>) {
    thread::spawn(move || {
        for line in BufReader::new(stream).lines() {
            match line {
                Ok(l) => sink
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(l.trim_end_matches('\r').to_string()),
                Err(_) => break,
            }
        }
        closed.store(true, Ordering::SeqCst);
    });
}

/// 启动一个 node，等到 `[node] listening 127.0.0.1:<port>` 出现后返回。
fn start_node(dir: &Path, extra: &[&str]) -> NodeProc {
    let dir_s = dir.to_string_lossy().to_string();
    let mut cmd = Command::new(bin());
    cmd.arg("node")
        .args(["--dir", &dir_s, "--port", "0"])
        .env("ATL_BITS", EASY_BITS)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd.args(extra);
    let mut child = cmd
        .spawn()
        .unwrap_or_else(|e| panic!("无法启动 node: {e}"));

    let log = Arc::new(Mutex::new(Vec::new()));
    let errs = Arc::new(Mutex::new(Vec::new()));
    let closed = Arc::new(AtomicBool::new(false));
    let out = child.stdout.take().expect("node stdout 必须被 pipe");
    let err = child.stderr.take().expect("node stderr 必须被 pipe");
    pump(out, log.clone(), closed.clone());
    pump(err, errs.clone(), closed.clone());

    let mut node = NodeProc {
        child,
        log,
        closed,
        port: 0,
    };
    let line = node.wait_line("listening", |l| {
        l.starts_with("[node] listening 127.0.0.1:")
    });
    let port: u16 = line["[node] listening 127.0.0.1:".len()..]
        .trim()
        .parse()
        .unwrap_or_else(|e| panic!("无法从 {line:?} 解析端口: {e}"));
    assert!(port > 0, "listening 行必须报出真实端口，实际: {line:?}");
    node.port = port;
    node
}

fn init(dir: &Path) -> String {
    let d = dir.to_string_lossy().to_string();
    let lines = ok(&cli(&["init", "--dir", &d]), "init");
    assert_eq!(lines.len(), 1, "init 必须恰好输出 1 行，实际: {lines:?}");
    let tip = lines[0]
        .strip_prefix("init ok ")
        .unwrap_or_else(|| panic!("init 输出必须是 \"init ok <64hex>\"，实际: {:?}", lines[0]));
    assert_hex(tip, 64, "init 的创世块哈希");
    tip.to_string()
}

fn balance(dir: &Path, addr: &str) -> u64 {
    balance_with(true, dir, addr)
}

/// 与 `balance` 相同，但对子进程使用默认难度（链由 `cli_default_bits` 创建时使用）。
fn balance_default(dir: &Path, addr: &str) -> u64 {
    balance_with(false, dir, addr)
}

fn balance_with(easy: bool, dir: &Path, addr: &str) -> u64 {
    let d = dir.to_string_lossy().to_string();
    let lines = ok(&run_with(easy, &["balance", "--dir", &d, "--addr", addr]), "balance");
    assert_eq!(lines.len(), 1, "balance 必须恰好输出 1 行，实际: {lines:?}");
    let rest = lines[0]
        .strip_prefix("balance ")
        .unwrap_or_else(|| panic!("balance 输出必须以 \"balance \" 开头，实际: {:?}", lines[0]));
    let (got_addr, amount) = rest
        .split_once(' ')
        .unwrap_or_else(|| panic!("balance 输出必须是 \"balance <addr> <n>\"，实际: {:?}", lines[0]));
    assert_eq!(got_addr, addr, "balance 回显的地址必须与请求一致");
    amount
        .parse()
        .unwrap_or_else(|e| panic!("balance 的金额必须是十进制 satoshi，实际 {amount:?}: {e}"))
}

fn info(dir: &Path) -> (u64, String, String, u64) {
    let d = dir.to_string_lossy().to_string();
    let lines = ok(&cli(&["info", "--dir", &d]), "info");
    assert_eq!(lines.len(), 4, "info 必须恰好输出 4 行，实际: {lines:?}");
    let field = |i: usize, key: &str| -> String {
        lines[i]
            .strip_prefix(key)
            .unwrap_or_else(|| panic!("info 第 {} 行必须以 {key:?} 开头，实际: {:?}", i + 1, lines[i]))
            .to_string()
    };
    let height: u64 = field(0, "height ")
        .parse()
        .unwrap_or_else(|e| panic!("info 的 height 必须是 u64: {e}"));
    let tip = field(1, "tip ");
    assert_hex(&tip, 64, "info 的 tip");
    let bits = field(2, "bits ");
    assert_hex(&bits, 8, "info 的 bits");
    let utxos: u64 = field(3, "utxos ")
        .parse()
        .unwrap_or_else(|e| panic!("info 的 utxos 必须是整数: {e}"));
    (height, tip, bits, utxos)
}

// ---------------------------------------------------------------------------
// CLI 测试
// ---------------------------------------------------------------------------

#[test]
fn cli_newkey_prints_exactly_three_lines() {
    let dir = tmp_dir("newkey");
    let k = newkey(&[]);
    assert_ne!(k.sk, k.pk, "sk 与 pk 不能相同");
    // 同一进程内连续两次随机出不同密钥
    let k2 = newkey(&[]);
    assert_ne!(k.sk, k2.sk, "两次随机 newkey 必须产生不同私钥");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cli_newkey_seed_and_index_are_deterministic() {
    let seed = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    let a = newkey(&["--seed", seed, "--index", "0"]);
    let b = newkey(&["--seed", seed, "--index", "0"]);
    assert_eq!(a.sk, b.sk, "相同 --seed/--index 必须确定性输出相同 sk");
    assert_eq!(a.pk, b.pk, "相同 --seed/--index 必须确定性输出相同 pk");
    assert_eq!(a.addr, b.addr, "相同 --seed/--index 必须确定性输出相同 addr");

    let c = newkey(&["--seed", seed, "--index", "1"]);
    assert_ne!(a.sk, c.sk, "不同 --index 必须输出不同 sk");
    assert_ne!(a.addr, c.addr, "不同 --index 必须输出不同 addr");

    // 私钥 hex 应能被 send --key 直接接受（长度 64）
    assert_hex(&a.sk, 64, "seed 派生的 sk");
}

#[test]
fn cli_init_info_and_reinit_error() {
    let dir = tmp_dir("init");
    let tip = init(&dir);
    assert!(dir.is_dir(), "init 必须创建 --dir 指定的目录");
    assert!(
        dir.join("blocks.bin").is_file(),
        "init 必须在目录下生成 blocks.bin"
    );

    let (height, info_tip, bits, utxos) = info(&dir);
    assert_eq!(height, 0, "刚 init 的链高度必须是 0（只有创世块）");
    assert_eq!(info_tip, tip, "info 的 tip 必须等于 init 打印的创世哈希");
    assert_hex(&bits, 8, "info 的 bits");
    assert_eq!(utxos, 1, "创世块的 coinbase 应产生 1 个 utxo");

    // 重复 init：stderr 一行 `error: already initialized`，exit 1
    let d = dir.to_string_lossy().to_string();
    let err = failed(&cli(&["init", "--dir", &d]), "重复 init");
    assert_eq!(
        err, "error: already initialized",
        "重复 init 的 stderr 必须恰好是 \"error: already initialized\""
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cli_mine_updates_height_tip_and_balance() {
    let dir = tmp_dir("mine");
    init(&dir);
    let k = newkey(&["--seed", &"7a".repeat(32), "--index", "0"]);
    let d = dir.to_string_lossy().to_string();

    let lines = ok(&cli(&["mine", "--dir", &d, "--addr", &k.addr]), "mine");
    assert_eq!(lines.len(), 1, "mine 必须恰好输出 1 行，实际: {lines:?}");
    let rest = lines[0]
        .strip_prefix("mined ")
        .unwrap_or_else(|| panic!("mine 输出必须以 \"mined \" 开头，实际: {:?}", lines[0]));
    let (h, hash) = rest
        .split_once(' ')
        .unwrap_or_else(|| panic!("mine 输出必须是 \"mined <height> <hash>\"，实际: {:?}", lines[0]));
    assert_eq!(h, "1", "第一块挖出后的高度必须是 1，实际: {h:?}");
    assert_hex(hash, 64, "mine 的块哈希");

    let (height, tip, _bits, utxos) = info(&dir);
    assert_eq!(height, 1, "info 的高度必须随挖矿增长到 1");
    assert_eq!(tip, hash, "info 的 tip 必须等于 mine 打印的块哈希");
    assert_eq!(utxos, 2, "挖出一块后应有 2 个 utxo（创世 + 新块 coinbase）");
    assert_eq!(
        balance(&dir, &k.addr),
        50 * 100_000_000,
        "挖矿奖励必须是 subsidy(1) = 50 COIN = 5000000000 satoshi"
    );
    assert_eq!(
        balance(&dir, &"00".repeat(20)),
        50 * 100_000_000,
        "创世块的 coinbase 应付给全零地址"
    );

    // 第二块高度递增
    let lines = ok(&cli(&["mine", "--dir", &d, "--addr", &k.addr]), "第二次 mine");
    assert!(
        lines[0].starts_with("mined 2 "),
        "第二块的高度必须是 2，实际: {:?}",
        lines[0]
    );
    assert_eq!(balance(&dir, &k.addr), 100 * 100_000_000, "两次挖矿应累计 100 COIN");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cli_send_moves_funds_and_prints_txid() {
    let dir = tmp_dir("send");
    init(&dir);
    let a = newkey(&["--seed", &"11".repeat(32), "--index", "0"]);
    let b = newkey(&["--seed", &"22".repeat(32), "--index", "0"]);
    let d = dir.to_string_lossy().to_string();

    ok(&cli(&["mine", "--dir", &d, "--addr", &a.addr]), "给付款方挖块");

    let lines = ok(
        &cli(&[
            "send", "--dir", &d, "--key", &a.sk, "--to", &b.addr, "--amount", "100000000",
            "--fee", "1000",
        ]),
        "send",
    );
    assert_eq!(lines.len(), 1, "send 必须恰好输出 1 行（只有 txid），实际: {lines:?}");
    assert_hex(&lines[0], 64, "send 的 txid");

    // send 只入内存池，不挖矿：高度不变、收款方余额此刻仍为 0
    let (height, _tip, _bits, _utxos) = info(&dir);
    assert_eq!(height, 1, "send 不得自行挖矿，链高度必须仍为 1，实际 {height}");
    assert_eq!(balance(&dir, &b.addr), 0, "交易未确认前收款方余额必须仍为 0");
    assert_eq!(
        balance(&dir, &a.addr),
        50 * 100_000_000,
        "交易未确认前付款方余额不变"
    );

    // 挖一块把内存池里的交易打包上链
    let mined = ok(&cli(&["mine", "--dir", &d, "--addr", &a.addr]), "确认交易的 mine");
    assert!(
        mined[0].starts_with("mined 2 "),
        "确认块的高度必须是 2，实际: {:?}",
        mined[0]
    );
    let (height, _tip, _bits, utxos) = info(&dir);
    assert_eq!(height, 2, "挖出确认块后高度必须是 2，实际 {height}");
    assert!(utxos >= 3, "确认块应产生新 utxo，实际 utxos={utxos}");

    assert_eq!(balance(&dir, &b.addr), 100_000_000, "收款方必须收到 1 COIN = 100000000 satoshi");
    // 付款方 = 找零 + 确认块 coinbase + 手续费返还
    //        = (50 - 1 - 0.00001) + 50 + 0.00001 = 99 COIN
    assert_eq!(
        balance(&dir, &a.addr),
        100 * 100_000_000 - 100_000_000,
        "付款方余额 = 99 COIN（找零 + 新块奖励，手续费作为区块奖励的一部分回到矿工）"
    );

    // 交易确认后内存池侧车应被清空：继续挖块不得重复打包已确认交易而报错
    let again = ok(&cli(&["mine", "--dir", &d, "--addr", &a.addr]), "确认后继续 mine");
    assert!(
        again[0].starts_with("mined 3 "),
        "确认后应能继续挖块，实际: {:?}",
        again[0]
    );
    assert_eq!(
        balance(&dir, &a.addr),
        100 * 100_000_000 - 100_000_000 + 50 * 100_000_000,
        "第三块的 coinbase 应继续累计到付款方"
    );
    assert_eq!(balance(&dir, &b.addr), 100_000_000, "收款方余额不得被后续挖矿改变");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cli_send_rejects_insufficient_funds() {
    let dir = tmp_dir("send-poor");
    init(&dir);
    let a = newkey(&["--seed", &"33".repeat(32), "--index", "0"]);
    let b = newkey(&["--seed", &"44".repeat(32), "--index", "0"]);
    let d = dir.to_string_lossy().to_string();

    // 没有任何 coinbase：余额为 0
    let err = failed(
        &cli(&[
            "send", "--dir", &d, "--key", &a.sk, "--to", &b.addr, "--amount", "1",
        ]),
        "余额不足的 send",
    );
    assert!(
        err.starts_with("error: insufficient funds"),
        "余额不足时 stderr 必须以 \"error: insufficient funds\" 开头，实际: {err:?}"
    );
    assert!(
        err.contains("have 0, need 1"),
        "错误信息必须给出现有余额与所需金额，实际: {err:?}"
    );

    // 金额为正但为 0：应被参数校验拒绝，且没有任何输出到 stdout
    let o = cli(&["send", "--dir", &d, "--key", &a.sk, "--to", &b.addr, "--amount", "0"]);
    assert_eq!(o.status.code(), Some(1), "amount=0 必须以 exit 1 结束");
    assert!(
        String::from_utf8_lossy(&o.stdout).is_empty(),
        "失败的 send 不得往 stdout 写内容"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cli_mine_with_tx_flag_confirms_external_tx() {
    use blockchain::store;
    use blockchain::wallet::{self, Key};

    // 本测试在测试进程里用 `store::load` 读回链文件，而创世哈希包含 bits，
    // 所以全程必须用 SPEC §4.5 的默认难度（0x1f0fffff ≈ 4096 次哈希，足够快）。
    let dir = tmp_dir("mine-tx");
    let d = dir.to_string_lossy().to_string();
    let lines = ok(&cli_default_bits(&["init", "--dir", &d]), "init");
    assert_eq!(lines.len(), 1, "init 必须恰好输出 1 行，实际: {lines:?}");
    let a = newkey(&["--seed", &"55".repeat(32), "--index", "0"]);
    let b = newkey(&["--seed", &"66".repeat(32), "--index", "0"]);

    ok(
        &cli_default_bits(&["mine", "--dir", &d, "--addr", &a.addr]),
        "给付款方挖块",
    );

    // 用库 API 在链外构造交易，再把 `Tx::enc()` 的 hex 交给 `mine --tx`
    let chain = store::load(&d).expect("store::load 必须能读回刚写的链");
    assert_eq!(chain.height(), 1, "读回的链高度必须是 1");
    let key = Key::from_seed(&[0x55u8; 32], 0);
    assert_eq!(
        blockchain::codec::hex(&key.addr),
        a.addr,
        "库场景下由 seed 0x55 派生的地址必须与 CLI 的 --seed 一致"
    );
    let tx = wallet::send(&chain, &key, hex20(&b.addr), 2 * blockchain::chain::COIN, 0, chain.tip_time() + 1)
        .expect("造交易必须成功");
    let tx_hex = blockchain::codec::hex(&tx.enc());

    let lines = ok(
        &cli_default_bits(&["mine", "--dir", &d, "--addr", &a.addr, "--tx", &tx_hex]),
        "mine --tx",
    );
    assert!(
        lines[0].starts_with("mined 2 "),
        "带交易挖出的块高度必须是 2，实际: {:?}",
        lines[0]
    );
    assert_eq!(
        balance_default(&dir, &b.addr),
        2 * 100_000_000,
        "外部传入的交易必须被打包上链（收款方收到 2 COIN）"
    );

    // 再挖一次同一笔交易：输入已被花费 → 必须报错退出 1
    let err = failed(
        &cli_default_bits(&["mine", "--dir", &d, "--addr", &a.addr, "--tx", &tx_hex]),
        "重放已确认的交易",
    );
    assert!(
        err.starts_with("error: "),
        "重放已确认交易必须输出 \"error: ...\"，实际: {err:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

fn hex20(hex: &str) -> [u8; 20] {
    let mut out = [0u8; 20];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("地址必须是合法 hex");
    }
    out
}

#[test]
fn cli_reports_missing_chain_and_bad_args() {
    let dir = tmp_dir("missing");
    let d = dir.to_string_lossy().to_string();
    // 目录不存在（也不存在 blocks.bin）
    let err = failed(&cli(&["info", "--dir", &d]), "对不存在的链执行 info");
    assert!(
        err.starts_with(&format!("error: no chain in {d}")),
        "缺少链时 stderr 必须以 \"error: no chain in <dir>\" 开头，实际: {err:?}"
    );

    // 缺少必填参数
    let err = failed(&cli(&["info"]), "info 缺少 --dir");
    assert!(err.starts_with("error: "), "参数缺失必须输出 \"error: ...\"，实际: {err:?}");

    // 未知子命令
    let err = failed(&cli(&["nonsense"]), "未知子命令");
    assert!(
        err.starts_with("error: usage: blockchain"),
        "未知子命令必须打印用法，实际: {err:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// P2P 同步
// ---------------------------------------------------------------------------

#[test]
fn nodes_sync_blocks_over_p2p() {
    let d1 = tmp_dir("sync-n1");
    let d2 = tmp_dir("sync-n2");
    init(&d1);
    init(&d2);

    let miner = newkey(&["--seed", &"88".repeat(32), "--index", "0"]);

    // node1：自带挖矿，1 秒一块
    let n1 = start_node(&d1, &["--mine", &miner.addr, "--interval", "1"]);
    // node2：只连 node1，不挖矿
    let peer = format!("127.0.0.1:{}", n1.port);
    let n2 = start_node(&d2, &["--connect", &peer]);

    // node1 至少要挖出一块
    let mined = n1.wait_line("mined", |l| l.starts_with("[node] mined "));
    let parts: Vec<&str> = mined.split_whitespace().collect();
    assert_eq!(parts.len(), 4, "mined 日志格式必须是 \"[node] mined <height> <hash>\"，实际: {mined:?}");
    assert_eq!(parts[2], "1", "node1 的第一块高度必须是 1");
    assert_hex(parts[3], 64, "node1 mined 日志里的块哈希");

    // 轮询 node2 的链文件，直到同步到高度 >= 1（最多 20 秒）
    let start = Instant::now();
    let mut last_height = 0u64;
    loop {
        if d2.join("blocks.bin").is_file() {
            let o = cli(&["info", "--dir", &d2.to_string_lossy()]);
            if o.status.success() {
                let lines = stdout_lines(&o);
                let h = lines
                    .first()
                    .and_then(|l| l.strip_prefix("height "))
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(0);
                last_height = h;
                if h >= 1 {
                    break;
                }
            }
        }
        if start.elapsed() > LIMIT {
            n1.dump("node1");
            n2.dump("node2");
            panic!(
                "node2 在 {} 秒内没有同步到高度 >= 1（最后高度 {last_height}）",
                LIMIT.as_secs()
            );
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(last_height >= 1, "node2 必须同步到至少 1 块");

    // node2 也应在日志里报告收到区块
    n2.wait_line("block", |l| l.starts_with("[node] block "));

    // 两个节点的 tip 必须一致
    let tip1 = info(&d1).1;
    let tip2 = info(&d2).1;
    assert_eq!(tip2, tip1, "同步后两个节点的链尖必须相同");

    drop(n1);
    drop(n2);
    let _ = std::fs::remove_dir_all(&d1);
    let _ = std::fs::remove_dir_all(&d2);
}

#[test]
fn node_mines_and_reports_height() {
    let d = tmp_dir("node-self");
    init(&d);
    let addr = newkey(&["--seed", &"99".repeat(32), "--index", "0"]).addr;
    let n = start_node(&d, &["--mine", &addr, "--interval", "1"]);

    // 连续两块
    let _ = n.wait_line("mined 2", |l| l.starts_with("[node] mined 2 "));
    let (height, _tip, _bits, _utxos) = info(&d);
    assert!(
        height >= 2,
        "自挖节点应在链上留下至少 2 块，实际高度 {height}"
    );

    drop(n);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn cli_send_to_peer_handshakes_and_returns_txid() {
    let d1 = tmp_dir("peer-send1");
    let d2 = tmp_dir("peer-send2");
    init(&d1);
    init(&d2);
    let a = newkey(&["--seed", &"ab".repeat(32), "--index", "0"]);
    let b = newkey(&["--seed", &"cd".repeat(32), "--index", "0"]);

    // 接收方节点（不挖矿）
    let mut n2 = start_node(&d2, &[]);
    let peer = format!("127.0.0.1:{}", n2.port);

    let d1s = d1.to_string_lossy().to_string();
    ok(&cli(&["mine", "--dir", &d1s, "--addr", &a.addr]), "给付款方挖块");

    let lines = ok(
        &cli(&[
            "send", "--dir", &d1s, "--key", &a.sk, "--to", &b.addr, "--amount", "1000000",
            "--peer", &peer,
        ]),
        "send --peer",
    );
    assert_eq!(lines.len(), 1, "带 --peer 的 send 也必须只输出 txid 一行，实际: {lines:?}");
    assert_hex(&lines[0], 64, "send --peer 的 txid");

    // 对端必须接受了这条 Tx（内存池不落盘，只能确认进程仍存活且没报错）
    assert!(n2.alive(), "对端节点在收到交易后不应退出");
    n2.dump("接收方节点");

    drop(n2);
    let _ = std::fs::remove_dir_all(&d1);
    let _ = std::fs::remove_dir_all(&d2);
}
