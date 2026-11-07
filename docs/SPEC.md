# ATL-Chain 规格书（唯一真理源）

只用 Rust 标准库（`std`），**零外部依赖**，禁止 `unsafe`。目标是「完整可跑的加密货币」：
SHA-256、secp256k1 签名、Base58 地址、UTXO 交易、PoW 挖矿、难度调整、减半、内存池、
P2P 节点同步、持久化、钱包/CLI、测试。代码追求**最少行数**但保持可读。

所有二进制数据一律小端（整数）/ 大端（哈希、公钥、签名的 32 字节数值）。
所有金额单位 satoshi，`COIN = 100_000_000`。

---

## 0. 文件与职责

| 文件 | 内容 |
|---|---|
| `Cargo.toml`, `src/lib.rs`, `src/codec.rs`, `src/hash.rs`, `src/secp.rs`, `src/main.rs` | 编解码/哈希/EC/CLI |
| `src/chain.rs`, `src/wallet.rs` | 数据结构/共识/UTXO/钱包 |
| `src/store.rs`, `src/net.rs`, `src/node.rs` | 持久化/P2P/节点 |
| `tests/*.rs` | 测试 |

---

## 1. `src/codec.rs`（编解码原语，直接调用）

```rust
pub fn put_u8(b:&mut Vec<u8>, v:u8);
pub fn put_u16(b:&mut Vec<u8>, v:u16);      // 小端
pub fn put_u32(b:&mut Vec<u8>, v:u32);
pub fn put_u64(b:&mut Vec<u8>, v:u64);
pub fn put_i64(b:&mut Vec<u8>, v:i64);
pub fn put_raw(b:&mut Vec<u8>, d:&[u8]);     // 原样
pub fn put_bytes(b:&mut Vec<u8>, d:&[u8]);   // u32 长度 + 数据
pub fn put_hash(b:&mut Vec<u8>, h:&[u8;32]);
pub fn hex(d:&[u8]) -> String;
pub fn unhex(s:&str) -> Option<Vec<u8>>;
pub fn b58check(d:&[u8]) -> String;          // base58(payload || sha256d(payload)[0..4])
pub fn unb58check(s:&str) -> Option<Vec<u8>>;// 校验失败返回 None

pub struct Rd<'a> { /* 私有游标 */ }
impl<'a> Rd<'a> {
    pub fn new(b:&'a [u8]) -> Self;
    pub fn rest(&self) -> usize;             // 剩余字节
    pub fn u8(&mut self) -> Option<u8>;
    pub fn u16(&mut self) -> Option<u16>;
    pub fn u32(&mut self) -> Option<u32>;
    pub fn u64(&mut self) -> Option<u64>;
    pub fn i64(&mut self) -> Option<i64>;
    pub fn raw(&mut self, n: usize) -> Option<&'a [u8]>; // 越界 None
    pub fn bytes(&mut self) -> Option<&'a [u8]>;         // u32 长度前缀
    pub fn hash(&mut self) -> Option<[u8;32]>;
}
```

## 2. `src/hash.rs`

```rust
pub fn sha256(d:&[u8]) -> [u8;32];
pub fn sha256d(d:&[u8]) -> [u8;32];          // sha256(sha256(d))
pub fn h160(d:&[u8]) -> [u8;20];             // sha256(d)[0..20]（为省行数不实现 RIPEMD160）
pub fn merkle(hs:&[[u8;32]]) -> [u8;32];     // 空->[0;32]; 奇数复制最后一个; 叶子已是 txid
```

## 3. `src/secp.rs`

```rust
pub fn pubkey(sk:&[u8;32]) -> [u8;33];       // 压缩公钥：02/03 || x
pub fn sign(sk:&[u8;32], msg32:&[u8;32]) -> [u8;64];   // r||s 各 32 字节大端
pub fn verify(pk33:&[u8;33], msg32:&[u8;32], sig:&[u8;64]) -> bool;
pub fn addr(pk33:&[u8;33]) -> [u8;20];       // h160(pk33)
```

## 4. `src/chain.rs`

### 4.1 类型（字段顺序即编码顺序）

```rust
pub const COIN: u64 = 100_000_000;
pub const SPACING: i64 = 60;                 // 目标出块秒数
pub const HALVING: u64 = 210_000;
pub const RETARGET: u64 = 2016;
pub const MAX_FRAME: usize = 4 << 20;        // 网络帧上限，供 net 使用

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug, Default)]
pub struct OutPoint { pub txid:[u8;32], pub idx:u32 }

#[derive(Clone, Debug)]
pub struct TxIn { pub prev:OutPoint, pub sig:Vec<u8>, pub pk:Vec<u8> }

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxOut { pub value:u64, pub addr:[u8;20] }

#[derive(Clone, Debug)]
pub struct Tx { pub time:i64, pub ins:Vec<TxIn>, pub outs:Vec<TxOut> }

#[derive(Clone, Debug)]
pub struct Block { pub prev:[u8;32], pub time:i64, pub bits:u32, pub nonce:u32, pub txs:Vec<Tx> }
```

### 4.2 编码（严格按此实现，跨进程/持久化/测试都依赖）

- `Tx`: `u32 n_in` → 每个输入 `32 prev.txid, u32 prev.idx, bytes sig, bytes pk`；`u32 n_out` → 每个输出 `u64 value, 20 addr`；`i64 time`。
- `Block`: `32 prev, i64 time, u32 bits, u32 nonce, u32 n_tx` → 各 `bytes tx.enc()`。
- `Block::header() -> Vec<u8>`：`32 prev, i64 time, u32 bits, u32 nonce`（48 字节）。
- `Block::hash() = sha256d(header())`；`Block::merkle() = hash::merkle(&txs.map(id))`。

### 4.3 函数

```rust
impl Tx {
    pub fn enc(&self) -> Vec<u8>;
    pub fn dec(r:&mut Rd) -> Option<Tx>;
    pub fn id(&self) -> [u8;32];                              // sha256d(enc())
    pub fn is_coinbase(&self) -> bool;                        // 1 个输入且 prev.txid==[0;32] 且 idx==0xffff_ffff
    pub fn signing_hash(&self, i:usize) -> [u8;32];           // sha256d(enc_nosig() || i as u32 LE)，enc_nosig 中所有 sig/pk 编码为空 bytes
}

impl Block {
    pub fn enc(&self) -> Vec<u8>;
    pub fn dec(r:&mut Rd) -> Option<Block>;
    pub fn header(&self) -> Vec<u8>;
    pub fn hash(&self) -> [u8;32];
    pub fn merkle(&self) -> [u8;32];
}

pub fn target(bits:u32) -> [u8;32];          // 紧凑格式：exp=bits>>24, mant=bits&0xffffff, 值=mant*256^(exp-3)，大端
pub fn pow_ok(h:&[u8;32], bits:u32) -> bool; // h 作为大端无符号数 <= target(bits)
pub fn subsidy(height:u64) -> u64;           // 50*COIN >> (height/HALVING)，位移 >=64 时 0
pub fn next_bits(c:&Chain) -> u32;           // 见 4.5

pub struct Chain {
    pub blocks: Vec<Block>,                  // blocks[0] 为创世块
    pub utxo: HashMap<OutPoint, TxOut>,      // 仅未花费输出
}
impl Chain {
    pub fn new(genesis_addr:[u8;20]) -> Chain;   // 创世块：prev=[0;32], time=GENESIS_TIME, bits=genesis_bits(), nonce 挖到位
    pub fn height(&self) -> u64;                 // blocks.len()-1
    pub fn tip(&self) -> [u8;32];                // 最后一个块 hash
    pub fn tip_time(&self) -> i64;
    pub fn balance(&self, addr:&[u8;20]) -> u64;
    pub fn utxos_of(&self, addr:&[u8;20]) -> Vec<(OutPoint, TxOut)>;
    pub fn validate_tx(&self, tx:&Tx, extra_spent:&HashSet<OutPoint>) -> Result<u64, String>; // 返回手续费
    pub fn build_block(&self, addr:&[u8;20], txs:&[Tx], time:i64) -> Block; // 自动加 coinbase（value=subsidy+fees），bits=next_bits
    pub fn mine_block(&self, b:&mut Block);      // 递增 nonce 直到 pow_ok（必要时更新 time？不更新，保持确定性）
    pub fn add_block(&mut self, b:&Block) -> Result<(), String>;   // 校验并落账（更新 utxo）
}

pub const GENESIS_TIME: i64 = 1_700_000_000;
pub fn genesis_bits() -> u32;                    // 读环境变量 ATL_BITS（hex，如 "1f0fffff"），缺省 0x1f0fffff（约 4096 次哈希）

pub struct Mempool { pub txs: Vec<Tx> }
impl Mempool {
    pub fn new() -> Self;
    pub fn add(&mut self, c:&Chain, tx:Tx) -> Result<(), String>;
    pub fn remove(&mut self, ids:&[[u8;32]]);
    pub fn clean(&mut self, c:&Chain);           // 丢弃已被链确认或已非法的交易
    pub fn select(&self, c:&Chain) -> Vec<Tx>;   // 返回仍可打包的交易（内部做依赖/冲突过滤）
}
```

### 4.4 交易校验规则（`validate_tx`，返回 fee）

1. 非 coinbase（coinbase 由 `add_block` 单独处理，不进内存池）。
2. `ins` 非空、`outs` 非空；每个 `outs[i].value > 0`。
3. 每个输入：`utxo` 中存在 `prev` 且不在 `extra_spent` 中（同一交易内重复输入也算冲突，用局部 set）。
4. 签名：`pk` 必须 33 字节且 `secp::addr(pk) == utxo.addr`；`sig` 必须 64 字节且
   `secp::verify(pk, &tx.signing_hash(i), sig)` 为真。
5. `sum(in) >= sum(out)`，fee = sum(in)-sum(out)。

### 4.5 区块校验与共识（`add_block`）

顺序：① `b.prev == self.tip()`；② `b.merkle() == hash::merkle(txids)`；③ `b.bits == next_bits(self)`；
④ `pow_ok(b.hash(), b.bits)`；⑤ `b.time > median(prev 最多 11 个块时间戳)`（创世后第一个块只要求 `> genesis.time`）；
⑥ 第一个 tx 必须是 coinbase，且其余 tx 都不是 coinbase；⑦ coinbase 输出总额 <= `subsidy(height+1)+fees`；
⑧ 每个普通 tx 用 `validate_tx` 校验（`extra_spent` 累积本块已花费输入），fees 累加；⑨ 落账：删除已花费 utxo，
加入新输出（含 coinbase 输出，`idx` 为输出下标），`blocks.push(b.clone())`。

`next_bits(c)`：若 `(height+1) % RETARGET == 0`（height 为当前高度），取最近 RETARGET 个块的实际时间跨度
span = `tip_time - time(height+1-RETARGET)`，期望 expect = `RETARGET*SPACING`；span 限幅到 `[expect/4, expect*4]`；
`m2 = mant * span / expect`，再把 `m2` 限幅到 `[mant/4, mant*4]`；用 `while m2 > 0xffffff { m2 >>= 8; exp += 1 }`
与 `while m2 < 0x10000 && exp > 3 { m2 <<= 8; exp -= 1 }` 归一化；返回 `(exp<<24)|m2`。否则返回 `tip.bits`。

## 5. `src/wallet.rs`

```rust
pub struct Key { pub sk:[u8;32], pub pk:[u8;33], pub addr:[u8;20] }
impl Key {
    pub fn from_seed(seed:&[u8], idx:u32) -> Key;  // sk = sha256(b"ATL-wallet" || seed || idx.to_le_bytes())，落在 [1,n-1]
    pub fn from_hex(s:&str) -> Option<Key>;        // 32 字节 hex
    pub fn hex(&self) -> String;                   // sk 的 hex
}
pub fn new_seed() -> [u8;32];                      // 无 rand 库：SystemTime 纳秒 + pid + 地址熵 + sha256
pub fn send(c:&Chain, k:&Key, to:[u8;20], amount:u64, fee:u64, time:i64) -> Result<Tx, String>;
// 选取 k.addr 的 utxo（按 OutPoint 升序），构建单/多输入交易，change 找零回 k.addr（change==0 则省略），逐输入签名
```

## 6. `src/store.rs`

```rust
pub const FILE: &str = "blocks.bin";
pub fn load(dir:&str) -> std::io::Result<Chain>;   // 仅读已有链：无文件/不可读 -> Err（原样透出 os error）；有文件 -> 校验创世后重放 add_block，坏块报错。不负责新建
pub fn save(dir:&str, c:&Chain) -> std::io::Result<()>; // 写 dir/blocks.bin.tmp 后 rename；格式：b"ATLDB01" || u32 n || 每块 bytes
pub fn exists(dir:&str) -> bool;
pub fn load_or_init(dir:&str) -> std::io::Result<Chain>; // 唯一的“新建”入口：不存在则 Chain::new(GENESIS_ADDR) 并落盘
```
创世地址固定为 `[0u8;20]`（`store` 与 `main` 都用它：`pub const GENESIS_ADDR:[u8;20] = [0;20];` 放 chain.rs）。

## 7. `src/net.rs`

```rust
pub const MAGIC:[u8;4] = *b"ATL1";
#[derive(Clone, Debug)]
pub enum Msg {
    Version{ height:u64, port:u16 },   // 0x01
    GetBlocks{ from:u64 },             // 0x02
    Blocks(Vec<Block>),                // 0x03
    Tx(Tx),                            // 0x04
    Ping,                              // 0x05
    Pong,                              // 0x06
}
impl Msg { pub fn enc(&self) -> Vec<u8>; pub fn dec(b:&[u8]) -> Option<Msg>; }
pub fn send(s:&mut std::net::TcpStream, m:&Msg) -> std::io::Result<()>; // MAGIC || u32 len || payload
pub fn recv(s:&mut std::net::TcpStream) -> std::io::Result<Option<Msg>>; // EOF -> Ok(None)，坏帧/超长 -> Err
```

## 8. `src/node.rs`

```rust
pub fn run(dir:&str, port:u16, connect:&[String], mine:Option<[u8;20]>, interval:u64) -> std::io::Result<()>;
```
行为：从 `store::load_or_init(dir)` 取链；绑定 `127.0.0.1:port`（port=0 时由系统分配）并打印
`[node] listening 127.0.0.1:<实际端口>` 后 flush；对每个 `--connect` 建连（失败重试，不退出）；
握手：连接建立后双方都先发 `Version{height,port}`；收到 `Version` 若对端更高则发 `GetBlocks{from:height+1}`；
收到 `Blocks` 逐个 `add_block`（非法块忽略并打印），成功则 `store::save` 并向所有 peer 广播 `Blocks(vec![b])`，
若仍落后则继续请求；收到 `Tx` → `mempool.add` 成功则广播给其他 peer（不回给发送者）；
`--mine ADDR` 时每 `interval` 秒从 mempool 取交易 `build_block` + `mine_block` + `add_block` + `save` + 广播，打印
`[node] mined <height> <hash>`。任何线程 panic 都不应杀掉主循环；`run` 正常情况不返回。
锁：`Arc<Mutex<...>>`，广播在锁内只做 `write_all`，避免死锁。

## 9. `src/main.rs`

```
blockchain init  --dir D
blockchain info  --dir D
blockchain balance --dir D --addr HEX
blockchain newkey [--seed HEX] [--index N]
blockchain mine  --dir D --addr HEX [--tx HEX]...      # 离线挖一块（从 -tx 解析的 mempool 交易）
blockchain send  --dir D --key HEX --to HEX --amount N [--fee N] [--peer HOST:PORT]
blockchain node  --dir D --port P [--connect HOST:PORT]... [--mine HEX] [--interval S]
```
### 9.1 精确输出格式（测试按此断言）

| 命令 | stdout | 失败 |
|---|---|---|
| `newkey` | 恰好 3 行：`sk <64hex>` / `pk <66hex>` / `addr <40hex>` | `error: ...` exit 1 |
| `init` | 一行 `init ok <genesis_hash_64hex>` | 已存在：`error: already initialized` exit 1 |
| `info` | 恰好 4 行：`height <u64>` / `tip <64hex>` / `bits <8hex>` / `utxos <n>` | `error: no chain in <dir>` exit 1 |
| `balance` | 一行 `balance <40hex> <satoshis十进制>`（**只输出整数 satoshi**） | 同上 |
| `mine` | 一行 `mined <height> <block_hash_64hex>`（高度=该块高度） | `error: ...` exit 1 |
| `send`（无 peer） | 一行 `<txid_64hex>`（只有 txid） | 余额不足：`error: insufficient funds` exit 1 |
| `send`（有 peer） | 先 Version 握手 + Tx 发送，成功后同上打印 txid | 同上 |
| `node` | `[node] listening 127.0.0.1:<port>`、`[node] mined <height> <hash>`（flush） | stderr + exit 1 |

其它约定：`--tx HEX` 是 `Tx::enc()` 的 hex，可重复；`--dir` 不存在时 `init` 创建它；所有日志走 stdout，
`error: ...` 走 stderr 且退出码 1；`Chain` derive `Clone`。
参数解析是严格的：未知 `--flag`、缺值的悬空 `--flag`、多余的位置参数一律 `error: ...` exit 1（不静默忽略）。

## 10. 测试与验收

- `tests/crypto.rs`：SHA-256 空串/`abc` 标准向量、`sha256d`、merkle 3 叶子、base58check 往返、私钥 1 的公钥
  应为 `0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798`、签名验证/篡改失败。
- `tests/chain.rs`：创世块、挖矿后 `add_block` 成功、错误 nonce/坏 merkle/双花/超发 coinbase 被拒、
  `subsidy` 减半、`next_bits` 稳定。
- `tests/wallet.rs`：构造链 → 给地址挖块 → `wallet::send` 生成交易进 mempool → 挖出后余额正确、无签名失败。
- `tests/net.rs`：`Msg` 全变体 enc/dec 往返；`TcpListener` + `send`/`recv` 往返；超长长度头返回 Err。
- `tests/e2e.rs`：用 `env!("CARGO_BIN_EXE_blockchain")` 跑 `init/newkey/mine/balance/send/info`；
  再起两个 `node`（端口 0，解析 stdout 的 `listening` 行）验证同步：node1 `--mine`，node2 `--connect node1`，
  轮询 node2 的 `info` 直到高度 >= 1（超时 20s）。
- `README.md`：架构图（文本）、模块表、快速开始、协议说明、安全边界（仅教学用：SHA256 截断地址、简化难度调整、
  无网络加密）、代码行数统计表。
- 测试须使用 `env!("CARGO_TARGET_TMPDIR")`（默认 `<repo>/target/tmp`）下带唯一后缀的目录，并在结束时清理；
  不得依赖外部网络。**注意本环境子进程无法写 `%TEMP%`/`std::env::temp_dir()`（`os error 5`，拒绝访问），
  因为它位于工作区之外**；`target/` 在可写范围内且本就是构建输出，故用它。也不要给 cargo 传 `TMP=`/`TEMP=` 覆盖，会让 linker 报 `LNK1104`。
