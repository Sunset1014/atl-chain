# ATL-Chain · 一条用纯 Rust 手写的区块链

**中文** | [English](#english)

> 一个**零外部依赖**、**纯标准库**、**没有一行 `unsafe`** 的教学用加密货币实现。
> 手写 SHA-256 与 secp256k1，UTXO 账本 + PoW 共识 + TCP 节点同步 + 命令行钱包，一共 **1730 行**。
>
> A dependency-free, `std`-only, `unsafe`-free educational cryptocurrency in **1730 lines** of Rust.
> Hand-written SHA-256 and secp256k1, UTXO ledger, proof-of-work, peer-to-peer sync and a CLI wallet.

`cargo build` 一次编译到底，**2.6 秒**；`cargo test` **73 个测试全绿**。
`[dependencies]` 是空的——没有 `rand`、没有 `serde`、没有 `tokio`、没有 `bitcoin` crate。

---

## 目录

- [1. 这是给谁看的](#1-这是给谁看的)
- [2. 三十秒跑起来](#2-三十秒跑起来)
- [3. 它到底包含什么](#3-它到底包含什么)
- [4. 架构：一条链由哪几块拼成](#4-架构一条链由哪几块拼成)
- [5. 核心概念，用人话说一遍](#5-核心概念用人话说一遍)
- [6. 命令参考](#6-命令参考)
- [7. 数据格式与网络协议](#7-数据格式与网络协议)
- [8. 代码怎么读](#8-代码怎么读)
- [9. 安全边界（务必先读）](#9-安全边界务必先读)
- [10. 测试](#10-测试)
- [11. 环境注意事项](#11-环境注意事项)
- [12. 许可](#12-许可)

---

## 1. 这是给谁看的

你可能有过这种经历：读比特币或以太坊的代码，被构建脚本、异步运行时、几千个依赖和一层层抽象淹没，读了半天还是不知道「一笔交易从签名到上链到底发生了什么」。

这个项目想解决的就是这件事。它把一条链压到最小可运行的体积：

- **没有第三方库**。哈希、椭圆曲线、序列化、网络帧、十六进制编解码，全部手写。
- **没有宏魔法**。没有过程宏、没有 `build.rs`、没有 `include!` 生成代码。
- **没有异步**。P2P 就是 `std::net::TcpStream` 加线程，看不懂的地方可以直接 `println!` 打断点。
- **没有 `unsafe`**。`grep -rn unsafe src/` 零命中，所有逻辑都在 Rust 安全子集内。

代价是它**不是生产级区块链**，[第 9 节](#9-安全边界务必先读)会逐条列出每一处刻意的简化。请把它当成一份可以编译、可以运行、可以改的教材，而不是一个能存钱的系统。

---

## 2. 三十秒跑起来

需要 Rust 1.70+（实测 `rustc 1.99.1`）。不需要任何网络依赖。

```bash
git clone <this-repo> && cd atl-chain
cargo build --release
```

产物是 `target/release/blockchain`（Windows 下 `blockchain.exe`），下面记作 `$B`。

一次完整的「建链 → 挖矿 → 转账 → 确认」：

```bash
$ export ATL_BITS=207fffff      # 测试用超低难度，见下方说明
$ B=./target/release/blockchain

$ $B init --dir demo
init ok 6ee30f47a8d38212fae8507b5b45de8206781bb26e724b4e1b8e11c62e2ee804

$ $B newkey --seed 00000000000000000000000000000000000000000000000000000000000000aa
sk 95136c684a7ede3d44f82867e0787fd9f92073f7906dcf15629859722b316cf0
pk 031855adce80268fa6dd9e81a2822d253bc606658380e3d26ed15657ff6d9d5b49
addr 1fdf5b79c0ff43ffc33847d3b6e8f0252de12721

$ $B newkey --seed 00000000000000000000000000000000000000000000000000000000000000bb
sk cfc3fdee2b94273e088b3b6b2a778822b538543ad6ce183d1f8982345c5696ba
pk 03699b4591f68836569a41d1f270147d96fdc6fb7588ca98d921fd9fd6e5936601
addr 1afb2f619116e0b4c0b5ae853e5192f3105257a1

# 挖一个块，奖励 50 币给 alice（1 币 = 100_000_000 satoshi）
$ $B mine --dir demo --addr 1fdf5b79c0ff43ffc33847d3b6e8f0252de12721
mined 1 21183d4ab2ae46c18dc7740905069b0bb973142133e4eb22450f3a3d1eab009c

$ $B balance --dir demo --addr 1fdf5b79c0ff43ffc33847d3b6e8f0252de12721
balance 1fdf5b79c0ff43ffc33847d3b6e8f0252de12721 5000000000

# 转账 1.5 币给 bob，手续费 1000 satoshi
$ $B send --dir demo \
    --key 95136c684a7ede3d44f82867e0787fd9f92073f7906dcf15629859722b316cf0 \
    --to 1afb2f619116e0b4c0b5ae853e5192f3105257a1 \
    --amount 150000000 --fee 1000
8ffb515b59fa7d7235a7a9b0e44a6010b17becf4b0e290f8725baafc7985d054

# send 只广播交易，不打包。要等下一个块确认：
$ $B info --dir demo | head -1
height 1                          # ← 还是 1，交易还在内存池里

$ $B mine --dir demo --addr 1fdf5b79c0ff43ffc33847d3b6e8f0252de12721
mined 2 412836f2df754698bfb838a9215ee6151db0761a315833ff5b9f2e125b170e57

$ $B balance --dir demo --addr 1fdf5b79c0ff43ffc33847d3b6e8f0252de12721
balance 1fdf5b79c0ff43ffc33847d3b6e8f0252de12721 9850000000
$ $B balance --dir demo --addr 1afb2f619116e0b4c0b5ae853e5192f3105257a1
balance 1afb2f619116e0b4c0b5ae853e5192f3105257a1 150000000
```

账算得对：alice 挖 1 块得 50 币（5_000_000_000 sat），转出 1.5 币（150_000_000）+ 手续费 1000，第二块又得 50 币 + 手续费返还，最终 `5e9 - 1.5e8 - 1000 + 5e9 + 1000 = 9850000000`。

> **关于 `ATL_BITS=207fffff`**：这个环境变量决定创世块的难度目标。默认 `0x1f0fffff` 约需 4096 次哈希，已经是「秒出块」；`207fffff` 则几乎任何 nonce 都能过，用于演示更快。它**参与创世哈希**，所以跨进程必须一致，否则读链会报 `genesis mismatch`。
>
> **哪些输出能逐字复现？** `init ok` 的哈希、`newkey` 的三行、`balance`、`info` 的 `height`/`utxos` 都可以。**`mined` 的块哈希与 `send` 的 txid 不行**——两者都把真实系统时钟写进了被哈希的内容（区块时间取 `max(now, tip_time + 1)`，交易时间取 `now`），每次都不同。金额与高度的数字则完全可复现。

两个节点互相同步：

```bash
# 终端 A
$ $B init --dir n1
$ $B node --dir n1 --port 33501 --mine 1fdf5b79c0ff43ffc33847d3b6e8f0252de12721 --interval 1
[node] listening 127.0.0.1:33501
[node] mined 1 21bfa1ff5eb6c295c122b53cd2da5453ae945d48bcefad50d2f5d82bf907966e
[node] mined 2 5966eab98a5570962df580f43a87373a091ab3019a5f3b31ff20bbc2b38f5960

# 终端 B
$ $B init --dir n2
$ $B node --dir n2 --port 33502 --connect 127.0.0.1:33501
[node] listening 127.0.0.1:33502
[node] peer 127.0.0.1:33501 up
[node] block 1 21bfa1ff5eb6c295c122b53cd2da5453ae945d48bcefad50d2f5d82bf907966e
[node] block 2 5966eab98a5570962df580f43a87373a091ab3019a5f3b31ff20bbc2b38f5960
```

哈希逐一相同，说明 B 真的把 A 的块原样收下并验证通过了。

---

## 3. 它到底包含什么

| 能力 | 实现位置 | 说明 |
|---|---|---|
| SHA-256 / SHA-256d | `src/hash.rs` | 标准 K 表 + 压缩函数，逐行手写 |
| Merkle 根 | `src/hash.rs` | 奇数个叶子时复制最后一个（比特币同样做法） |
| secp256k1 域运算 | `src/secp.rs` | 4×`u64` 小端肢体，`2^256 ≡ 0x1000003D1` 折叠 |
| ECDSA 签名/验签 | `src/secp.rs` | 确定性 nonce，low-S 归一化，Jacobian 坐标点乘 |
| 地址派生 | `src/secp.rs` | `sha256(pk)[0..20]`，压缩公钥 33 字节 |
| 二进制编解码 | `src/codec.rs` | 整数小端、变长字段 `u32` 长度前缀、hex、Base58Check |
| 交易（UTXO） | `src/chain.rs` | 多输入多输出、逐输入签名、手续费 = 输入 − 输出 |
| 区块与链 | `src/chain.rs` | 哈希指针、Merkle 根、时间戳中位数校验 |
| PoW 与难度调整 | `src/chain.rs` | 紧凑 `bits` 目标、每 2016 块重定目标、幅度钳制 |
| 出块奖励减半 | `src/chain.rs` | 每 210_000 块 `/2`，起点 50 币 |
| 内存池 | `src/chain.rs` | 入池校验、冲突过滤、上链后清理 |
| 钱包 | `src/wallet.rs` | 种子派生密钥、UTXO 选币、找零 |
| 持久化 | `src/store.rs` | `blocks.bin`，临时文件 + `rename` 原子落盘 |
| P2P 协议 | `src/net.rs` | `ATL1` 魔数帧、6 种消息 |
| 节点主循环 | `src/node.rs` | 握手、批量同步、广播转发、挖矿、断线重连 |
| 命令行 | `src/main.rs` | 6 个子命令 + 严格参数校验 |

---

## 4. 架构：一条链由哪几块拼成

依赖方向单向向下，**无环**。`chain.rs` 是枢纽：所有业务模块都要用它。

```
                    ┌──────────────────┐
                    │    src/main.rs   │  命令行入口（唯一 [[bin]]）
                    └────────┬─────────┘
        ┌──────────────┬─────┴─────┬──────────────┐
        ▼              ▼           ▼              ▼
  ┌──────────┐  ┌──────────┐ ┌──────────┐  ┌──────────┐
  │src/wallet│  │ src/node │ │src/store │  │  src/net │
  └────┬─────┘  └────┬─────┘ └────┬─────┘  └────┬─────┘
       │             └─────┬──────┘             │
       └──────────┬────────┴────────────────────┘
                  ▼
          ┌──────────────┐
          │  src/chain   │   ← 账本与共识，全项目的中心
          └──────┬───────┘
                 ▼
       ┌─────────┴──────────┬──────────────┐
       ▼                    ▼              ▼
 ┌──────────┐        ┌──────────┐    ┌──────────┐
 │src/wallet│        │src/codec │    │  src/hash│
 └──────────┘        └──────────┘    └────┬─────┘
                                          ▼
                                    ┌──────────┐
                                    │ src/secp │   最底层：数学
                                    └──────────┘
```

| 文件 | 行数 | 职责 |
|---|---:|---|
| `src/secp.rs` | 553 | 有限域、标量算术、曲线点运算、ECDSA |
| `src/chain.rs` | 305 | 交易/区块/链/内存池/共识规则 |
| `src/main.rs` | 204 | CLI |
| `src/node.rs` | 203 | 节点主循环 |
| `src/codec.rs` | 133 | 编解码原语 |
| `src/net.rs` | 104 | 帧协议与消息 |
| `src/hash.rs` | 85 | SHA-256 系列 |
| `src/wallet.rs` | 74 | 密钥与选币 |
| `src/store.rs` | 59 | 持久化 |
| `src/lib.rs` | 10 | `pub mod` 声明 |
| **合计** | **1730** | |

---

## 5. 核心概念，用人话说一遍

这一节不涉及代码，只讲清楚「一条链为什么能成立」。如果你已经熟悉区块链，跳过它。

### 5.1 钱不是余额，是一堆「还没花掉的收据」

传统银行记的是账户余额。比特币这类系统不记余额，只记**每一笔钱的来历**。

想象一张收据：「付给 Alice 50 币」。这张收据只要没被花掉，就叫一个 **UTXO**（Unspent Transaction Output，未花费交易输出）。你的「余额」是把你名下所有没收据加起来算出来的——没有哪个字段单独存着这个数。

转账时，你把这些收据当输入，开出新的收据当输出：

```
输入：Alice 的 50 币收据（凭空消失，标记为已花）
输出：Bob 1.5 币收据 + Alice 48.5 币找零收据
```

这就是为什么本项目的 `balance()` 是个**遍历求和**函数，而不是查一个表。

这么设计的好处：每笔钱只有「花掉」和「没花掉」两种状态，**天然防双花**——同一张收据你不可能花两次，因为第一次花掉时它就从 UTXO 集合里删掉了。代价是账本随时间膨胀，需要额外机制压缩（比特币用 UTXO 集快照，这个项目没有）。

### 5.2 区块是「账本的一页」，哈希是把页钉在一起的钉子

每个区块里有一堆交易，外加一个指向上一块的哈希。改任何一页的内容，它的哈希就变，下一页记的「上一页哈希」就对不上——所以你只能从最新一块往回改，并且要把后面每一块都重新挖一遍。

```
块 0（创世）← 块 1 ← 块 2 ← 块 3
   prev=0      prev=H(0)  prev=H(1)  prev=H(2)
```

本项目的 `Block::hash()` 是 `sha256d(header)`，header 只有 48 字节：`prev(32) | time(8) | bits(4) | nonce(4)`。注意**交易不在 header 里**，它们在 header 里以 Merkle 根的形式出现——`merkle()` 把交易 id 两两配对哈希，最后剩一个根，塞进 header。这样只改区块头就能代表整个区块的内容。

### 5.3 挖矿：把哈希值「压小」

`bits` 是一个紧凑编码的难度目标，比如 `0x1f0fffff` 解出来是 `0x0fffff << (8*(0x1f-3))`，一个 256 位整数。合法区块的条件是：

```
sha256d(header) < target
```

哈希看起来是随机的，所以只能一个个试 `nonce` 直到撞上。这就是 PoW：**它的唯一作用是让「写历史」变得昂贵**。想改一个 10 块以前的区块，你得重算这 10 块的 PoW，还得比全网其他人算得快。

难度每 2016 块调整一次，目标是让出块间隔保持在 60 秒：

```
实际耗时 span = clamp(最后一块时间 − 2016 块前的时间, 期望/4, 期望×4)
新目标 = 旧目标 × span / 期望
```

`clamp` 是防攻击的：如果没有它，攻击者可以伪造一个极端时间戳，把难度一次性砸到泥土里。本项目的钳制范围是 `[期望/4, 期望×4]`，比特币是 `[期望/4, 期望×4]`，思路一致。

### 5.4 签名：证明「这笔钱归我处置」，但不暴露私钥

你有私钥 `sk`（32 字节随机数），能算出公钥 `pk = sk·G`（椭圆曲线上的点乘），地址是 `sha256(pk)` 的前 20 字节。

签名时，你把交易内容哈希成一个 256 位的数 `h`，算出 `(r, s)` 两个数，共 64 字节。验证方拿到 `pk`、`h`、`(r, s)`，做几次曲线运算，就能判断「这个签名是不是 `sk` 对 `h` 做的」——但**无法反推出 `sk`**。

交易里每一笔输入都带自己的签名和公钥。验证规则是：`addr(pk) == 该 UTXO 的收款地址`，且签名有效。

`src/secp.rs` 是整个项目最长的文件，因为它真的实现了 256 位模运算：

- 用 4 个 `u64` 表示一个大数（小端），加、减、乘、比较全靠手写进位/借位。
- 模乘之后要「折叠」：因为 `2^256 ≡ 0x1000003D1 (mod p)`，超出 256 位的部分乘上这个常数再加回来。
- 求模逆用**二进制扩展 GCD**，比费马小定理的快速幂快得多（实测从 6.8 秒降到毫秒级）。
- 点乘用 Jacobian 投影坐标，避免每一步都做除法（求逆）。

签名用的随机数 `k` 不能重复（否则私钥直接泄露）。传统做法是取随机数，本项目用确定性派生：

```
k = sha256("ATL-k" || sk || msg)
```

思路来自 RFC6979，但**不是**标准 RFC6979 的实现。好处是不需要随机源，坏处是没做过侧信道加固。

### 5.5 网络：三句话说完同步

1. 连上以后双方各发一个 `Version { height, port }`，交换「我有多少个块」。
2. 谁发现对方更高，就发 `GetBlocks { from: 对方高度+1 }` 要块；对方回 `Blocks(最多 64 个)`；收完再要下一批，直到追平。
3. 每收到一个块就 `add_block` 校验（前一块对得上吗？Merkle 根对吗？难度对吗？PoW 对吗？时间戳对吗？交易都合法吗？coinbase 有没有多给钱？），通过就落盘并转给其它 peer。

没有共识算法（PoW 本身就是共识）、没有分叉选择（只接受 `prev == tip` 的块）、没有 peer 发现（手动 `--connect`）。

---

## 6. 命令参考

```
blockchain {init|info|balance|newkey|mine|send|node} [flags]
```

| 命令 | 参数 | 输出 |
|---|---|---|
| `newkey` | `--seed <hex32>` `--index <n>` | 三行 `sk <64hex>` / `pk <66hex>` / `addr <40hex>` |
| `init` | `--dir <path>` | `init ok <genesis_hash>` |
| `info` | `--dir <path>` | 四行 `height` / `tip` / `bits` / `utxos` |
| `balance` | `--dir` `--addr <40hex>` | `balance <40hex> <satoshis>` |
| `mine` | `--dir` `--addr` `--tx <hex>`（可重复） | `mined <height> <block_hash>` |
| `send` | `--dir` `--key <64hex>` `--to` `--amount` `--fee` `--peer` | `<txid>` |
| `node` | `--dir` `--port` `--connect`（可重复） `--mine` `--interval` | 持续的 `[node] ...` 日志 |

几条约定：

- **金额单位永远是 satoshi**，`1 币 = 100_000_000`。`--amount 150000000` 就是 1.5 币。
- `--seed` 给定时密钥完全确定（`Key::from_seed(seed, index)`），否则用系统时间 + pid 派生，不可重现。
- `send` **不挖块**，只把交易写进内存池侧车文件 `mempool.bin` 并输出 txid；要等 `mine` 或 `node` 打包才生效。
- `--tx` 指的是 `Tx::enc()` 的十六进制编码，**不是** txid。
- 参数解析是**严格**的：未知 `--flag`、缺值的悬空 flag、多余的位置参数一律报错退出，不会静默忽略。

错误一律走 stderr + 退出码 1：

```bash
$ $B init --dir demo
error: already initialized
$ $B balance --dir nope --addr 1fdf...
error: no chain in nope (系统找不到指定的路径。 (os error 3))
$ $B send --dir demo --key ... --to ... --amount 99999999999999
error: insufficient funds: have 9850000000, need 99999999999999
```

---

## 7. 数据格式与网络协议

### 7.1 编码总约定

- 所有整数**小端**。
- 哈希、公钥、签名按大端原样存放（`sha256` 输出的字节序即「显示的哈希」）。
- 变长字段统一 `u32` 长度前缀。
- 地址是 20 字节裸值，hex 显示为 40 字符（不是 Base58；`codec.rs` 里实现了 Base58Check 但 CLI 没用它）。

### 7.2 交易

```
Tx = time: i64            (8，小端)
   | u32 n_in
   | n_in × ( prev_txid: 32 | prev_idx: u32 | u32 sig_len | sig | u32 pk_len | pk )
   | u32 n_out
   | n_out × ( value: u64 | addr: 20 )
```

txid 是 `sha256d(完整编码)`。签名时把对应输入的 `sig` 和 `pk` **清空**后哈希（`signing_hash(i)`），这样签名不会覆盖自己。

coinbase 交易很特殊：恰好 1 个输入，`prev = ([0;32], 0xffff_ffff)`，`sig` 和 `pk` 为空。

### 7.3 区块

```
header = prev: 32 | time: i64 | bits: u32 | nonce: u32        (48 字节)
block  = header | u32 n_tx | n_tx × Tx::enc()
```

块哈希 = `sha256d(header)`。`bits` 解码为目标的算法：

```
target = mantissa << (8 × (exponent − 3))
```

### 7.4 `add_block` 的校验顺序

顺序很重要，否则错误信息会互相掩盖：

1. `prev == tip`（不接受分叉）
2. Merkle 根正确
3. `bits == next_bits(chain)`（难度必须符合规则）
4. PoW 达标
5. 时间戳大于最近 11 块的中位数
6. 第一笔是 coinbase，且后面没有多余 coinbase
7. 每笔普通交易 `validate_tx` 通过，累加手续费
8. coinbase 总额 ≤ `subsidy(height+1) + 手续费`
9. 全部通过才落账

`validate_tx` 内部也是**两趟扫描**：先查所有输入的存在性与冲突，再验所有签名。如果交错做，一笔「重复输入但没重新签名」的交易会报 `bad signature` 而不是 `input already spent`，把真正的错误藏起来。

### 7.5 P2P 帧

```
"ATL1" (4 字节) | u32 payload_len (小端) | payload
payload[0] = 消息类型码
```

| 码 | 消息 | 载荷 |
|---:|---|---|
| `0x01` | `Version { height: u64, port: u16 }` | 11 字节 |
| `0x02` | `GetBlocks { from: u64 }` | 9 字节 |
| `0x03` | `Blocks(Vec<Block>)` | `u32 n` + n 个自定界的 Block |
| `0x04` | `Tx(Tx)` | 自定界 |
| `0x05` | `Ping` | 1 字节 |
| `0x06` | `Pong` | 1 字节 |

单帧上限 4 MiB；`GetBlocks` 一次最多回 64 块。客户端断线后从 200ms 起指数退避，封顶 2s，永不放弃。

### 7.6 持久化

`blocks.bin`：

```
"ATLDB01" (7) | u32 n | n × ( u32 len | Block::enc() )
```

先写 `blocks.bin.tmp` → `sync_all()` → `rename` 覆盖，保证原子性。加载时校验魔数、比对创世块哈希、再逐块 `add_block` 重放——坏块会在加载阶段就被拒绝。

`mempool.bin` 是**侧车文件**，格式是重复的 `u32 len | Tx::enc()`。删掉它不影响链本身，只是丢掉未确认的交易。

---

## 8. 代码怎么读

按这个顺序读，每一步都只依赖前面读过的内容：

1. **`src/hash.rs`（85 行）** — 先看 SHA-256。标准算法，看完就懂整个哈希基础。
2. **`src/codec.rs`（133 行）** — 编解码原语。没有技巧，纯粹是字节搬运，但后面所有结构都靠它。
3. **`src/chain.rs` 的数据结构部分** — `OutPoint`/`TxIn`/`TxOut`/`Tx`/`Block` 五个结构，配合上面的编码格式看。
4. **`src/chain.rs` 的 `Chain` 部分** — `validate_tx` → `add_block` → `apply`，这是共识的核心。
5. **`src/wallet.rs`（74 行）** — 很短，看它怎么选 UTXO 和找零。
6. **`src/main.rs`（204 行）** — CLI 把所有东西串起来，看一遍就知道模块之间怎么配合。
7. **`src/store.rs` + `src/net.rs` + `src/node.rs`** — 持久化和网络，最后读。
8. **`src/secp.rs`（553 行）** — 最长的文件，但它是**独立的数学库**，不影响理解其它部分。想深挖再加读。

`docs/SPEC.md`（282 行）是写代码前定下的规格书，里面记录了每个函数的精确签名、编码顺序和验收清单。对照着读能看清「设计 → 实现」的对应关系。

---

## 9. 安全边界（务必先读）

**这是一个教学项目。下面每一条都是刻意的简化，请不要用它保管真实资产。**

| 简化 | 后果 |
|---|---|
| 地址用 `sha256(pk)[0..20]`，不是 `RIPEMD160(sha256(pk))` | 为了省掉 RIPEMD160 的实现。地址与比特币地址不兼容，无法复用其生态工具 |
| ECDSA 手写，nonce 是 `sha256("ATL-k"‖sk‖msg)` | 不是标准 RFC6979；没有侧信道加固；未经第三方审计 |
| P2P 是裸 TCP，无加密无认证 | 任何人都能连接、伪造消息源。魔数和长度校验只防误连和畸形帧 |
| 难度调整极简 | 只有窗口式调整 + 幅度钳制，没有检查点 |
| 无脚本系统 | 只有「签名匹配地址」一条规则，没有多签、时间锁、P2PKH 脚本 |
| 内存池不检测池内双花 | 冲突由出块时的 `input already spent` 兜住，先入池者胜 |
| 私钥明文 hex | `newkey` 直接打印到 stdout，无加密无口令 |
| 只接受线性链 | `prev != tip` 直接拒绝，没有分叉重组、没有孤块池 |
| 无 peer 发现 | 只能手动 `--connect` |

**唯一值得夸的**：`grep -rn unsafe src/ tests/` 零命中，全部在 Rust 安全子集内，不会出现内存安全问题。

---

## 10. 测试

```bash
cargo test              # 73 passed
cargo test --release    # 同样 73 passed，约 2.3 秒
```

| 文件 | 测试数 | 覆盖 |
|---|---:|---|
| `src/secp.rs` 内建 | 4 | 域运算、标量运算、曲线点乘、公钥解码（含已知向量） |
| `tests/crypto.rs` | 11 | SHA-256 标准向量、Base58Check 往返与篡改、Merkle 根 |
| `tests/chain.rs` | 25 | 编解码往返、8 条拒绝路径、减半表、难度调整边界、UTXO 记账 |
| `tests/wallet.rs` | 12 | 密钥派生确定性、选币与找零、余额不足、签名验证 |
| `tests/net.rs` | 10 | 6 种消息编解码、帧拆分与合并、超长帧拒绝、畸形帧 |
| `tests/e2e.rs` | 11 | 真实二进制跑完整流程、双节点同步、错误退出码 |
| **合计** | **73** | |

**测试没有覆盖的地方**（诚实声明，别当成已验证）：真实的 2016 块难度调整端到端、真实挖到 210000 块验证减半切换、3 节点拓扑与分叉重组、`Blocks` 单批 64 块上限的跨批场景、`blocks.bin`/`mempool.bin` 损坏时的行为、并发压测。

---

## 11. 环境注意事项

这几条是在 Windows + MSYS bash 下实测踩到的坑，Linux/macOS 上大概率用不到。

1. **测试临时目录用 `CARGO_TARGET_TMPDIR`，不要用 `%TEMP%`。** 某些受限环境里，cargo 构建出的可执行文件带 Low integrity 标签，其子进程无法向 Medium IL 的 `C:\Users\<用户>\AppData\Local\Temp` 写入，`create_dir_all` 直接返回 `os error 5`（拒绝访问）。`tests/e2e.rs` 因此统一用 `env!("CARGO_TARGET_TMPDIR")`（解析到 `<repo>/target/tmp`）。
2. **不要给 cargo 传 `TMP=` / `TEMP=` 覆盖。** 覆盖后 MSVC linker 会报 `LNK1104`，构建直接失败。
3. **`ATL_BITS` 会改变创世哈希。** 跨进程混用不同 `ATL_BITS` 会得到 `error: no chain in <dir> (genesis mismatch ...)`。
4. **MSYS bash 下 `taskkill` 的斜杠会被路径转换破坏。** `taskkill //F //IM x.exe` 报 `Invalid argument/option - '//F'`；改用单横线形式 `taskkill -F -IM x.exe`，或 `MSYS2_ARG_CONV_EXCL='*' taskkill /F /IM x.exe`。
5. **e2e 的节点子进程必须回收**，否则残留进程会占端口，并锁住 `target/release/blockchain.exe` 导致下次构建报 `os error 5`。`tests/e2e.rs` 用 `Drop` 包住 `kill()` + `wait()`。

---

## 12. 许可

MIT。见 [LICENSE](LICENSE)。

**仅供学习与实验。教学用途，勿用于生产环境，勿用于保管有价值的资产。** 作者不对由此产生的任何损失负责。

---

<a name="english"></a>
# ATL-Chain · A blockchain written from scratch in pure Rust

[中文](#atl-chain--一条用纯-rust-手写的区块链) | **English**

> A **zero-dependency**, **`std`-only**, **`unsafe`-free** educational cryptocurrency in **1730 lines**.
> Hand-written SHA-256 and secp256k1, UTXO ledger, proof-of-work consensus, TCP peer-to-peer sync,
> and a command-line wallet.

`cargo build` is a single 2.6-second pass. `cargo test` runs **73 green tests**.
The `[dependencies]` section is empty — no `rand`, no `serde`, no `tokio`, no `bitcoin` crate.

---

## Table of contents

- [1. Who this is for](#1-who-this-is-for)
- [2. Running it in thirty seconds](#2-running-it-in-thirty-seconds)
- [3. What it actually contains](#3-what-it-actually-contains)
- [4. Architecture: what a blockchain is made of](#4-architecture-what-a-blockchain-is-made-of)
- [5. Core concepts in plain language](#5-core-concepts-in-plain-language)
- [6. Command reference](#6-command-reference)
- [7. Data formats and wire protocol](#7-data-formats-and-wire-protocol)
- [8. How to read the code](#8-how-to-read-the-code)
- [9. Security boundaries (read this first)](#9-security-boundaries-read-this-first)
- [10. Tests](#10-tests)
- [11. Platform notes](#11-platform-notes)
- [12. License](#12-license)

---

## 1. Who this is for

You have probably tried to read Bitcoin or Ethereum source code and drowned — build scripts, async runtimes, thousands of dependencies, layers of abstraction — and still could not say what actually happens to a transaction between signing it and getting it mined.

This project attacks that problem directly. It compresses a blockchain into the smallest thing that still works:

- **No third-party crates.** Hashing, elliptic curves, serialization, network framing, hex encoding — all hand-written.
- **No macro magic.** No proc macros, no `build.rs`, no generated code.
- **No async.** P2P is `std::net::TcpStream` plus threads. You can `println!` anywhere and it means what you think.
- **No `unsafe`.** `grep -rn unsafe src/` returns nothing. Everything lives in Rust's safe subset.

The price is that it is **not a production blockchain**. [Section 9](#9-security-boundaries-read-this-first) lists every deliberate simplification. Treat it as compilable, runnable, modifiable teaching material — not a system to store money in.

---

## 2. Running it in thirty seconds

Rust 1.70+ required (tested on `rustc 1.99.1`). No network access needed.

```bash
git clone <this-repo> && cd atl-chain
cargo build --release
```

The artifact is `target/release/blockchain` (`blockchain.exe` on Windows), referred to as `$B` below.

A complete "create → mine → transfer → confirm" cycle:

```bash
$ export ATL_BITS=207fffff      # trivial difficulty for demos, see the note below
$ B=./target/release/blockchain

$ $B init --dir demo
init ok 6ee30f47a8d38212fae8507b5b45de8206781bb26e724b4e1b8e11c62e2ee804

$ $B newkey --seed 00000000000000000000000000000000000000000000000000000000000000aa
sk 95136c684a7ede3d44f82867e0787fd9f92073f7906dcf15629859722b316cf0
pk 031855adce80268fa6dd9e81a2822d253bc606658380e3d26ed15657ff6d9d5b49
addr 1fdf5b79c0ff43ffc33847d3b6e8f0252de12721

$ $B newkey --seed 00000000000000000000000000000000000000000000000000000000000000bb
sk cfc3fdee2b94273e088b3b6b2a778822b538543ad6ce183d1f8982345c5696ba
pk 03699b4591f68836569a41d1f270147d96fdc6fb7588ca98d921fd9fd6e5936601
addr 1afb2f619116e0b4c0b5ae853e5192f3105257a1

# Mine a block; the 50-coin reward goes to alice (1 coin = 100_000_000 satoshi)
$ $B mine --dir demo --addr 1fdf5b79c0ff43ffc33847d3b6e8f0252de12721
mined 1 21183d4ab2ae46c18dc7740905069b0bb973142133e4eb22450f3a3d1eab009c

$ $B balance --dir demo --addr 1fdf5b79c0ff43ffc33847d3b6e8f0252de12721
balance 1fdf5b79c0ff43ffc33847d3b6e8f0252de12721 5000000000

# Send 1.5 coins to bob with a 1000-satoshi fee
$ $B send --dir demo \
    --key 95136c684a7ede3d44f82867e0787fd9f92073f7906dcf15629859722b316cf0 \
    --to 1afb2f619116e0b4c0b5ae853e5192f3105257a1 \
    --amount 150000000 --fee 1000
8ffb515b59fa7d7235a7a9b0e44a6010b17becf4b0e290f8725baafc7985d054

# send only broadcasts the transaction; it does not mine. Wait for the next block:
$ $B info --dir demo | head -1
height 1                          # still 1 — the transaction is in the mempool

$ $B mine --dir demo --addr 1fdf5b79c0ff43ffc33847d3b6e8f0252de12721
mined 2 412836f2df754698bfb838a9215ee6151db0761a315833ff5b9f2e125b170e57

$ $B balance --dir demo --addr 1fdf5b79c0ff43ffc33847d3b6e8f0252de12721
balance 1fdf5b79c0ff43ffc33847d3b6e8f0252de12721 9850000000
$ $B balance --dir demo --addr 1afb2f619116e0b4c0b5ae853e5192f3105257a1
balance 1afb2f619116e0b4c0b5ae853e5192f3105257a1 150000000
```

The arithmetic checks out: alice mines one block for 50 coins (5_000_000_000 sat), spends 1.5 coins (150_000_000) plus a 1000-satoshi fee, then mines a second block worth 50 coins plus the reclaimed fee. Final balance: `5e9 - 1.5e8 - 1000 + 5e9 + 1000 = 9850000000`.

> **About `ATL_BITS=207fffff`**: this environment variable sets the genesis difficulty target. The default `0x1f0fffff` needs roughly 4096 hashes — already "instant" for demos; `207fffff` lets almost any nonce through, which is faster still. It **feeds into the genesis hash**, so it must match across processes or loading a chain fails with `genesis mismatch`.
>
> **Which outputs are reproducible byte-for-byte?** The `init ok` hash, the three `newkey` lines, `balance`, and `info`'s `height`/`utxos`. **Not the `mined` block hashes or the `send` txid** — both hash a real system timestamp into their contents (block time is `max(now, tip_time + 1)`, transaction time is `now`), so every run differs. The amounts and heights are fully reproducible.

Two nodes syncing:

```bash
# Terminal A
$ $B init --dir n1
$ $B node --dir n1 --port 33501 --mine 1fdf5b79c0ff43ffc33847d3b6e8f0252de12721 --interval 1
[node] listening 127.0.0.1:33501
[node] mined 1 21bfa1ff5eb6c295c122b53cd2da5453ae945d48bcefad50d2f5d82bf907966e
[node] mined 2 5966eab98a5570962df580f43a87373a091ab3019a5f3b31ff20bbc2b38f5960

# Terminal B
$ $B init --dir n2
$ $B node --dir n2 --port 33502 --connect 127.0.0.1:33501
[node] listening 127.0.0.1:33502
[node] peer 127.0.0.1:33501 up
[node] block 1 21bfa1ff5eb6c295c122b53cd2da5453ae945d48bcefad50d2f5d82bf907966e
[node] block 2 5966eab98a5570962df580f43a87373a091ab3019a5f3b31ff20bbc2b38f5960
```

The hashes match exactly — B genuinely received A's blocks and re-validated them.

---

## 3. What it actually contains

| Capability | Where | Notes |
|---|---|---|
| SHA-256 / SHA-256d | `src/hash.rs` | Standard K table plus compression function, written out |
| Merkle root | `src/hash.rs` | Duplicates the last leaf on odd counts, as Bitcoin does |
| secp256k1 field arithmetic | `src/secp.rs` | 4×`u64` little-endian limbs, `2^256 ≡ 0x1000003D1` folding |
| ECDSA sign/verify | `src/secp.rs` | Deterministic nonce, low-S normalization, Jacobian coordinates |
| Address derivation | `src/secp.rs` | `sha256(pk)[0..20]`, 33-byte compressed public keys |
| Binary codec | `src/codec.rs` | Little-endian ints, `u32` length prefixes, hex, Base58Check |
| Transactions (UTXO) | `src/chain.rs` | Multiple inputs/outputs, per-input signatures, fee = in − out |
| Blocks and chain | `src/chain.rs` | Hash pointers, Merkle root, median-time validation |
| PoW and difficulty | `src/chain.rs` | Compact `bits` target, retarget every 2016 blocks, clamped |
| Block subsidy halving | `src/chain.rs` | Halves every 210_000 blocks, starting at 50 coins |
| Mempool | `src/chain.rs` | Admission checks, conflict filtering, cleanup after mining |
| Wallet | `src/wallet.rs` | Seed-derived keys, UTXO selection, change output |
| Persistence | `src/store.rs` | `blocks.bin` via temp file plus atomic `rename` |
| P2P protocol | `src/net.rs` | `ATL1` magic framing, 6 message types |
| Node loop | `src/node.rs` | Handshake, batched sync, relay, mining, reconnect |
| Command line | `src/main.rs` | 6 subcommands with strict argument validation |

---

## 4. Architecture: what a blockchain is made of

Dependencies flow one way, with **no cycles**. `chain.rs` is the hub every business module depends on.

```
                    ┌──────────────────┐
                    │    src/main.rs   │  CLI entry point (the only [[bin]])
                    └────────┬─────────┘
        ┌──────────────┬─────┴─────┬──────────────┐
        ▼              ▼           ▼              ▼
  ┌──────────┐  ┌──────────┐ ┌──────────┐  ┌──────────┐
  │src/wallet│  │ src/node │ │src/store │  │  src/net │
  └────┬─────┘  └────┬─────┘ └────┬─────┘  └────┬─────┘
       │             └─────┬──────┘             │
       └──────────┬────────┴────────────────────┘
                  ▼
          ┌──────────────┐
          │  src/chain   │   ← ledger and consensus, the centre of the project
          └──────┬───────┘
                 ▼
       ┌─────────┴──────────┬──────────────┐
       ▼                    ▼              ▼
 ┌──────────┐        ┌──────────┐    ┌──────────┐
 │src/wallet│        │src/codec │    │  src/hash│
 └──────────┘        └──────────┘    └────┬─────┘
                                          ▼
                                    ┌──────────┐
                                    │ src/secp │   the bottom layer: mathematics
                                    └──────────┘
```

| File | Lines | Responsibility |
|---|---:|---|
| `src/secp.rs` | 553 | Finite fields, scalar arithmetic, curve points, ECDSA |
| `src/chain.rs` | 305 | Transactions, blocks, chain, mempool, consensus rules |
| `src/main.rs` | 204 | CLI |
| `src/node.rs` | 203 | Node main loop |
| `src/codec.rs` | 133 | Encoding primitives |
| `src/net.rs` | 104 | Framing and messages |
| `src/hash.rs` | 85 | SHA-256 family |
| `src/wallet.rs` | 74 | Keys and coin selection |
| `src/store.rs` | 59 | Persistence |
| `src/lib.rs` | 10 | `pub mod` declarations |
| **Total** | **1730** | |

---

## 5. Core concepts in plain language

No code here — just why a blockchain holds together. Skip it if you already know the material.

### 5.1 Money is not a balance; it is a pile of unspent receipts

Banks track account balances. Bitcoin-style systems do not. They track **where each coin came from**.

Picture a receipt: "paid 50 coins to Alice." As long as it has not been spent, it is an **UTXO** (Unspent Transaction Output). Your "balance" is the sum of every receipt in your name — no single field stores that number.

To pay someone, you consume receipts as inputs and mint new ones as outputs:

```
input:  Alice's 50-coin receipt   (destroyed, marked spent)
output: Bob 1.5-coin receipt  +  Alice 48.5-coin change receipt
```

That is why `balance()` here is a **linear scan and sum**, not a table lookup.

The benefit: every coin is either spent or unspent, which makes **double-spending structurally impossible** — the same receipt cannot be used twice because the first spend removes it from the UTXO set. The cost is that the ledger grows over time and needs compaction (Bitcoin snapshots the UTXO set; this project does not).

### 5.2 A block is one page of the ledger; the hash is the staple

Each block holds a batch of transactions plus the hash of the previous block. Change anything on a page and its hash changes, so the next page's "previous hash" no longer matches — you would have to rewrite every page after it, re-mining each one.

```
block 0 (genesis) ← block 1 ← block 2 ← block 3
    prev=0           prev=H(0)  prev=H(1)  prev=H(2)
```

`Block::hash()` is `sha256d(header)`, where the header is only 48 bytes: `prev(32) | time(8) | bits(4) | nonce(4)`. Note that **transactions are not in the header** — they appear as a Merkle root. `merkle()` hashes transaction ids pairwise until one root remains, then that root goes into the header. Changing the header alone therefore commits to the whole block's contents.

### 5.3 Mining: push the hash below a threshold

`bits` is a compact encoding of a difficulty target. For example `0x1f0fffff` decodes to `0x0fffff << (8*(0x1f-3))`, a 256-bit integer. A block is valid when:

```
sha256d(header) < target
```

Hashes look random, so the only strategy is to try nonces until one lands low enough. That is proof-of-work: **its only job is to make rewriting history expensive**. To alter a block ten deep, you must redo ten blocks of work while outrunning everyone else.

Difficulty retargets every 2016 blocks to keep the block interval near 60 seconds:

```
observed span = clamp(last_time − time_2016_blocks_ago, expected/4, expected×4)
new target    = old target × span / expected
```

The `clamp` is the anti-attack part: without it, an attacker could forge an extreme timestamp and crater the difficulty in one step. This project clamps to `[expected/4, expected×4]`, same idea as Bitcoin.

### 5.4 Signatures: prove you may spend it, without revealing the key

You hold a private key `sk` (32 random bytes). It yields a public key `pk = sk·G` (a curve multiplication), and the address is the first 20 bytes of `sha256(pk)`.

To sign, hash the transaction into a 256-bit number `h` and compute `(r, s)`, 64 bytes total. A verifier with `pk`, `h` and `(r, s)` runs a few curve operations and decides whether `sk` signed `h` — **without being able to recover `sk`**.

Every transaction input carries its own signature and public key. The rule is: `addr(pk)` must equal the address on the UTXO being spent, and the signature must verify.

`src/secp.rs` is the longest file because it genuinely implements 256-bit modular arithmetic:

- Four `u64` limbs represent a big number (little-endian); add, subtract, multiply and compare are all hand-written carry/borrow code.
- After a modular multiply the result is "folded": since `2^256 ≡ 0x1000003D1 (mod p)`, the part above 256 bits gets multiplied by that constant and added back.
- Modular inverse uses the **binary extended GCD**, far faster than a Fermat little-theorem exponentiation (measured: 6.8 seconds down to milliseconds).
- Scalar multiplication uses Jacobian projective coordinates to avoid a division (inversion) at every step.

The per-signature nonce `k` must never repeat — a repeat leaks the private key. Convention is to use a random number; this project derives it deterministically:

```
k = sha256("ATL-k" || sk || msg)
```

The idea comes from RFC6979, but this is **not** a standard RFC6979 implementation. The upside is needing no randomness; the downside is no side-channel hardening.

### 5.5 Networking in three sentences

1. On connect, both sides send `Version { height, port }` to exchange chain heights.
2. Whoever sees a taller peer sends `GetBlocks { from: peer_height+1 }`; the peer replies with `Blocks(up to 64)`; repeat until caught up.
3. Every received block goes through `add_block` validation (does `prev` match? is the Merkle root right? is the difficulty right? is the PoW valid? is the timestamp sane? are all transactions valid? does the coinbase overpay?). If it passes, it is persisted and relayed to other peers.

There is no consensus algorithm (PoW *is* the consensus), no fork choice (only `prev == tip` is accepted), and no peer discovery (manual `--connect`).

---

## 6. Command reference

```
blockchain {init|info|balance|newkey|mine|send|node} [flags]
```

| Command | Flags | Output |
|---|---|---|
| `newkey` | `--seed <hex32>` `--index <n>` | Three lines: `sk <64hex>` / `pk <66hex>` / `addr <40hex>` |
| `init` | `--dir <path>` | `init ok <genesis_hash>` |
| `info` | `--dir <path>` | Four lines: `height` / `tip` / `bits` / `utxos` |
| `balance` | `--dir` `--addr <40hex>` | `balance <40hex> <satoshis>` |
| `mine` | `--dir` `--addr` `--tx <hex>` (repeatable) | `mined <height> <block_hash>` |
| `send` | `--dir` `--key <64hex>` `--to` `--amount` `--fee` `--peer` | `<txid>` |
| `node` | `--dir` `--port` `--connect` (repeatable) `--mine` `--interval` | Continuous `[node] ...` logs |

A few conventions:

- **Amounts are always satoshis**; `1 coin = 100_000_000`. So `--amount 150000000` is 1.5 coins.
- With `--seed` the key is fully deterministic (`Key::from_seed(seed, index)`); otherwise it derives from system time plus pid and cannot be reproduced.
- `send` **does not mine**. It writes the transaction to the sidecar mempool file `mempool.bin` and prints the txid; the transaction takes effect once `mine` or `node` packages it.
- `--tx` takes the hex of `Tx::enc()`, **not** a txid.
- Argument parsing is **strict**: unknown `--flag`, a flag missing its value, or an extra positional argument all fail loudly rather than being silently ignored.

Errors always go to stderr with exit code 1:

```bash
$ $B init --dir demo
error: already initialized
$ $B balance --dir nope --addr 1fdf...
error: no chain in nope (The system cannot find the path specified. (os error 3))
$ $B send --dir demo --key ... --to ... --amount 99999999999999
error: insufficient funds: have 9850000000, need 99999999999999
```

---

## 7. Data formats and wire protocol

### 7.1 Encoding conventions

- All integers are **little-endian**.
- Hashes, public keys and signatures are stored big-endian as-is (the byte order `sha256` outputs is the "displayed hash").
- Variable-length fields use a `u32` length prefix.
- Addresses are a raw 20-byte value rendered as 40 hex characters (not Base58; `codec.rs` implements Base58Check but the CLI does not use it).

### 7.2 Transactions

```
Tx = time: i64            (8, little-endian)
   | u32 n_in
   | n_in × ( prev_txid: 32 | prev_idx: u32 | u32 sig_len | sig | u32 pk_len | pk )
   | u32 n_out
   | n_out × ( value: u64 | addr: 20 )
```

The txid is `sha256d(full encoding)`. When signing, input `i`'s own `sig` and `pk` are **cleared** before hashing (`signing_hash(i)`), so the signature cannot cover itself.

A coinbase transaction is special: exactly one input, `prev = ([0;32], 0xffff_ffff)`, empty `sig` and `pk`.

### 7.3 Blocks

```
header = prev: 32 | time: i64 | bits: u32 | nonce: u32        (48 bytes)
block  = header | u32 n_tx | n_tx × Tx::enc()
```

The block hash is `sha256d(header)`. `bits` decodes to a target as:

```
target = mantissa << (8 × (exponent − 3))
```

### 7.4 `add_block` validation order

Order matters, otherwise error messages mask each other:

1. `prev == tip` (no forks accepted)
2. Merkle root is correct
3. `bits == next_bits(chain)` (difficulty follows the rules)
4. Proof-of-work meets the target
5. Timestamp exceeds the median of the last 11 blocks
6. First transaction is a coinbase, and there are no extra coinbases
7. Every ordinary transaction passes `validate_tx`; fees accumulate
8. Coinbase total ≤ `subsidy(height+1) + fees`
9. Only then is state applied

`validate_tx` itself does **two passes**: first check every input's existence and conflicts, then verify every signature. Interleaving them means a transaction that repeats an input without re-signing reports `bad signature` instead of `input already spent`, hiding the real error.

### 7.5 P2P framing

```
"ATL1" (4 bytes) | u32 payload_len (little-endian) | payload
payload[0] = message type code
```

| Code | Message | Payload |
|---:|---|---|
| `0x01` | `Version { height: u64, port: u16 }` | 11 bytes |
| `0x02` | `GetBlocks { from: u64 }` | 9 bytes |
| `0x03` | `Blocks(Vec<Block>)` | `u32 n` plus n self-delimiting blocks |
| `0x04` | `Tx(Tx)` | self-delimiting |
| `0x05` | `Ping` | 1 byte |
| `0x06` | `Pong` | 1 byte |

Frames cap at 4 MiB; `GetBlocks` returns at most 64 blocks per batch. A disconnected client retries with exponential backoff from 200 ms, capped at 2 s, never giving up.

### 7.6 Persistence

`blocks.bin`:

```
"ATLDB01" (7) | u32 n | n × ( u32 len | Block::enc() )
```

The writer goes to `blocks.bin.tmp` → `sync_all()` → `rename`, which is atomic. Loading checks the magic, compares the genesis hash, then replays each block through `add_block` — a bad block is rejected at load time.

`mempool.bin` is a **sidecar file** containing repeated `u32 len | Tx::enc()`. Deleting it does not affect the chain; it only discards unconfirmed transactions.

---

## 8. How to read the code

Read in this order; each step depends only on what came before.

1. **`src/hash.rs` (85 lines)** — Start with SHA-256. Standard algorithm; once it clicks, the hashing foundation is done.
2. **`src/codec.rs` (133 lines)** — Encoding primitives. No cleverness, just byte shuffling, but every structure below relies on it.
3. **`src/chain.rs`, the data structures** — `OutPoint`/`TxIn`/`TxOut`/`Tx`/`Block`, read alongside the encoding format above.
4. **`src/chain.rs`, the `Chain` type** — `validate_tx` → `add_block` → `apply` is the heart of consensus.
5. **`src/wallet.rs` (74 lines)** — Short. See how it picks UTXOs and produces change.
6. **`src/main.rs` (204 lines)** — The CLI wires everything together; one pass shows how the modules cooperate.
7. **`src/store.rs` + `src/net.rs` + `src/node.rs`** — Persistence and networking, last.
8. **`src/secp.rs` (553 lines)** — The longest file, but it is a **self-contained math library** that you do not need in order to understand the rest. Dig in later.

`docs/SPEC.md` (282 lines) is the specification written before the code, recording exact signatures, encoding orders and acceptance checklists. Reading the two side by side makes the design-to-implementation mapping visible.

---

## 9. Security boundaries (read this first)

**This is a teaching project. Every item below is a deliberate simplification. Do not store real assets with it.**

| Simplification | Consequence |
|---|---|
| Addresses are `sha256(pk)[0..20]`, not `RIPEMD160(sha256(pk))` | Saves implementing RIPEMD160. Incompatible with Bitcoin addresses and tooling |
| Hand-written ECDSA, nonce is `sha256("ATL-k"‖sk‖msg)` | Not standard RFC6979; no side-channel hardening; unaudited |
| P2P is raw TCP, no encryption or authentication | Anyone can connect and forge message sources. Magic and length checks only catch accidents and malformed frames |
| Minimal difficulty adjustment | Windowed retarget plus clamping only; no checkpoints |
| No scripting system | Only "signature matches address" — no multisig, timelocks, or P2PKH scripts |
| Mempool does not detect intra-pool double spends | Conflicts are caught at block time by `input already spent`; first-in wins |
| Private keys are plain hex | `newkey` prints to stdout; no encryption, no passphrase |
| Linear chain only | `prev != tip` is rejected outright: no reorgs, no orphan pool |
| No peer discovery | Manual `--connect` only |

**The one thing worth bragging about**: `grep -rn unsafe src/ tests/` returns zero hits. Everything is in Rust's safe subset, so memory-safety bugs are off the table.

---

## 10. Tests

```bash
cargo test              # 73 passed
cargo test --release    # 73 passed again, about 2.3 seconds
```

| File | Tests | Coverage |
|---|---:|---|
| built into `src/secp.rs` | 4 | Field arithmetic, scalar arithmetic, curve multiplication, key decoding (with known vectors) |
| `tests/crypto.rs` | 11 | SHA-256 standard vectors, Base58Check round-trip and tampering, Merkle roots |
| `tests/chain.rs` | 25 | Codec round-trips, 8 rejection paths, halving table, difficulty boundaries, UTXO accounting |
| `tests/wallet.rs` | 12 | Deterministic key derivation, coin selection and change, insufficient funds, signature checks |
| `tests/net.rs` | 10 | All 6 message codecs, frame splitting and coalescing, oversize rejection, malformed frames |
| `tests/e2e.rs` | 11 | The real binary through full flows, two-node sync, error exit codes |
| **Total** | **73** | |

**What the tests do not cover** (stated honestly, not verified): a full end-to-end 2016-block retarget, actually mining to height 210_000 to observe a halving, three-node topologies and reorgs, the 64-block batch limit across multiple batches, corrupted `blocks.bin`/`mempool.bin` behaviour, and concurrency stress.

---

## 11. Platform notes

These were hit on Windows with MSYS bash; Linux and macOS will likely never see them.

1. **Use `CARGO_TARGET_TMPDIR` for test temp dirs, not `%TEMP%`.** In some restricted environments, binaries built by cargo carry a Low integrity label, and their child processes cannot write to the Medium-IL `C:\Users\<user>\AppData\Local\Temp`; `create_dir_all` returns `os error 5` (access denied). `tests/e2e.rs` therefore uses `env!("CARGO_TARGET_TMPDIR")`, which resolves to `<repo>/target/tmp`.
2. **Do not override `TMP=` / `TEMP=` when invoking cargo.** The MSVC linker then fails with `LNK1104`.
3. **`ATL_BITS` changes the genesis hash.** Mixing different `ATL_BITS` values across processes yields `error: no chain in <dir> (genesis mismatch ...)`.
4. **MSYS bash mangles the slashes in `taskkill`.** `taskkill //F //IM x.exe` reports `Invalid argument/option - '//F'`; use the single-dash form `taskkill -F -IM x.exe`, or `MSYS2_ARG_CONV_EXCL='*' taskkill /F /IM x.exe`.
5. **Reap the e2e node subprocesses.** A leftover process holds the port and locks `target/release/blockchain.exe`, making the next build fail with `os error 5`. `tests/e2e.rs` guards them with a `Drop` impl calling `kill()` + `wait()`.

---

## 12. License

MIT. See [LICENSE](LICENSE).

**For learning and experimentation only. Not for production, and not for holding anything of value.** The author accepts no liability for any losses.
