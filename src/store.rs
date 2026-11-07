//! 链持久化：blocks.bin = b"ATLDB01" || u32 n || 每块 `bytes`；tmp + rename 原子写。
use crate::chain::{Block, Chain, GENESIS_ADDR};
use crate::codec::{put_bytes, put_u32, Rd};
use std::fs;
use std::io::{Error, ErrorKind::InvalidData, Result, Write};
use std::path::{Path, PathBuf};

pub const FILE: &str = "blocks.bin";

fn bad(m: &str) -> Error { Error::new(InvalidData, m.to_string()) }

fn path(dir: &str) -> PathBuf { Path::new(dir).join(FILE) }

pub fn exists(dir: &str) -> bool { path(dir).is_file() }

/// 无文件 -> 新链；有文件 -> 校验创世块后逐块重放 add_block（坏块报错）。
pub fn load(dir: &str) -> Result<Chain> {
    let buf = fs::read(path(dir))?;
    if buf.len() < 11 || &buf[..7] != b"ATLDB01" { return Err(bad("bad store magic")); }
    let n = u32::from_le_bytes([buf[7], buf[8], buf[9], buf[10]]);
    let mut r = Rd::new(&buf[11..]);
    let mut c = Chain::new(GENESIS_ADDR);
    for i in 0..n {
        let raw = r.bytes().ok_or_else(|| bad("short block"))?;
        let b = Block::dec(&mut Rd::new(raw)).ok_or_else(|| bad("bad block encoding"))?;
        if i == 0 {
            if b.hash() != c.tip() { return Err(bad("genesis mismatch")); }
        } else {
            c.add_block(&b).map_err(|e| bad(&e))?;
        }
    }
    Ok(c)
}

/// 先写 blocks.bin.tmp 再 rename，保证落盘原子性。
pub fn save(dir: &str, c: &Chain) -> Result<()> {
    let p = path(dir);
    let mut b = Vec::with_capacity(c.blocks.len() * 256 + 11);
    b.extend_from_slice(b"ATLDB01");
    put_u32(&mut b, c.blocks.len() as u32);
    for blk in &c.blocks { put_bytes(&mut b, &blk.enc()); }
    if let Some(d) = p.parent() {
        if !d.as_os_str().is_empty() { fs::create_dir_all(d)?; }
    }
    let tmp = p.with_extension("bin.tmp");
    let mut f = fs::File::create(&tmp)?;
    f.write_all(&b)?;
    f.sync_all()?;
    drop(f);
    fs::rename(&tmp, &p)?;
    Ok(())
}

pub fn load_or_init(dir: &str) -> Result<Chain> {
    if exists(dir) { return load(dir); }
    let c = Chain::new(GENESIS_ADDR);
    save(dir, &c)?;
    Ok(c)
}
