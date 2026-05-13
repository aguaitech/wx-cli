pub mod wal;

use aes::Aes256;
use anyhow::{bail, Context, Result};
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use cbc::Decryptor;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac_array;
use sha1::Sha1;
use std::io::{Read, Write};
use std::path::Path;

type Block = aes::cipher::Block<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;
type HmacSha1 = Hmac<Sha1>;

pub const SQLITE_HDR: &[u8; 16] = b"SQLite format 3\x00";
pub const FILE_HEADER_SZ: usize = 16;
pub const SQLCIPHER3_HMAC_LEN: usize = 20;
pub const SQLCIPHER3_HMAC_SALT_MASK: u8 = 0x3a;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyMode {
    Raw,
    Pbkdf2Sha1,
}

#[derive(Debug, Clone, Copy)]
pub struct DbCryptoParams {
    pub page_size: usize,
    pub reserve_size: usize,
    pub key_mode: KeyMode,
}

const CANDIDATES_3X: [DbCryptoParams; 4] = [
    DbCryptoParams {
        page_size: 1024,
        reserve_size: 48,
        key_mode: KeyMode::Raw,
    },
    DbCryptoParams {
        page_size: 4096,
        reserve_size: 48,
        key_mode: KeyMode::Raw,
    },
    DbCryptoParams {
        page_size: 1024,
        reserve_size: 48,
        key_mode: KeyMode::Pbkdf2Sha1,
    },
    DbCryptoParams {
        page_size: 4096,
        reserve_size: 48,
        key_mode: KeyMode::Pbkdf2Sha1,
    },
];

pub fn detect_params_and_key(
    db_path: &Path,
    raw_key: &[u8; 32],
) -> Result<(DbCryptoParams, [u8; 32])> {
    let file_size = std::fs::metadata(db_path)?.len() as usize;
    if file_size < 64 {
        bail!("数据库文件过小: {}", db_path.display());
    }

    let max_page = CANDIDATES_3X
        .iter()
        .map(|c| c.page_size)
        .max()
        .unwrap_or(4096);
    let mut first = vec![0u8; max_page];
    let mut f = std::fs::File::open(db_path)?;
    let n = f.read(&mut first)?;
    first.truncate(n);

    if first.len() >= 16 && &first[..16] == SQLITE_HDR {
        return Ok((
            DbCryptoParams {
                page_size: 1024,
                reserve_size: 0,
                key_mode: KeyMode::Raw,
            },
            *raw_key,
        ));
    }

    for params in CANDIDATES_3X {
        if first.len() < params.page_size {
            continue;
        }
        let enc_key = derive_db_key_from_salt(raw_key, &first[..16], params);
        if verify_hmac_page1(&first[..params.page_size], &enc_key, params)? {
            return Ok((params, enc_key));
        }
    }

    bail!("未能识别数据库加密参数: {}", db_path.display())
}

fn derive_db_key_from_salt(raw_key: &[u8; 32], salt: &[u8], params: DbCryptoParams) -> [u8; 32] {
    match params.key_mode {
        KeyMode::Raw => *raw_key,
        KeyMode::Pbkdf2Sha1 => pbkdf2_hmac_array::<Sha1, 32>(raw_key, salt, 64_000),
    }
}

fn verify_hmac_page1(page_data: &[u8], enc_key: &[u8; 32], params: DbCryptoParams) -> Result<bool> {
    verify_page_hmac(page_data, &page_data[..FILE_HEADER_SZ], enc_key, params, 1)
}

fn derive_hmac_key(enc_key: &[u8; 32], salt: &[u8]) -> [u8; 32] {
    let mac_salt: Vec<u8> = salt
        .iter()
        .map(|b| b ^ SQLCIPHER3_HMAC_SALT_MASK)
        .collect();
    pbkdf2_hmac_array::<Sha1, 32>(enc_key, &mac_salt, 2)
}

pub fn verify_page_hmac(
    page_data: &[u8],
    db_salt: &[u8],
    enc_key: &[u8; 32],
    params: DbCryptoParams,
    pgno: u32,
) -> Result<bool> {
    if params.reserve_size < (16 + SQLCIPHER3_HMAC_LEN) || page_data.len() < params.page_size {
        return Ok(false);
    }
    if db_salt.len() < FILE_HEADER_SZ {
        return Ok(false);
    }

    let mac_key = derive_hmac_key(enc_key, &db_salt[..FILE_HEADER_SZ]);
    let iv_start = params.page_size - params.reserve_size;
    let iv_end = iv_start + 16;
    let hmac_end = iv_end + SQLCIPHER3_HMAC_LEN;
    if hmac_end > page_data.len() {
        return Ok(false);
    }

    let hmac_input = if pgno == 1 {
        &page_data[FILE_HEADER_SZ..iv_end]
    } else {
        &page_data[..iv_end]
    };
    let stored_hmac = &page_data[iv_end..hmac_end];

    let mut mac = HmacSha1::new_from_slice(&mac_key).expect("32-byte HMAC key");
    mac.update(hmac_input);
    mac.update(&pgno.to_le_bytes());
    let calc = mac.finalize().into_bytes();

    Ok(calc.as_slice() == stored_hmac)
}

pub fn decrypt_page(
    enc_key: &[u8; 32],
    page_data: &[u8],
    pgno: u32,
    params: DbCryptoParams,
) -> Result<Vec<u8>> {
    if page_data.len() < params.page_size {
        bail!("页面数据不足 {} 字节", params.page_size);
    }
    if params.reserve_size == 0 {
        return Ok(page_data[..params.page_size].to_vec());
    }

    let iv_offset = params.page_size - params.reserve_size;
    let iv: &[u8; 16] = page_data[iv_offset..iv_offset + 16]
        .try_into()
        .expect("IV 长度固定为 16");

    let mut result = vec![0u8; params.page_size];

    if pgno == 1 {
        let enc = &page_data[FILE_HEADER_SZ..params.page_size - params.reserve_size];
        let dec = aes_cbc_decrypt(enc_key, iv, enc)?;
        result[..16].copy_from_slice(SQLITE_HDR);
        result[16..params.page_size - params.reserve_size].copy_from_slice(&dec);
        result[20] = params.reserve_size as u8;
    } else {
        let enc = &page_data[..params.page_size - params.reserve_size];
        let dec = aes_cbc_decrypt(enc_key, iv, enc)?;
        result[..params.page_size - params.reserve_size].copy_from_slice(&dec);
    }

    Ok(result)
}

fn aes_cbc_decrypt(key: &[u8; 32], iv: &[u8; 16], data: &[u8]) -> Result<Vec<u8>> {
    if data.is_empty() || data.len() % 16 != 0 {
        bail!("密文长度不是 AES 块大小的倍数: {}", data.len());
    }
    let mut blocks: Vec<Block> = data.chunks_exact(16).map(Block::clone_from_slice).collect();
    Aes256CbcDec::new(key.into(), iv.into()).decrypt_blocks_mut(&mut blocks);
    Ok(blocks.iter().flat_map(|b| b.iter().copied()).collect())
}

pub fn full_decrypt(
    db_path: &Path,
    out_path: &Path,
    enc_key: &[u8; 32],
    params: DbCryptoParams,
) -> Result<()> {
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    if params.reserve_size == 0 {
        std::fs::copy(db_path, out_path)?;
        return Ok(());
    }

    let mut input = std::fs::File::open(db_path)?;
    let file_size = input.metadata()?.len() as usize;
    if file_size == 0 {
        bail!("数据库文件为空: {}", db_path.display());
    }

    let mut output = std::fs::File::create(out_path)?;
    let total_pages = (file_size + params.page_size - 1) / params.page_size;
    let mut page_buf = vec![0u8; params.page_size];
    let mut db_salt = [0u8; FILE_HEADER_SZ];

    for pgno in 1..=total_pages {
        let n = input.read(&mut page_buf)?;
        if n == 0 {
            break;
        }
        if n < params.page_size {
            page_buf[n..].fill(0);
        }
        if pgno == 1 {
            db_salt.copy_from_slice(&page_buf[..FILE_HEADER_SZ]);
        } else if !verify_page_hmac(&page_buf, &db_salt, enc_key, params, pgno as u32)? {
            bail!("页 {} HMAC 校验失败: {}", pgno, db_path.display());
        }
        let dec = decrypt_page(enc_key, &page_buf, pgno as u32, params)
            .with_context(|| format!("解密页 {} 失败: {}", pgno, db_path.display()))?;
        output.write_all(&dec)?;
    }

    Ok(())
}
