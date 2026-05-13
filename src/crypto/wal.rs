use anyhow::Result;
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

use super::{decrypt_page, verify_page_hmac, DbCryptoParams};

pub const WAL_HDR_SZ: usize = 32;
pub const WAL_FRAME_HDR: usize = 24;
const WAL_MAGIC: u32 = 0x377f0682;

pub fn apply_wal(
    wal_path: &Path,
    out_path: &Path,
    db_salt: &[u8; 16],
    enc_key: &[u8; 32],
    params: DbCryptoParams,
) -> Result<()> {
    if !wal_path.exists() {
        return Ok(());
    }

    let wal_data = std::fs::read(wal_path)?;
    if wal_data.len() <= WAL_HDR_SZ {
        return Ok(());
    }

    let magic = u32::from_be_bytes(wal_data[0..4].try_into().unwrap());
    let wal_page_size = decode_wal_page_size(u32::from_be_bytes(
        wal_data[8..12].try_into().unwrap(),
    )) as usize;
    if (magic & 0xFFFFFFFE) != WAL_MAGIC || wal_page_size == 0 || wal_page_size != params.page_size
    {
        return Ok(());
    }

    let big_end_cksum = (magic & 0x00000001) != 0;
    let native_cksum = big_end_cksum == cfg!(target_endian = "big");
    let mut cksum = [0u32; 2];
    wal_checksum_bytes(native_cksum, &wal_data[..WAL_HDR_SZ - 8], None, &mut cksum);
    let hdr_cksum_1 = u32::from_be_bytes(wal_data[24..28].try_into().unwrap());
    let hdr_cksum_2 = u32::from_be_bytes(wal_data[28..32].try_into().unwrap());
    if cksum[0] != hdr_cksum_1 || cksum[1] != hdr_cksum_2 {
        return Ok(());
    }

    let frame_size = WAL_FRAME_HDR + wal_page_size;
    let frame_area = &wal_data[WAL_HDR_SZ..];

    let salt = &wal_data[16..24];
    let mut pos = 0usize;
    let mut valid_frames: Vec<(u32, u32, Vec<u8>)> = Vec::new();
    let mut last_commit_idx: Option<usize> = None;
    let mut truncate_to_pages: Option<u32> = None;
    while pos + frame_size <= frame_area.len() {
        let fh = &frame_area[pos..pos + WAL_FRAME_HDR];
        let page_data = &frame_area[pos + WAL_FRAME_HDR..pos + frame_size];

        let pgno = u32::from_be_bytes(fh[0..4].try_into().unwrap());
        let n_truncate = u32::from_be_bytes(fh[4..8].try_into().unwrap());

        pos += frame_size;

        if pgno == 0 || pgno > 1_000_000 {
            break;
        }
        if &fh[8..16] != salt {
            break;
        }

        let mut next1 = cksum;
        wal_checksum_bytes(native_cksum, &fh[..8], Some(&cksum), &mut next1);
        let mut next2 = next1;
        wal_checksum_bytes(native_cksum, page_data, Some(&next1), &mut next2);
        let frame_cksum_1 = u32::from_be_bytes(fh[16..20].try_into().unwrap());
        let frame_cksum_2 = u32::from_be_bytes(fh[20..24].try_into().unwrap());
        if next2[0] != frame_cksum_1 || next2[1] != frame_cksum_2 {
            break;
        }
        if !verify_page_hmac(page_data, db_salt, enc_key, params, pgno)? {
            break;
        }
        cksum = next2;
        valid_frames.push((pgno, n_truncate, page_data.to_vec()));
        if n_truncate > 0 {
            last_commit_idx = Some(valid_frames.len() - 1);
            truncate_to_pages = Some(n_truncate);
        }
    }

    let Some(last_commit_idx) = last_commit_idx else {
        return Ok(());
    };

    let mut db_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(out_path)?;

    for (pgno, _n_truncate, mut page_buf) in valid_frames.into_iter().take(last_commit_idx + 1) {
        if page_buf.len() < wal_page_size {
            page_buf.resize(wal_page_size, 0);
        }

        let dec = decrypt_page(enc_key, &page_buf, pgno, params)?;
        let file_offset = (pgno as u64 - 1) * wal_page_size as u64;
        db_file.seek(SeekFrom::Start(file_offset))?;
        db_file.write_all(&dec)?;
    }

    if let Some(n_pages) = truncate_to_pages {
        db_file.set_len(n_pages as u64 * wal_page_size as u64)?;
    }

    Ok(())
}

fn decode_wal_page_size(raw: u32) -> u32 {
    (raw & 0xfe00) + ((raw & 0x0001) << 16)
}

fn wal_checksum_bytes(
    native_cksum: bool,
    bytes: &[u8],
    input: Option<&[u32; 2]>,
    out: &mut [u32; 2],
) {
    let mut s1 = input.map(|v| v[0]).unwrap_or(0);
    let mut s2 = input.map(|v| v[1]).unwrap_or(0);

    for chunk in bytes.chunks_exact(8) {
        let w0 = u32::from_ne_bytes(chunk[0..4].try_into().unwrap());
        let w1 = u32::from_ne_bytes(chunk[4..8].try_into().unwrap());
        let a = if native_cksum { w0 } else { w0.swap_bytes() };
        let b = if native_cksum { w1 } else { w1.swap_bytes() };
        s1 = s1.wrapping_add(a).wrapping_add(s2);
        s2 = s2.wrapping_add(b).wrapping_add(s1);
    }

    out[0] = s1;
    out[1] = s2;
}
