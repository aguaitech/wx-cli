use anyhow::{Context, Result};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::config;
use crate::crypto;
use crate::crypto::wal;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MtimeEntry {
    db_mt: u64,
    wal_mt: u64,
    path: String,
}

#[derive(Debug, Clone)]
struct CacheEntry {
    db_mtime: u64,
    wal_mtime: u64,
    decrypted_path: PathBuf,
}

/// 解密后数据库的 mtime-aware 缓存
///
/// 当数据库文件（.db）或 WAL 文件（.db-wal）的 mtime 发生变化时，
/// 自动重新解密并更新缓存。跨进程重启可通过持久化 mtime 文件复用已解密的 DB。
pub struct DbCache {
    db_dir: PathBuf,
    cache_dir: PathBuf,
    all_keys: HashMap<String, String>, // rel_key -> enc_key(hex)
    inner: Arc<Mutex<HashMap<String, CacheEntry>>>,
}

impl DbCache {
    pub async fn new(db_dir: PathBuf, all_keys: HashMap<String, String>) -> Result<Self> {
        let cache_dir = config::cache_dir();
        tokio::fs::create_dir_all(&cache_dir).await?;

        let inner: HashMap<String, CacheEntry> = HashMap::new();
        let cache = DbCache {
            db_dir,
            cache_dir,
            all_keys,
            inner: Arc::new(Mutex::new(inner)),
        };

        cache.load_persistent().await;
        Ok(cache)
    }

    fn cache_file_path(&self, rel_key: &str) -> PathBuf {
        let hash = format!("{:x}", md5::compute(rel_key.as_bytes()));
        self.cache_dir.join(format!("{}.db", hash))
    }

    fn find_case_insensitive(&self, target: &str) -> Option<String> {
        let target = target.to_ascii_lowercase();
        self.all_keys
            .keys()
            .find(|k| k.to_ascii_lowercase() == target)
            .cloned()
    }

    fn find_with_predicate<F>(&self, pred: F) -> Option<String>
    where
        F: Fn(&str) -> bool,
    {
        self.all_keys.keys().find(|k| pred(k)).cloned()
    }

    fn resolve_rel_key(&self, rel_key: &str) -> Option<String> {
        let requested = rel_key.replace('\\', "/");
        if self.all_keys.contains_key(&requested) {
            return Some(requested);
        }

        let lower = requested.to_ascii_lowercase();
        let alias = match lower.as_str() {
            "session/session.db" => self
                .find_case_insensitive("Session/session_new.db")
                .or_else(|| self.find_case_insensitive("Session/session.db"))
                .or_else(|| {
                    self.find_with_predicate(|k| {
                        let k = k.to_ascii_lowercase();
                        k.starts_with("session/") && k.ends_with(".db")
                    })
                }),
            "contact/contact.db" => self
                .find_case_insensitive("Contact/wccontact_new2.db")
                .or_else(|| self.find_case_insensitive("Contact/wccontact_new.db"))
                .or_else(|| self.find_case_insensitive("Contact/contact.db"))
                .or_else(|| {
                    self.find_with_predicate(|k| {
                        let k = k.to_ascii_lowercase();
                        k.starts_with("contact/") && k.contains("wccontact") && k.ends_with(".db")
                    })
                }),
            "favorite/favorite.db" => self
                .find_case_insensitive("Favorites/favorites.db")
                .or_else(|| self.find_case_insensitive("Favorite/favorite.db"))
                .or_else(|| {
                    self.find_with_predicate(|k| {
                        let k = k.to_ascii_lowercase();
                        k.ends_with("/favorites.db") || k.ends_with("/favorite.db")
                    })
                }),
            "sns/sns.db" => self
                .find_case_insensitive("Sns/sns.db")
                .or_else(|| self.find_case_insensitive("sns/sns.db"))
                .or_else(|| {
                    self.find_with_predicate(|k| {
                        let k = k.to_ascii_lowercase();
                        k.ends_with("/sns.db")
                    })
                }),
            _ => None,
        };

        alias
    }

    /// 从持久化文件加载 mtime 记录，复用未过期的解密文件
    async fn load_persistent(&self) {
        let mtime_file = config::mtime_file();
        let content = match tokio::fs::read_to_string(&mtime_file).await {
            Ok(c) => c,
            Err(_) => return,
        };
        let saved: HashMap<String, MtimeEntry> = match serde_json::from_str(&content) {
            Ok(v) => v,
            Err(_) => return,
        };

        let mut inner = self.inner.lock().await;
        let mut reused = 0usize;
        for (rel_key, entry) in &saved {
            let dec_path = PathBuf::from(&entry.path);
            if !dec_path.exists() {
                continue;
            }
            if !looks_like_sqlite(&dec_path) {
                continue;
            }
            let db_path = self.db_dir.join(
                rel_key
                    .replace('\\', std::path::MAIN_SEPARATOR_STR)
                    .replace('/', std::path::MAIN_SEPARATOR_STR),
            );
            let wal_path = wal_path_for(&db_path);

            let db_mt = mtime_nanos(&db_path);
            let wal_mt = if wal_path.exists() {
                mtime_nanos(&wal_path)
            } else {
                0
            };

            if db_mt == entry.db_mt && wal_mt == entry.wal_mt {
                inner.insert(
                    rel_key.clone(),
                    CacheEntry {
                        db_mtime: db_mt,
                        wal_mtime: wal_mt,
                        decrypted_path: dec_path,
                    },
                );
                reused += 1;
            }
        }
        if reused > 0 {
            eprintln!("[cache] 复用 {} 个已解密 DB", reused);
        }
    }

    /// 持久化 mtime 记录
    async fn save_persistent(&self) {
        let mtime_file = config::mtime_file();
        let inner = self.inner.lock().await;
        let data: HashMap<String, MtimeEntry> = inner
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    MtimeEntry {
                        db_mt: v.db_mtime,
                        wal_mt: v.wal_mtime,
                        path: v.decrypted_path.to_string_lossy().into_owned(),
                    },
                )
            })
            .collect();
        drop(inner);

        if let Ok(json) = serde_json::to_string_pretty(&data) {
            let _ = tokio::fs::write(&mtime_file, json).await;
        }
    }

    /// 获取解密后的数据库路径
    ///
    /// 如果 mtime 未变，直接返回缓存路径；否则重新解密
    pub async fn get(&self, rel_key: &str) -> Result<Option<PathBuf>> {
        let resolved = match self.resolve_rel_key(rel_key) {
            Some(k) => k,
            None => return Ok(None),
        };

        let enc_key_hex = match self.all_keys.get(&resolved) {
            Some(k) => k.clone(),
            None => return Ok(None),
        };

        let db_path = self.db_dir.join(
            resolved
                .replace('\\', std::path::MAIN_SEPARATOR_STR)
                .replace('/', std::path::MAIN_SEPARATOR_STR),
        );
        if !db_path.exists() {
            return Ok(None);
        }

        let wal_path = wal_path_for(&db_path);

        let db_mt = mtime_nanos(&db_path);
        let wal_mt = if wal_path.exists() {
            mtime_nanos(&wal_path)
        } else {
            0
        };

        // 检查缓存
        {
            let inner = self.inner.lock().await;
            if let Some(entry) = inner.get(&resolved) {
                if entry.db_mtime == db_mt
                    && entry.wal_mtime == wal_mt
                    && entry.decrypted_path.exists()
                {
                    return Ok(Some(entry.decrypted_path.clone()));
                }
            }
        }

        // 需要重新解密
        let out_path = self.cache_file_path(&resolved);
        let raw_key_bytes =
            hex_to_32bytes(&enc_key_hex).with_context(|| format!("密钥格式错误: {}", resolved))?;
        let (params, enc_key_bytes) = crypto::detect_params_and_key(&db_path, &raw_key_bytes)
            .with_context(|| format!("识别数据库参数失败: {}", resolved))?;
        let db_salt =
            read_db_salt(&db_path).with_context(|| format!("读取数据库 salt 失败: {}", resolved))?;

        let t0 = std::time::Instant::now();
        let db_path2 = db_path.clone();
        let out_path2 = out_path.clone();
        let key_copy = enc_key_bytes;
        let params_copy = params;
        tokio::task::spawn_blocking(move || {
            crypto::full_decrypt(&db_path2, &out_path2, &key_copy, params_copy)
        })
        .await??;

        // 应用 WAL
        if wal_path.exists() {
            let out_path3 = out_path.clone();
            let wal_path3 = wal_path.clone();
            let db_salt3 = db_salt;
            let key_copy2 = enc_key_bytes;
            let params_copy2 = params;
            tokio::task::spawn_blocking(move || {
                wal::apply_wal(&wal_path3, &out_path3, &db_salt3, &key_copy2, params_copy2)
            })
            .await??;
            if !sqlite_opens(&out_path) {
                let is_message_shard = resolved
                    .to_ascii_lowercase()
                    .starts_with("message/msg_");
                if is_message_shard {
                    eprintln!(
                        "[cache] WAL 合并后校验失败，保留消息分片并交给 recover 读取: {}",
                        resolved
                    );
                } else {
                    eprintln!("[cache] WAL 合并后校验失败，回退到基础解密: {}", resolved);
                    let db_path4 = db_path.clone();
                    let out_path4 = out_path.clone();
                    let key_copy3 = enc_key_bytes;
                    let params_copy3 = params;
                    tokio::task::spawn_blocking(move || {
                        crypto::full_decrypt(&db_path4, &out_path4, &key_copy3, params_copy3)
                    })
                    .await??;
                }
            }
        }

        let elapsed_ms = t0.elapsed().as_millis();
        eprintln!("[cache] 解密 {} ({}ms)", resolved, elapsed_ms);

        // 更新内存缓存
        {
            let mut inner = self.inner.lock().await;
            inner.insert(
                resolved,
                CacheEntry {
                    db_mtime: db_mt,
                    wal_mtime: wal_mt,
                    decrypted_path: out_path.clone(),
                },
            );
        }

        self.save_persistent().await;
        Ok(Some(out_path))
    }
}

pub(super) fn mtime_nanos(path: &Path) -> u64 {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .map(|t| {
            t.duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64
        })
        .unwrap_or(0)
}

/// `foo/bar.db` → `foo/bar.db-wal`（用 OsString 拼接，避免 display() 的 UTF-8 问题）
fn wal_path_for(db_path: &Path) -> PathBuf {
    let mut name = db_path.file_name().unwrap_or_default().to_os_string();
    name.push("-wal");
    db_path.with_file_name(name)
}

fn hex_to_32bytes(s: &str) -> Result<[u8; 32]> {
    if s.len() != 64 {
        anyhow::bail!("密钥 hex 长度应为 64，实际为 {}", s.len());
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .with_context(|| format!("非法 hex 字符 at {}", i * 2))?;
    }
    Ok(out)
}

fn looks_like_sqlite(path: &Path) -> bool {
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    let mut buf = [0u8; 16];
    use std::io::Read;
    if f.read_exact(&mut buf).is_err() {
        return false;
    }
    buf == *crypto::SQLITE_HDR
}

fn sqlite_opens(path: &Path) -> bool {
    let Ok(conn) = Connection::open(path) else {
        return false;
    };
    conn.query_row("PRAGMA schema_version", [], |row| row.get::<_, i64>(0))
        .is_ok()
}

fn read_db_salt(path: &Path) -> Result<[u8; 16]> {
    let mut f = std::fs::File::open(path)?;
    let mut buf = [0u8; 16];
    f.read_exact(&mut buf)?;
    Ok(buf)
}
