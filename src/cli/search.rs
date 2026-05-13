use super::history::{parse_msg_type, parse_time, parse_time_end};
use super::output::{print_value, resolve};
use super::transport;
use crate::ipc::Request;
use anyhow::Result;

pub fn cmd_search(
    keyword: String,
    chats: Vec<String>,
    limit: usize,
    since: Option<String>,
    until: Option<String>,
    msg_type: Option<String>,
    json: bool,
) -> Result<()> {
    let since_ts = since.as_deref().map(parse_time).transpose()?;
    let until_ts = until.as_deref().map(parse_time_end).transpose()?;
    let type_val = msg_type.as_deref().and_then(parse_msg_type);
    let chats_opt = if chats.is_empty() { None } else { Some(chats) };

    let req = Request::Search {
        keyword,
        chats: chats_opt,
        limit,
        since: since_ts,
        until: until_ts,
        msg_type: type_val,
    };

    let resp = transport::send(req)?;
    let results = resp
        .data
        .get("results")
        .cloned()
        .unwrap_or(serde_json::Value::Array(vec![]));
    print_value(&results, &resolve(json))
}
