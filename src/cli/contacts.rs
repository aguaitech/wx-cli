use super::output::{print_value, resolve};
use super::transport;
use crate::ipc::Request;
use anyhow::Result;

pub fn cmd_contacts(query: Option<String>, limit: usize, json: bool) -> Result<()> {
    let resp = transport::send(Request::Contacts { query, limit })?;
    let contacts = resp
        .data
        .get("contacts")
        .cloned()
        .unwrap_or(serde_json::Value::Array(vec![]));
    print_value(&contacts, &resolve(json))
}
