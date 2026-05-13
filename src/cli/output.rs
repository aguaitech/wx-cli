/// 输出格式
pub enum Fmt {
    Yaml,
    Json,
}

/// 默认 YAML，--json 时输出 JSON
pub fn resolve(json: bool) -> Fmt {
    if json {
        Fmt::Json
    } else {
        Fmt::Yaml
    }
}

pub fn print_value(value: &serde_json::Value, fmt: &Fmt) -> anyhow::Result<()> {
    match fmt {
        Fmt::Json => println!("{}", serde_json::to_string_pretty(value)?),
        Fmt::Yaml => print!("{}", serde_yaml::to_string(value)?),
    }
    Ok(())
}
