use anyhow::Result;
use solang_parser::{parse, pt::SourceUnit};

/// Parses Solidity source code into an AST 
pub fn parse_source(source_code: &str) -> Result<SourceUnit> {
    let (ast, _comments) = parse(source_code, 0)
        .map_err(|errors| anyhow::anyhow!("Parse error: {:?}", errors))?;
    Ok(ast)
}
