mod detector;
mod parser;

use anyhow::Result;
use detector::{Finding, analyze_ast};
use parser::parse_source;
use serde::Serialize;
use std::{env, fs, path::Path};

#[derive(Serialize)]
struct Report {
    file: String,
    findings: Vec<Finding>,
}

fn collect_solidity_files(path: &str) -> Result<Vec<String>> {
    let mut files = Vec::new();
    let path = Path::new(path);

    if path.is_file() {
        if path.extension().map_or(false, |ext| ext == "sol") {
            files.push(path.to_string_lossy().to_string());
        }
    } else if path.is_dir() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().map_or(false, |ext| ext == "sol") {
                files.push(path.to_string_lossy().to_string());
            }
        }
    }

    Ok(files)
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: vulpes <contract.sol or folder/>");
        std::process::exit(1);
    }

    let paths = collect_solidity_files(&args[1])?;

    let mut reports = Vec::new();

    for file_path in paths {
        let source = match fs::read_to_string(&file_path) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("❌ Failed to read {}: {}", file_path, e);
                continue;
            }
        };

        match parse_source(&source) {
            Ok(ast) => {
                let findings = analyze_ast(&ast, &source);
                reports.push(Report {
                    file: file_path.clone(),
                    findings,
                });
            }
            Err(_e) => {
                eprintln!("❌ Failed to parse {}", file_path);
            }
        }
    }

    let json = serde_json::to_string_pretty(&reports)?;
    std::fs::write("output/report.json", &json)?;

    // Pretty print summary
    println!("\n──── Summary ────");
    let mut total_files = 0;
    let mut total_findings = 0;

    for report in &reports {
        total_files += 1;
        if report.findings.is_empty() {
            println!("✅ {} — No issues found", report.file);
        } else {
            println!("⚠️  {} — {} issue(s) found", report.file, report.findings.len());
            for f in &report.findings {
                println!("   - {}::{} → {} at line {}", f.contract, f.function, f.reason, f.line);
            }
            total_findings += report.findings.len();
        }
    }

    println!(
        "\n📄 Scanned {} file(s). 🚨 {} total issue(s) detected.",
        total_files, total_findings
    );

    let contracts_with_issues = reports.iter().filter(|r| !r.findings.is_empty()).count();

    println!("⚠️  {} file(s) with issues", contracts_with_issues);

    let total_contracts = reports.len();

    let coverage = if total_contracts > 0 {
        (contracts_with_issues as f64 / total_contracts as f64) * 100.0
    } else {
        0.0
    };

    println!("📊 Detection Coverage: {:.2}%", coverage);

    Ok(())
}


