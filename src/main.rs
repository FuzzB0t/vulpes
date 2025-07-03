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

// Iterate over solidity files inside a directory
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
        print_help_screen();
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

    // Save machine-readable output
    std::fs::create_dir_all("output")?;
    let json = serde_json::to_string_pretty(&reports)?;
    std::fs::write("output/report.json", &json)?;

    // Start report
    println!("\n\u{001b}[1;34m───── Analysis Report ─────\u{001b}[0m");

    let mut total_findings = 0;

    for report in &reports {
        println!(
            "\n📄 \u{001b}[1mFile:\u{001b}[0m {}\n{}",
            report.file,
            "-".repeat(80)
        );

        if report.findings.is_empty() {
            println!("✅ No vulnerabilities detected.\n");
        } else {
            println!(
                "⚠️  \u{001b}[33m{} potential issue(s) found:\u{001b}[0m",
                report.findings.len()
            );
            for finding in &report.findings {
                println!(
                    "   → \u{001b}[1m{:<20}\u{001b}[0m | fn: {:<20} | line: {:<4} | pattern: {}",
                    finding.contract,
                    finding.function,
                    finding.line,
                    finding.pattern
                );
            }
            total_findings += report.findings.len();
        }
    }

    // Summary
    let total_files = reports.len();
    let files_with_issues = reports.iter().filter(|r| !r.findings.is_empty()).count();
    let coverage = if total_files > 0 {
        (files_with_issues as f64 / total_files as f64) * 100.0
    } else {
        0.0
    };

    println!("\n\u{001b}[1;34m───── Summary ─────\u{001b}[0m");
    println!("📁 Files scanned        : {}", total_files);
    println!("⚠️  Files with findings  : {}", files_with_issues);
    println!("🚨 Total issues found    : {}", total_findings);
    println!("📊 Detection coverage    : {:.2}%", coverage);
    println!("📝 Report saved to       : output/report.json");

    Ok(())
}


fn print_help_screen() {
    // ANSI escape codes for colors
    let cyan_bold = "\x1b[1;36m";
    let reset = "\x1b[0m";
    let bold = "\x1b[1m";

    println!("{}██    ██ ██    ██ ██      ██████  ███████ ███████ {}", cyan_bold, reset);
    println!("{}██    ██ ██    ██ ██      ██   ██ ██      ██      {}", cyan_bold, reset);
    println!("{}██    ██ ██    ██ ██      ██   ██ █████   ███████ {}", cyan_bold, reset);
    println!("{} ██  ██   ██  ██  ██      ██████  ██           ██ {}", cyan_bold, reset);
    println!("{}  ████     ████   ███████ ██      ███████ ███████ {}", cyan_bold, reset);
    println!();
    println!("🐺 {}Vulpes{} – Solidity Static Analysis Tool for Reentrancy & More", bold, reset);
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    println!("{}USAGE{}:", bold, reset);
    println!("    vulpes <file.sol | directory/>");
    println!();
    println!("{}EXAMPLES{}:", bold, reset);
    println!("    vulpes contracts/MyToken.sol");
    println!("    vulpes ./contracts/");
    println!();
    println!("{}FEATURES{}:", bold, reset);
    println!("  • Detects common reentrancy vulnerabilities:");
    println!("      - call.value().()");
    println!("      - call{{value:...}}()");
    println!("      - send(), transfer(), delegatecall(), callcode()");
    println!("      - Reentrancy in modifiers (e.g. via msg.sender)");
    println!("  • Parses entire directories of Solidity files");
    println!("  • Outputs structured JSON report at output/report.json");
    println!("  • Beautiful CLI summaries & vulnerability breakdowns");
    println!();
    println!("{}OUTPUT{}:", bold, reset);
    println!("    → Human-readable CLI summary");
    println!("    → Machine-readable: output/report.json");
    println!();
    println!("{}ABOUT{}:", bold, reset);
    println!("    Author   : YOU");
    println!("    Version  : 1.0.0");
    println!("    Repo     : https://github.com/yourname/vulpes");
    println!();
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
}