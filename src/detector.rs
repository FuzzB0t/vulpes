use serde::Serialize;
use solang_parser::helpers::CodeLocation;
use solang_parser::pt::{ContractPart, Expression, SourceUnit, SourceUnitPart, Statement};

/// Represents a single finding detected in a smart contract
#[derive(Debug, Serialize)]
pub struct Finding {
    pub contract: String,
    pub function: String,
    pub pattern: String,
    pub line: usize,
}

/// Analyzes the top-level AST structure and walks through all contracts and functions
/// to detect reentrancy vulnerabilities.
pub fn analyze_ast(ast: &SourceUnit, source: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for item in &ast.0 {
        if let SourceUnitPart::ContractDefinition(contract) = item {
            let contract_name = contract
                .name
                .as_ref()
                .map(|id| id.name.clone())
                .unwrap_or_else(|| "<anonymous>".into());

            for part in &contract.parts {
                if let ContractPart::FunctionDefinition(func) = part {
                    let function_name = func
                        .name
                        .as_ref()
                        .map(|id| id.name.clone())
                        .unwrap_or_else(|| "<fallback>".into());

                    // Analyze each statement inside the function body
                    if let Some(Statement::Block { statements, .. }) = &func.body {
                        for stmt in statements {
                            visit_stmt(stmt, &contract_name, &function_name, source, &mut findings);
                        }
                    }
                }
            }
        }
    }

    findings
}

/// Recursively visits and analyzes all statements in a function, including nested blocks and conditions.
fn visit_stmt(
    stmt: &Statement,
    contract: &str,
    function: &str,
    source: &str,
    findings: &mut Vec<Finding>,
) {
    // Check the current statement for reentrancy patterns
    if let Some(pattern) = contains_reentrancy_risk(stmt) {
        findings.push(Finding {
            contract: contract.to_string(),
            function: function.to_string(),
            pattern,
            line: source[..stmt.loc().start()].lines().count(),
        });
    }

    // Recursively analyze statements in blocks (e.g., `{ ... }`)
    if let Statement::Block { statements, .. } = stmt {
        for inner in statements {
            visit_stmt(inner, contract, function, source, findings);
        }
    }

    // Recursively analyze conditional branches
    if let Statement::If(_, cond, then_branch, else_branch) = stmt {
        // Analyze the if condition expression
        if let Some(pattern) = has_reentrancy_risk(cond) {
            findings.push(Finding {
                contract: contract.to_string(),
                function: function.to_string(),
                pattern,
                line: source[..stmt.loc().start()].lines().count(),
            });
        }

        visit_stmt(then_branch.as_ref(), contract, function, source, findings);
        if let Some(else_stmt) = else_branch {
            visit_stmt(else_stmt, contract, function, source, findings);
        }
    }
}

/// Checks if the current statement contains any expression associated with reentrancy.
fn contains_reentrancy_risk(stmt: &Statement) -> Option<String> {
    match stmt {
        Statement::Expression(_, expr) | Statement::VariableDefinition(_, _, Some(expr)) => {
            has_reentrancy_risk(expr)
        }
        _ => None,
    }
}

/// Recursively checks expressions for specific reentrancy patterns like `call.value()`, `send()`, etc.
fn has_reentrancy_risk(expr: &Expression) -> Option<String> {
    if is_old_call_value(expr) {
        return Some("call.value() external call".into());
    }
    if is_new_call_value(expr) {
        return Some("call{value:} external call".into());
    }
    if is_send_or_transfer(expr) {
        return Some("send() or transfer() external call".into());
    }
    if is_delegatecall_or_callcode(expr) {
        return Some("delegatecall() or callcode() external call".into());
    }

    // Recursively explore subexpressions (e.g., inside assignments, member access, etc.)
    match expr {
        Expression::FunctionCall(_, callee, args) => has_reentrancy_risk(callee.as_ref())
            .or_else(|| args.iter().find_map(|arg| has_reentrancy_risk(arg))),
        Expression::Assign(_, lhs, rhs) => {
            has_reentrancy_risk(lhs).or_else(|| has_reentrancy_risk(rhs))
        }
        Expression::MemberAccess(_, inner, _) => has_reentrancy_risk(inner.as_ref()),
        Expression::ArraySubscript(_, base, idx) => has_reentrancy_risk(base.as_ref())
            .or_else(|| idx.as_deref().and_then(has_reentrancy_risk)),
        _ => None,
    }
}

/* ──────────────────────────────────────────────────────────────
Pattern-Specific Helper Functions
────────────────────────────────────────────────────────────── */

/// Detects older style reentrancy pattern: `msg.sender.call.value(amount)()`
fn is_old_call_value(expr: &Expression) -> bool {
    if let Expression::FunctionCall(_, outer_callee, _) = expr {
        if let Expression::FunctionCall(_, inner_callee, _) = outer_callee.as_ref() {
            if let Expression::MemberAccess(_, value_expr, value_member) = inner_callee.as_ref() {
                if value_member.name == "value" {
                    if let Expression::MemberAccess(_, _base_expr, call_member) =
                        value_expr.as_ref()
                    {
                        return call_member.name == "call";
                    }
                }
            }
        }
    }
    false
}

/// Detects newer style reentrancy pattern: `call{value: amount}()`
fn is_new_call_value(expr: &Expression) -> bool {
    if let Expression::FunctionCall(_, callee, args) = expr {
        if let Expression::MemberAccess(_, _, member) = callee.as_ref() {
            return member.name == "call" && !args.is_empty();
        }
    }
    false
}

/// Detects usage of `send()` or `transfer()` calls, which may be risky
fn is_send_or_transfer(expr: &Expression) -> bool {
    if let Expression::FunctionCall(_, callee, _) = expr {
        if let Expression::MemberAccess(_, _, member) = callee.as_ref() {
            return member.name == "send" || member.name == "transfer";
        }
    }
    false
}

/// Detects use of low-level delegate or context-changing calls
fn is_delegatecall_or_callcode(expr: &Expression) -> bool {
    if let Expression::FunctionCall(_, callee, _) = expr {
        if let Expression::MemberAccess(_, _, member) = callee.as_ref() {
            return member.name == "delegatecall" || member.name == "callcode";
        }
    }
    false
}
