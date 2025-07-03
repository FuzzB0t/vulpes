use serde::Serialize;
use solang_parser::helpers::CodeLocation;
use solang_parser::pt::{ContractPart, Expression, SourceUnit, SourceUnitPart, Statement};

#[derive(Debug, Serialize)]
pub struct Finding {
    pub contract: String,
    pub function: String,
    pub reason: String,
    pub line: usize,
}

// Walks through AST tree and finds matching vulnerability patterns
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

/// Recursively visit statements and record reentrancy findings with their specific reasons
fn visit_stmt(
    stmt: &Statement,
    contract: &str,
    function: &str,
    source: &str,
    findings: &mut Vec<Finding>,
) {
    if let Some(reason) = contains_reentrancy_risk(stmt) {
        findings.push(Finding {
            contract: contract.to_string(),
            function: function.to_string(),
            reason,
            line: source[..stmt.loc().start()].lines().count(),
        });
    }
    // Recurse into blocks
    if let Statement::Block { statements, .. } = stmt {
        for inner in statements {
            visit_stmt(inner, contract, function, source, findings);
        }
    }
    // Recurse into if branches
    if let Statement::If(_, cond, then_branch, else_branch) = stmt {
        // Check condition for call.value pattern
        if let Some(reason) = expr_contains_reentrancy_risk(cond) {
            findings.push(Finding {
                contract: contract.to_string(),
                function: function.to_string(),
                reason,
                line: source[..stmt.loc().start()].lines().count(),
            });
        }
        visit_stmt(then_branch.as_ref(), contract, function, source, findings);
        if let Some(else_stmt) = else_branch {
            visit_stmt(else_stmt, contract, function, source, findings);
        }
    }
}

/// Determine if a function statement contains a reentrancy-risky call
fn contains_reentrancy_risk(stmt: &Statement) -> Option<String> {
    match stmt {
        Statement::Expression(_, expr) | Statement::VariableDefinition(_, _, Some(expr)) => {
            expr_contains_reentrancy_risk(expr)
        }
        _ => None,
    }
}

/// Check expressions for reentrancy patterns, returning the reason if found
fn expr_contains_reentrancy_risk(expr: &Expression) -> Option<String> {
    if is_old_call_value(expr) {
        return Some("Reentrancy Risk: call.value() external call".into());
    }
    if is_new_call_value(expr) {
        return Some("Reentrancy Risk: call{value:} external call".into());
    }
    if is_send_or_transfer(expr) {
        return Some("Reentrancy Risk: send() or transfer() external call".into());
    }
    if is_delegatecall_or_callcode(expr) {
        return Some("Reentrancy Risk: delegatecall() or callcode() external call".into());
    }
    
    // recurse into sub-expressions to ensure we capture these patterns anywhere in the call stack
    match expr {
        Expression::FunctionCall(_, callee, args) => {
            expr_contains_reentrancy_risk(callee.as_ref())
                .or_else(|| args.iter().find_map(|arg| expr_contains_reentrancy_risk(arg)))
        }
        Expression::Assign(_, lhs, rhs) => {
            expr_contains_reentrancy_risk(lhs).or_else(|| expr_contains_reentrancy_risk(rhs))
        }
        Expression::MemberAccess(_, inner, _) => expr_contains_reentrancy_risk(inner.as_ref()),
        Expression::ArraySubscript(_, base, idx) => {
            expr_contains_reentrancy_risk(base.as_ref())
                .or_else(|| idx.as_deref().and_then(expr_contains_reentrancy_risk))
        }
        _ => None,
    }
}

/*  Helper functions for pattern detection */

// Checks for call.value(...)
fn is_old_call_value(expr: &Expression) -> bool {
    if let Expression::FunctionCall(_, outer_callee, _) = expr {
        // Outer '()' call
        if let Expression::FunctionCall(_, inner_callee, _) = outer_callee.as_ref() {
            // Inner call.value(...) call
            if let Expression::MemberAccess(_, value_expr, value_member) = inner_callee.as_ref() {
                if value_member.name == "value" {
                    if let Expression::MemberAccess(_, _base_expr, call_member) = value_expr.as_ref() {
                        return call_member.name == "call";
                    }
                }
            }
        }
    }
    false
}

// Checks for call{value...}
fn is_new_call_value(expr: &Expression) -> bool {
    if let Expression::FunctionCall(_, callee, args) = expr {
        if let Expression::MemberAccess(_, _, member) = callee.as_ref() {
            return member.name == "call" && !args.is_empty();
        }
    }
    false
}

// Checks for send() or transfer() functions
fn is_send_or_transfer(expr: &Expression) -> bool {
    if let Expression::FunctionCall(_, callee, _) = expr {
        if let Expression::MemberAccess(_, _, member) = callee.as_ref() {
            return member.name == "send" || member.name == "transfer";
        }
    }
    false
}

// Checks for delegatecall or callcode functions
fn is_delegatecall_or_callcode(expr: &Expression) -> bool {
    if let Expression::FunctionCall(_, callee, _) = expr {
        if let Expression::MemberAccess(_, _, member) = callee.as_ref() {
            return member.name == "delegatecall" || member.name == "callcode";
        }
    }
    false
}
