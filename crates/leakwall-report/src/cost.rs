use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostEstimate {
    pub total_input_tokens: u64,
    pub total_output_tokens: u64,
    pub estimated_cost_usd: f64,
    pub model: String,
    pub provider: String,
}

#[derive(Debug, Clone)]
pub struct InterceptedRequestSummary {
    pub host: String,
    pub request_body_size: usize,
    pub response_headers: HashMap<String, String>,
    pub response_body: Option<String>,
    pub request_body: Option<String>,
}

/// Detect the provider name from the API host.
fn detect_provider(host: &str) -> &'static str {
    if host.contains("anthropic.com") {
        "Anthropic"
    } else if host.contains("openai.com") {
        "OpenAI"
    } else if host.contains("groq.com") {
        "Groq"
    } else if host.contains("mistral.ai") {
        "Mistral"
    } else if host.contains("deepseek.com") {
        "DeepSeek"
    } else if host.contains("cohere.com") {
        "Cohere"
    } else if host.contains("googleapis.com") {
        "Google"
    } else {
        "Unknown"
    }
}

/// Detect the model name from request/response body JSON.
fn detect_model(request: &InterceptedRequestSummary) -> String {
    for body in [&request.response_body, &request.request_body]
        .into_iter()
        .flatten()
    {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
            if let Some(m) = v.get("model").and_then(|m| m.as_str()) {
                return m.to_string();
            }
        }
    }
    "unknown".to_string()
}

/// Per-million-token pricing: (input_cost, output_cost).
fn model_pricing(model: &str) -> (f64, f64) {
    match model {
        m if m.contains("claude-3-5-sonnet") || m.contains("claude-3.5-sonnet") => (3.0, 15.0),
        m if m.contains("claude-3-opus") || m.contains("claude-3.0-opus") => (15.0, 75.0),
        m if m.contains("claude-3-haiku") || m.contains("claude-3.5-haiku") => (0.25, 1.25),
        m if m.contains("gpt-4o-mini") => (0.15, 0.60),
        m if m.contains("gpt-4o") => (2.50, 10.0),
        m if m.contains("gpt-4-turbo") => (10.0, 30.0),
        m if m.contains("gpt-4") => (30.0, 60.0),
        m if m.contains("gpt-3.5") => (0.50, 1.50),
        _ => (3.0, 15.0),
    }
}

/// Extract token counts from response headers.
fn tokens_from_headers(headers: &HashMap<String, String>) -> (Option<u64>, Option<u64>) {
    let input = headers
        .get("x-usage-input-tokens")
        .or_else(|| headers.get("x-usage-prompt-tokens"))
        .and_then(|v| v.parse::<u64>().ok());
    let output = headers
        .get("x-usage-output-tokens")
        .or_else(|| headers.get("x-usage-completion-tokens"))
        .and_then(|v| v.parse::<u64>().ok());
    (input, output)
}

/// Extract token counts from JSON response body "usage" field.
fn tokens_from_body(body: &str) -> (Option<u64>, Option<u64>) {
    let v: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return (None, None),
    };
    let usage = match v.get("usage") {
        Some(u) => u,
        None => return (None, None),
    };
    let input = usage
        .get("input_tokens")
        .or_else(|| usage.get("prompt_tokens"))
        .and_then(|v| v.as_u64());
    let output = usage
        .get("output_tokens")
        .or_else(|| usage.get("completion_tokens"))
        .and_then(|v| v.as_u64());
    (input, output)
}

/// Estimate ~4 chars per token as a rough fallback.
fn tokens_from_size(bytes: usize) -> u64 {
    (bytes as u64) / 4
}

/// Estimate cost across a set of intercepted API requests.
pub fn estimate_cost(requests: &[InterceptedRequestSummary]) -> CostEstimate {
    let mut total_input: u64 = 0;
    let mut total_output: u64 = 0;
    let mut provider = "Unknown".to_string();
    let mut model = "unknown".to_string();

    for req in requests {
        let p = detect_provider(&req.host);
        if p != "Unknown" && provider == "Unknown" {
            provider = p.to_string();
        }
        let m = detect_model(req);
        if m != "unknown" && model == "unknown" {
            model = m;
        }

        // Try headers first
        let (hi, ho) = tokens_from_headers(&req.response_headers);

        // Try response body if headers missing
        let (bi, bo) = req
            .response_body
            .as_deref()
            .map(tokens_from_body)
            .unwrap_or((None, None));

        let input_tokens = hi
            .or(bi)
            .unwrap_or_else(|| tokens_from_size(req.request_body_size));
        let output_tokens = ho.or(bo).unwrap_or(0);

        total_input += input_tokens;
        total_output += output_tokens;
    }

    let (input_price, output_price) = model_pricing(&model);
    let cost = (total_input as f64 / 1_000_000.0) * input_price
        + (total_output as f64 / 1_000_000.0) * output_price;

    CostEstimate {
        total_input_tokens: total_input,
        total_output_tokens: total_output,
        estimated_cost_usd: (cost * 1_000_000.0).round() / 1_000_000.0,
        model,
        provider,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cost_estimation_with_known_headers() {
        let mut headers = HashMap::new();
        headers.insert("x-usage-input-tokens".to_string(), "1000".to_string());
        headers.insert("x-usage-output-tokens".to_string(), "500".to_string());

        let requests = vec![InterceptedRequestSummary {
            host: "api.anthropic.com".to_string(),
            request_body_size: 4000,
            response_headers: headers,
            response_body: Some(r#"{"model":"claude-3-5-sonnet-20241022"}"#.to_string()),
            request_body: None,
        }];

        let est = estimate_cost(&requests);
        assert_eq!(est.total_input_tokens, 1000);
        assert_eq!(est.total_output_tokens, 500);
        assert_eq!(est.provider, "Anthropic");
        assert!(est.model.contains("claude-3-5-sonnet"));
        // 1000/1M * 3.0 + 500/1M * 15.0 = 0.0105
        assert!(
            (est.estimated_cost_usd - 0.0105).abs() < 0.0001,
            "expected ~0.0105, got {}",
            est.estimated_cost_usd
        );
    }

    #[test]
    fn cost_estimation_fallback_no_headers() {
        let requests = vec![InterceptedRequestSummary {
            host: "api.openai.com".to_string(),
            request_body_size: 8000,
            response_headers: HashMap::new(),
            response_body: None,
            request_body: Some(r#"{"model":"gpt-4o","messages":[]}"#.to_string()),
        }];

        let est = estimate_cost(&requests);
        // fallback: 8000 / 4 = 2000 input tokens
        assert_eq!(est.total_input_tokens, 2000);
        assert_eq!(est.total_output_tokens, 0);
        assert_eq!(est.provider, "OpenAI");
        assert_eq!(est.model, "gpt-4o");
    }

    #[test]
    fn cost_estimation_from_body_usage() {
        let body = r#"{
            "model": "gpt-4o",
            "usage": {
                "prompt_tokens": 300,
                "completion_tokens": 150
            }
        }"#;

        let requests = vec![InterceptedRequestSummary {
            host: "api.openai.com".to_string(),
            request_body_size: 1200,
            response_headers: HashMap::new(),
            response_body: Some(body.to_string()),
            request_body: None,
        }];

        let est = estimate_cost(&requests);
        assert_eq!(est.total_input_tokens, 300);
        assert_eq!(est.total_output_tokens, 150);
    }

    #[test]
    fn detect_provider_names() {
        assert_eq!(detect_provider("api.anthropic.com"), "Anthropic");
        assert_eq!(detect_provider("api.openai.com"), "OpenAI");
        assert_eq!(detect_provider("api.groq.com"), "Groq");
        assert_eq!(detect_provider("api.mistral.ai"), "Mistral");
        assert_eq!(detect_provider("example.com"), "Unknown");
    }
}
