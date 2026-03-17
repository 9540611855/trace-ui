use serde::{Deserialize, Serialize};
use tauri::State;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct SearchRequest {
    pub query: String,
    #[serde(default = "default_max_results")]
    pub max_results: u32,
}

fn default_max_results() -> u32 {
    10000
}

#[derive(Serialize)]
pub struct SearchMatch {
    pub seq: u32,
    pub address: String,
    pub disasm: String,
    pub changes: String,
    pub mem_rw: Option<String>,
}

#[derive(Serialize)]
pub struct SearchResult {
    pub matches: Vec<SearchMatch>,
    pub total_scanned: u32,
    pub total_matches: u32,
    pub truncated: bool,
}

enum SearchMode {
    Text(Vec<u8>),
    Regex(regex::bytes::Regex),
}

fn parse_search_mode(query: &str) -> Result<SearchMode, String> {
    if query.starts_with('/') && query.ends_with('/') && query.len() > 2 {
        let pattern = &query[1..query.len() - 1];
        let re = regex::bytes::Regex::new(pattern)
            .map_err(|e| format!("正则表达式错误: {}", e))?;
        Ok(SearchMode::Regex(re))
    } else {
        Ok(SearchMode::Text(query.as_bytes().to_vec()))
    }
}

#[tauri::command]
pub async fn search_trace(
    session_id: String,
    request: SearchRequest,
    state: State<'_, AppState>,
) -> Result<SearchResult, String> {
    if request.query.is_empty() {
        return Ok(SearchResult {
            matches: Vec::new(),
            total_scanned: 0,
            total_matches: 0,
            truncated: false,
        });
    }

    let mode = parse_search_mode(&request.query)?;
    let max_results = request.max_results;

    // 预构建 call_annotations 的搜索文本: seq -> searchable_text
    let (mmap_arc, total_lines, trace_format, call_search_texts) = {
        let sessions = state.sessions.read().map_err(|e| e.to_string())?;
        let session = sessions.get(&session_id).ok_or_else(|| format!("Session {} 不存在", session_id))?;
        let texts: std::collections::HashMap<u32, String> = session.call_annotations.iter()
            .map(|(&seq, ann)| (seq, ann.searchable_text()))
            .collect();
        (
            session.mmap.clone(),
            session.line_index.as_ref().map(|li| li.total_lines()).unwrap_or(0),
            session.trace_format,
            texts,
        )
    };

    let result = tauri::async_runtime::spawn_blocking(move || {
        let data: &[u8] = &mmap_arc;

        let mut matches = Vec::new();
        let mut total_matches = 0u32;
        let mut pos = 0usize;
        let mut seq = 0u32;

        while pos < data.len() && seq < total_lines {
            let end = memchr::memchr(b'\n', &data[pos..])
                .map(|i| pos + i)
                .unwrap_or(data.len());

            let line = &data[pos..end];

            let is_match = match &mode {
                SearchMode::Text(needle) => memchr::memmem::find(line, needle).is_some(),
                SearchMode::Regex(re) => re.is_match(line),
            };
            // 未命中原始行时，检查该行关联的 call_annotation
            let is_match = is_match || (!is_match && call_search_texts.get(&seq).map_or(false, |text| {
                let text_bytes = text.as_bytes();
                match &mode {
                    SearchMode::Text(needle) => memchr::memmem::find(text_bytes, needle).is_some(),
                    SearchMode::Regex(re) => re.is_match(text_bytes),
                }
            }));

            if is_match {
                total_matches += 1;
                if matches.len() < max_results as usize {
                    let parsed = match trace_format {
                    crate::taint::types::TraceFormat::Unidbg => crate::commands::browse::parse_trace_line(seq, line),
                    crate::taint::types::TraceFormat::Gumtrace => crate::commands::browse::parse_trace_line_gumtrace(seq, line),
                };
                if let Some(parsed) = parsed {
                        matches.push(SearchMatch {
                            seq: parsed.seq,
                            address: parsed.address,
                            disasm: parsed.disasm,
                            changes: parsed.changes,
                            mem_rw: parsed.mem_rw,
                        });
                    }
                }
            }

            pos = end + 1;
            seq += 1;
        }

        SearchResult {
            matches,
            total_scanned: seq,
            total_matches,
            truncated: total_matches > max_results,
        }
    })
    .await
    .map_err(|e| format!("搜索线程 panic: {}", e))?;

    Ok(result)
}
