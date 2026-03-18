use serde::{Deserialize, Serialize};
use tauri::State;
use crate::state::AppState;
use crate::commands::browse::CallInfoDto;

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
    pub call_info: Option<CallInfoDto>,
}

#[derive(Serialize)]
pub struct SearchResult {
    pub matches: Vec<SearchMatch>,
    pub total_scanned: u32,
    pub total_matches: u32,
    pub truncated: bool,
}

enum SearchMode {
    /// 单个关键词子串匹配（不区分大小写）
    Text(Vec<u8>),
    /// 多个关键词模糊匹配（空格分隔，全部命中才算匹配，不区分大小写）
    FuzzyText(Vec<Vec<u8>>),
    Regex(regex::bytes::Regex),
}

fn parse_search_mode(query: &str) -> Result<SearchMode, String> {
    if query.starts_with('/') && query.ends_with('/') && query.len() > 2 {
        let pattern = &query[1..query.len() - 1];
        let re = regex::bytes::Regex::new(pattern)
            .map_err(|e| format!("正则表达式错误: {}", e))?;
        Ok(SearchMode::Regex(re))
    } else {
        let tokens: Vec<Vec<u8>> = query.split_whitespace()
            .map(|s| s.to_lowercase().into_bytes())
            .collect();
        if tokens.len() > 1 {
            Ok(SearchMode::FuzzyText(tokens))
        } else {
            Ok(SearchMode::Text(query.to_lowercase().into_bytes()))
        }
    }
}

/// 零分配 ASCII 大小写不敏感子串搜索
#[inline]
fn ascii_contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|window| {
        window.iter().zip(needle).all(|(h, n)| h.to_ascii_lowercase() == *n)
    })
}

/// 零分配多关键词模糊匹配
#[inline]
fn ascii_fuzzy_match(haystack: &[u8], tokens: &[Vec<u8>]) -> bool {
    tokens.iter().all(|t| ascii_contains(haystack, t))
}

/// 对一行执行匹配（支持原始行 + call_search_text 双重匹配）
#[inline]
fn matches_line(mode: &SearchMode, line: &[u8], call_text: Option<&[u8]>) -> bool {
    let line_match = match mode {
        SearchMode::Text(needle) => ascii_contains(line, needle),
        SearchMode::FuzzyText(tokens) => ascii_fuzzy_match(line, tokens),
        SearchMode::Regex(re) => re.is_match(line),
    };
    if line_match {
        return true;
    }
    if let Some(text) = call_text {
        match mode {
            SearchMode::Text(needle) => ascii_contains(text, needle),
            SearchMode::FuzzyText(tokens) => ascii_fuzzy_match(text, tokens),
            SearchMode::Regex(re) => re.is_match(text),
        }
    } else {
        false
    }
}

/// 搜索一个分块，返回 (匹配列表, 总匹配数)
fn search_chunk(
    data: &[u8],
    start_seq: u32,
    end_seq: u32,
    start_offset: usize,
    mode: &SearchMode,
    consumed_seqs: &std::collections::HashSet<u32>,
    call_search_texts: &std::collections::HashMap<u32, String>,
    call_annotations: &std::collections::HashMap<u32, crate::taint::gumtrace_parser::CallAnnotation>,
    trace_format: crate::taint::types::TraceFormat,
    max_results_per_chunk: usize,
) -> (Vec<SearchMatch>, u32) {
    let mut matches = Vec::new();
    let mut total_matches = 0u32;
    let mut pos = start_offset;
    let mut seq = start_seq;

    while pos < data.len() && seq < end_seq {
        let end = memchr::memchr(b'\n', &data[pos..])
            .map(|i| pos + i)
            .unwrap_or(data.len());

        let line = &data[pos..end];

        if consumed_seqs.contains(&seq) {
            pos = end + 1;
            seq += 1;
            continue;
        }

        let call_text = call_search_texts.get(&seq).map(|s| s.as_bytes());
        if matches_line(mode, line, call_text) {
            total_matches += 1;
            if matches.len() < max_results_per_chunk {
                let parsed = match trace_format {
                    crate::taint::types::TraceFormat::Unidbg => crate::commands::browse::parse_trace_line(seq, line),
                    crate::taint::types::TraceFormat::Gumtrace => crate::commands::browse::parse_trace_line_gumtrace(seq, line),
                };
                if let Some(parsed) = parsed {
                    let call_info = call_annotations.get(&seq).map(|ann| CallInfoDto {
                        func_name: ann.func_name.clone(),
                        is_jni: ann.is_jni,
                        summary: ann.summary(),
                        tooltip: ann.tooltip(),
                    });
                    matches.push(SearchMatch {
                        seq: parsed.seq,
                        address: parsed.address,
                        disasm: parsed.disasm,
                        changes: parsed.changes,
                        mem_rw: parsed.mem_rw,
                        call_info,
                    });
                }
            }
        }

        pos = end + 1;
        seq += 1;
    }

    (matches, total_matches)
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

    // 从 session 中提取搜索所需数据（使用缓存的 call_search_texts）
    let (mmap_arc, total_lines, trace_format, call_search_texts, call_annotations, consumed_seqs, line_index) = {
        let sessions = state.sessions.read().map_err(|e| e.to_string())?;
        let session = sessions.get(&session_id).ok_or_else(|| format!("Session {} 不存在", session_id))?;
        (
            session.mmap.clone(),
            session.line_index.as_ref().map(|li| li.total_lines()).unwrap_or(0),
            session.trace_format,
            session.call_search_texts.clone(),
            session.call_annotations.clone(),
            session.consumed_seqs.iter().copied().collect::<std::collections::HashSet<u32>>(),
            session.line_index.clone(),
        )
    };

    let result = tauri::async_runtime::spawn_blocking(move || {
        let data: &[u8] = &mmap_arc;

        // 确定并行分块数
        let num_cpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);

        // 如果行数较少或无 line_index，退化为单线程
        let use_parallel = num_cpus > 1 && total_lines > 10000 && line_index.is_some();

        if use_parallel {
            let li = line_index.as_ref().unwrap();
            let num_chunks = num_cpus.min(16);
            let lines_per_chunk = (total_lines as usize + num_chunks - 1) / num_chunks;

            // 构建分块边界: (start_seq, end_seq, start_byte_offset)
            let mut chunks = Vec::with_capacity(num_chunks);
            for i in 0..num_chunks {
                let start_seq = (i * lines_per_chunk) as u32;
                if start_seq >= total_lines {
                    break;
                }
                let end_seq = ((i + 1) * lines_per_chunk).min(total_lines as usize) as u32;
                let start_offset = li.line_byte_offset(data, start_seq).unwrap_or(0) as usize;
                chunks.push((start_seq, end_seq, start_offset));
            }

            // rayon 并行搜索各分块
            use rayon::prelude::*;
            let chunk_results: Vec<(Vec<SearchMatch>, u32)> = chunks.par_iter()
                .map(|&(start_seq, end_seq, start_offset)| {
                    search_chunk(
                        data, start_seq, end_seq, start_offset,
                        &mode, &consumed_seqs, &call_search_texts,
                        &call_annotations, trace_format,
                        max_results as usize,  // 每块最多收集 max_results，后续合并截断
                    )
                })
                .collect();

            // 合并结果（各块按 seq 天然有序）
            let mut all_matches = Vec::new();
            let mut total_matches = 0u32;
            for (chunk_matches, chunk_total) in chunk_results {
                total_matches += chunk_total;
                if all_matches.len() < max_results as usize {
                    let remaining = max_results as usize - all_matches.len();
                    all_matches.extend(chunk_matches.into_iter().take(remaining));
                }
            }

            SearchResult {
                matches: all_matches,
                total_scanned: total_lines,
                total_matches,
                truncated: total_matches > max_results,
            }
        } else {
            // 单线程搜索（行数少或无 line_index 时）
            let (matches, total_matches) = search_chunk(
                data, 0, total_lines, 0,
                &mode, &consumed_seqs, &call_search_texts,
                &call_annotations, trace_format, max_results as usize,
            );

            SearchResult {
                matches,
                total_scanned: total_lines,
                total_matches,
                truncated: total_matches > max_results,
            }
        }
    })
    .await
    .map_err(|e| format!("搜索线程 panic: {}", e))?;

    Ok(result)
}
