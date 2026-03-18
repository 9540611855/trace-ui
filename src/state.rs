use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, RwLock};
use memmap2::Mmap;
use serde::{Serialize, Deserialize};
use crate::taint::call_tree::CallTree;
use crate::taint::mem_access::MemAccessIndex;
use crate::taint::reg_checkpoint::RegCheckpoints;
use crate::line_index::LineIndex;
use crate::taint::strings::StringIndex;
use crate::taint::types::TraceFormat;
use crate::taint::gumtrace_parser::CallAnnotation;

/// Phase 2 索引数据（CallTree + MemAccessIndex + RegCheckpoints）
#[derive(Serialize, Deserialize)]
pub struct Phase2State {
    pub call_tree: CallTree,
    pub mem_accesses: MemAccessIndex,
    pub reg_checkpoints: RegCheckpoints,
    pub string_index: StringIndex,
}

/// 单个 trace 文件的会话状态
#[allow(dead_code)]
pub struct SessionState {
    pub mmap: Arc<Mmap>,
    pub line_index: Option<LineIndex>,
    pub file_path: String,
    pub total_lines: u32,
    pub file_size: u64,
    pub phase2: Option<Phase2State>,
    pub scan_state: Option<crate::taint::scanner::ScanState>,
    pub slice_result: Option<bitvec::prelude::BitVec>,
    pub scan_strings_cancelled: Arc<AtomicBool>,
    pub trace_format: TraceFormat,
    pub call_annotations: std::collections::HashMap<u32, CallAnnotation>,
    pub consumed_seqs: Vec<u32>,
    /// 缓存 call_annotations 的搜索文本，避免每次搜索重复生成
    pub call_search_texts: std::collections::HashMap<u32, String>,
}

impl SessionState {
    /// 从 call_annotations 重建搜索文本缓存
    pub fn rebuild_call_search_texts(&mut self) {
        self.call_search_texts = self.call_annotations.iter()
            .map(|(&seq, ann)| (seq, ann.searchable_text()))
            .collect();
    }
}

/// 全局应用状态，支持多 Session（key = session_id）
pub struct AppState {
    pub sessions: RwLock<HashMap<String, SessionState>>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
        }
    }
}
