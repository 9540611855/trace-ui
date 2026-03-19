import { useState, useEffect, useCallback, useRef } from "react";
import { emit, emitTo, listen } from "@tauri-apps/api/event";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { invoke } from "@tauri-apps/api/core";
import MemoryPanel from "./components/MemoryPanel";
import FloatingWindowFrame from "./components/FloatingWindowFrame";
import SearchResultList from "./components/SearchResultList";
import StringsPanel from "./components/StringsPanel";
import StringDetailPanel from "./components/StringDetailPanel";
import StringXRefsPanel from "./components/StringXRefsPanel";
import type { SearchMatch, SearchResult } from "./types/trace";

const PANEL_TITLES: Record<string, string> = {
  memory: "Memory",
  accesses: "Accesses",
  "taint-state": "Taint State",
  search: "Search",
  strings: "Strings",
  "string-detail": "String Detail",
  "string-xrefs": "XRefs",
  "call-info": "Call Info",
};

interface SyncState {
  sessionId: string | null;
  selectedSeq: number | null;
  isPhase2Ready: boolean;
  isLoaded: boolean;
  totalLines: number;
  filePath: string | null;
}

export default function FloatingPanel({ panel }: { panel: string }) {
  const title = PANEL_TITLES[panel] ?? panel;

  const [syncState, setSyncState] = useState<SyncState>({
    sessionId: null,
    selectedSeq: null,
    isPhase2Ready: false,
    isLoaded: false,
    totalLines: 0,
    filePath: null,
  });

  // Search 面板状态
  const [searchResults, setSearchResults] = useState<SearchMatch[]>([]);
  const [searchQuery, setSearchQuery] = useState("");
  const [isSearching, setIsSearching] = useState(false);
  const [searchStatus, setSearchStatus] = useState("");
  const [searchTotalMatches, setSearchTotalMatches] = useState(0);

  // 初始化：发送 panel:ready
  useEffect(() => {
    emitTo("main", "panel:ready", { panel });
  }, [panel]);

  // 监听主窗口同步事件
  useEffect(() => {
    const unlisteners: Promise<() => void>[] = [];

    unlisteners.push(listen<SyncState>("sync:init-state", (e) => {
      setSyncState(e.payload);
    }));

    unlisteners.push(listen<{ seq: number | null }>("sync:selected-seq", (e) => {
      setSyncState(prev => ({ ...prev, selectedSeq: e.payload.seq }));
    }));

    unlisteners.push(listen<{ ready: boolean }>("sync:phase2-ready", (e) => {
      setSyncState(prev => ({ ...prev, isPhase2Ready: e.payload.ready }));
    }));

    unlisteners.push(listen<{ isLoaded: boolean; totalLines: number; filePath: string | null }>("sync:file-state", (e) => {
      setSyncState(prev => ({
        ...prev,
        isLoaded: e.payload.isLoaded,
        totalLines: e.payload.totalLines,
        filePath: e.payload.filePath,
      }));
    }));

    unlisteners.push(listen<{ sessionId: string | null }>("sync:session-id", (e) => {
      setSyncState(prev => ({ ...prev, sessionId: e.payload.sessionId }));
    }));

    return () => { unlisteners.forEach(p => p.then(fn => fn())); };
  }, []);

  // Search 面板：监听主窗口搜索转发
  const handleSearch = useCallback(async (query: string) => {
    if (!query.trim() || !syncState.sessionId) return;
    setSearchQuery(query);
    setIsSearching(true);
    setSearchResults([]);
    setSearchTotalMatches(0);
    setSearchStatus("Searching...");
    try {
      const result = await invoke<SearchResult>("search_trace", {
        sessionId: syncState.sessionId,
        request: { query, max_results: 10000 },
      });
      setSearchResults(result.matches);
      setSearchTotalMatches(result.total_matches);
      const status = result.total_matches > 0
        ? `${result.total_matches.toLocaleString()} results${result.truncated ? " (truncated)" : ""}`
        : "No results";
      setSearchStatus(status);
      // 同步搜索结果回主窗口，关闭浮窗后 search tab 能保留数据
      emit("sync:search-results-back", {
        results: result.matches,
        query,
        status,
        totalMatches: result.total_matches,
      });
    } catch (e) {
      setSearchStatus(`Error: ${e}`);
    } finally {
      setIsSearching(false);
    }
  }, [syncState.sessionId]);

  useEffect(() => {
    if (panel !== "search") return;
    const unlisten = listen<{ query: string }>("action:trigger-search", (e) => {
      handleSearch(e.payload.query);
    });
    return () => { unlisten.then(fn => fn()); };
  }, [panel, handleSearch]);

  // Search 面板：接收主窗口同步的已有搜索结果
  useEffect(() => {
    if (panel !== "search") return;
    const unlisten = listen<{ results: SearchMatch[]; query: string; status: string; totalMatches: number }>("sync:search-state", (e) => {
      setSearchResults(e.payload.results);
      setSearchQuery(e.payload.query);
      setSearchStatus(e.payload.status);
      setSearchTotalMatches(e.payload.totalMatches);
      setIsSearching(false);
    });
    return () => { unlisten.then(fn => fn()); };
  }, [panel]);

  // Esc 关闭搜索浮窗
  useEffect(() => {
    if (panel !== "search") return;
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        getCurrentWindow().close();
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [panel]);

  const handleJumpToSeq = useCallback((seq: number) => {
    emit("action:jump-to-seq", { seq });
  }, []);

  const handleJumpToSearchMatch = useCallback((match: SearchMatch) => {
    if (match.call_info) {
      emit("action:jump-to-search-match", { seq: match.seq });
      return;
    }
    handleJumpToSeq(match.seq);
  }, [handleJumpToSeq]);

  const renderPanelContent = () => {
    switch (panel) {
      case "memory":
        return (
          <MemoryPanel
            selectedSeq={syncState.selectedSeq}
            isPhase2Ready={syncState.isPhase2Ready}
            onJumpToSeq={handleJumpToSeq}
            sessionId={syncState.sessionId}
          />
        );
      case "search":
        return (
          <FloatingSearchContent
            searchResults={searchResults}
            searchQuery={searchQuery}
            isSearching={isSearching}
            searchStatus={searchStatus}
            onJumpToSeq={handleJumpToSeq}
            onJumpToMatch={handleJumpToSearchMatch}
            onSearch={handleSearch}
          />
        );
      case "strings":
        return (
          <StringsPanel
            sessionId={syncState.sessionId}
            isPhase2Ready={syncState.isPhase2Ready}
            onJumpToSeq={handleJumpToSeq}
          />
        );
      case "string-detail":
        return <StringDetailPanel />;
      case "string-xrefs":
        return <StringXRefsPanel />;
      case "call-info":
        return <CallInfoContent />;
      default:
        return (
          <div style={{
            height: "100%",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
          }}>
            <span style={{ color: "var(--text-secondary)", fontSize: 12 }}>
              {title} — Panel not yet implemented
            </span>
          </div>
        );
    }
  };

  return (
    <FloatingWindowFrame title={title}>
      {/* 面板内容 */}
      <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
        {renderPanelContent()}
      </div>
    </FloatingWindowFrame>
  );
}

function FloatingSearchContent({
  searchResults, searchQuery, isSearching, searchStatus,
  onJumpToSeq, onJumpToMatch, onSearch,
}: {
  searchResults: SearchMatch[];
  searchQuery: string;
  isSearching: boolean;
  searchStatus: string;
  onJumpToSeq: (seq: number) => void;
  onJumpToMatch: (match: SearchMatch) => void;
  onSearch: (query: string) => void;
}) {
  const [localQuery, setLocalQuery] = useState(searchQuery);
  const inputRef = useRef<HTMLInputElement>(null);

  // 初始化时自动聚焦输入框
  useEffect(() => {
    setTimeout(() => inputRef.current?.focus(), 100);
  }, []);

  // 监听 search:focus-input 事件（Ctrl+F 触发已有浮窗时聚焦）
  useEffect(() => {
    const unlisten = listen("search:focus-input", () => {
      inputRef.current?.focus();
      inputRef.current?.select();
    });
    return () => { unlisten.then(fn => fn()); };
  }, []);

  useEffect(() => { setLocalQuery(searchQuery); }, [searchQuery]);

  return (
    <div style={{ height: "100%", display: "flex", flexDirection: "column" }}>
      {/* 搜索输入框 */}
      <div style={{
        display: "flex", gap: 8, padding: "6px 8px",
        borderBottom: "1px solid var(--border-color)", flexShrink: 0,
      }}>
        <div style={{ flex: 1, position: "relative" }}>
          <input
            ref={inputRef}
            type="text"
            placeholder="Search text or /regex/"
            value={localQuery}
            onChange={(e) => setLocalQuery(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && onSearch(localQuery)}
            style={{
              width: "100%", padding: "4px 26px 4px 8px",
              background: "var(--bg-input)", color: "var(--text-primary)",
              border: "1px solid var(--border-color)", borderRadius: 4,
              fontFamily: "var(--font-mono)", fontSize: "var(--font-size-sm)",
            }}
          />
          {localQuery && (
            <button
              onClick={() => setLocalQuery("")}
              style={{
                position: "absolute", right: 4, top: "50%", transform: "translateY(-50%)",
                width: 18, height: 18, padding: 0,
                display: "flex", alignItems: "center", justifyContent: "center",
                background: "transparent", color: "var(--text-secondary)",
                border: "none", borderRadius: 3, cursor: "pointer",
                fontSize: 12, lineHeight: 1,
              }}
              onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.color = "var(--text-primary)"; (e.currentTarget as HTMLElement).style.background = "var(--bg-secondary)"; }}
              onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.color = "var(--text-secondary)"; (e.currentTarget as HTMLElement).style.background = "transparent"; }}
              title="Clear search"
            >✕</button>
          )}
        </div>
        <button
          onClick={() => onSearch(localQuery)}
          style={{
            padding: "4px 12px", background: "var(--bg-input)",
            color: "var(--text-primary)", border: "1px solid var(--border-color)",
            borderRadius: 4, cursor: "pointer",
          }}
        >Search</button>
      </div>

      {/* 结果列表 */}
      {isSearching ? (
        <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center" }}>
          <span style={{ color: "var(--text-secondary)", fontSize: 12 }}>Searching...</span>
        </div>
      ) : searchResults.length === 0 ? (
        <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center" }}>
          <span style={{ color: "var(--text-secondary)", fontSize: 12 }}>
            {searchQuery ? `No results found for "${searchQuery}"` : "Enter search query and press Enter"}
          </span>
        </div>
      ) : (
        <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
          <SearchResultList
            results={searchResults}
            selectedSeq={null}
            onJumpToSeq={onJumpToSeq}
            onJumpToMatch={onJumpToMatch}
          />
        </div>
      )}

      {/* 状态栏 */}
      {searchStatus && (
        <div style={{
          padding: "3px 8px", flexShrink: 0,
          borderTop: "1px solid var(--border-color)",
          background: "var(--bg-secondary)",
          fontSize: 11, color: "var(--text-secondary)",
        }}>
          {searchStatus}
        </div>
      )}
    </div>
  );
}

function CallInfoContent() {
  const [info, setInfo] = useState<{ text: string; isJni: boolean } | null>(null);

  // 事件方案：先注册数据监听，再发送 ready 信号
  useEffect(() => {
    const unlisten = listen<{ text: string; isJni: boolean }>("call-info:init-data", (e) => {
      setInfo(e.payload);
    });
    const winLabel = getCurrentWindow().label;
    emit(`call-info:ready:${winLabel}`);
    return () => { unlisten.then(fn => fn()); };
  }, []);

  // Esc 关闭窗口
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        getCurrentWindow().close();
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);

  if (!info) {
    return (
      <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center" }}>
        <span style={{ color: "var(--text-secondary)", fontSize: 12 }}>No data</span>
      </div>
    );
  }

  return (
    <div style={{
      flex: 1,
      overflow: "auto",
      padding: "8px 12px",
      fontSize: 12,
      fontFamily: '"JetBrains Mono", "Fira Code", monospace',
      color: "var(--text-primary, #abb2bf)",
      whiteSpace: "pre",
      borderTop: `2px solid ${info.isJni ? "#c792ea" : "#56d4dd"}`,
    }}>
      {info.text}
    </div>
  );
}
