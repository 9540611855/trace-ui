import { useState, useEffect, useMemo, useRef, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useVirtualizerNoSync } from "../hooks/useVirtualizerNoSync";
import type { FunctionCallEntry, FunctionCallsResult } from "../types/trace";

type FilterType = "all" | "syscall" | "jni";

type FlatRow = {
  type: "group";
  entry: FunctionCallEntry;
  isExpanded: boolean;
} | {
  type: "occurrence";
  seq: number;
  summary: string;
  func_name: string;
};

interface Props {
  sessionId: string | null;
  onJumpToSeq: (seq: number) => void;
}

export default function FunctionListPanel({ sessionId, onJumpToSeq }: Props) {
  const [data, setData] = useState<FunctionCallsResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<FilterType>("all");
  const [search, setSearch] = useState("");
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const parentRef = useRef<HTMLDivElement>(null);

  // Fetch data when sessionId changes
  useEffect(() => {
    if (!sessionId) { setData(null); return; }
    setLoading(true);
    setError(null);
    invoke<FunctionCallsResult>("get_function_calls", { sessionId })
      .then((result) => {
        setData(result);
        setExpanded(new Set());
      })
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  }, [sessionId]);

  // Filter + search
  const filtered = useMemo(() => {
    if (!data) return [];
    let fns = data.functions;
    if (filter === "jni") fns = fns.filter(f => f.is_jni);
    else if (filter === "syscall") fns = fns.filter(f => !f.is_jni);
    if (search) {
      const q = search.toLowerCase();
      fns = fns.filter(f => f.func_name.toLowerCase().includes(q));
    }
    return fns;
  }, [data, filter, search]);

  // Flatten for virtual list
  const rows = useMemo(() => {
    const result: FlatRow[] = [];
    for (const entry of filtered) {
      const isExpanded = expanded.has(entry.func_name);
      result.push({ type: "group", entry, isExpanded });
      if (isExpanded) {
        for (const occ of entry.occurrences) {
          result.push({ type: "occurrence", seq: occ.seq, summary: occ.summary, func_name: entry.func_name });
        }
      }
    }
    return result;
  }, [filtered, expanded]);

  const virtualizer = useVirtualizerNoSync({
    count: rows.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 26,
    overscan: 10,
  });

  const toggleExpand = useCallback((funcName: string) => {
    setExpanded(prev => {
      const next = new Set(prev);
      if (next.has(funcName)) next.delete(funcName);
      else next.add(funcName);
      return next;
    });
  }, []);

  // Stats
  const filteredCalls = useMemo(() => filtered.reduce((sum, f) => sum + f.occurrences.length, 0), [filtered]);

  if (!sessionId) {
    return <div style={{ padding: 12, color: "var(--text-secondary)" }}>No file loaded</div>;
  }

  if (loading) {
    return <div style={{ padding: 12, color: "var(--text-secondary)" }}>Loading...</div>;
  }

  if (error) {
    return <div style={{ padding: 12, color: "var(--text-secondary)" }}>{error}</div>;
  }

  if (!data || data.functions.length === 0) {
    return <div style={{ padding: 12, color: "var(--text-secondary)" }}>No function calls found</div>;
  }

  return (
    <div style={{ height: "100%", display: "flex", flexDirection: "column", background: "var(--bg-primary)" }}>
      {/* Search box */}
      <div style={{ padding: "4px 6px", borderBottom: "1px solid var(--border-color)", flexShrink: 0 }}>
        <input
          type="text"
          placeholder="Search functions..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          style={{
            width: "100%",
            padding: "3px 6px",
            background: "var(--bg-input)",
            border: "1px solid var(--border-color)",
            borderRadius: 3,
            color: "var(--text-primary)",
            fontSize: "var(--font-size-sm)",
            fontFamily: "var(--font-mono)",
            outline: "none",
          }}
        />
      </div>

      {/* Filter buttons */}
      <div style={{ display: "flex", gap: 2, padding: "3px 6px", borderBottom: "1px solid var(--border-color)", flexShrink: 0 }}>
        {(["all", "syscall", "jni"] as FilterType[]).map(f => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            style={{
              flex: 1,
              padding: "2px 0",
              background: filter === f ? "var(--btn-primary)" : "transparent",
              color: filter === f ? "#fff" : "var(--text-secondary)",
              border: filter === f ? "none" : "1px solid var(--border-color)",
              borderRadius: 3,
              fontSize: "var(--font-size-sm)",
              fontFamily: "var(--font-mono)",
              cursor: "pointer",
            }}
          >
            {f === "all" ? "All" : f === "syscall" ? "Syscall" : "JNI"}
          </button>
        ))}
      </div>

      {/* Virtual list */}
      <div ref={parentRef} style={{ flex: 1, overflow: "auto" }}>
        <div style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
          {virtualizer.getVirtualItems().map(vItem => {
            const row = rows[vItem.index];
            if (row.type === "group") {
              const { entry, isExpanded } = row;
              return (
                <div
                  key={`g-${entry.func_name}`}
                  data-index={vItem.index}
                  style={{
                    position: "absolute",
                    top: vItem.start,
                    left: 0,
                    right: 0,
                    height: vItem.size,
                    display: "flex",
                    alignItems: "center",
                    padding: "0 6px",
                    cursor: "pointer",
                    borderBottom: "1px solid var(--border-color)",
                    background: "var(--bg-secondary)",
                    fontSize: "var(--font-size-sm)",
                    userSelect: "none",
                  }}
                  onClick={() => toggleExpand(entry.func_name)}
                >
                  <span style={{ width: 16, flexShrink: 0, color: "var(--text-secondary)" }}>
                    {isExpanded ? "\u25BC" : "\u25B6"}
                  </span>
                  <span style={{
                    color: entry.is_jni ? "var(--asm-immediate)" : "var(--asm-mnemonic)",
                    fontWeight: 500,
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                    flex: 1,
                  }}>
                    {entry.func_name}
                  </span>
                  <span style={{
                    marginLeft: 6,
                    color: "var(--text-secondary)",
                    fontSize: 11,
                    flexShrink: 0,
                  }}>
                    {entry.is_jni ? "JNI" : "SYS"} ({entry.occurrences.length})
                  </span>
                </div>
              );
            } else {
              return (
                <div
                  key={`o-${row.func_name}-${row.seq}`}
                  data-index={vItem.index}
                  style={{
                    position: "absolute",
                    top: vItem.start,
                    left: 0,
                    right: 0,
                    height: vItem.size,
                    display: "flex",
                    alignItems: "center",
                    padding: "0 6px 0 22px",
                    cursor: "pointer",
                    borderBottom: "1px solid var(--border-color)",
                    fontSize: "var(--font-size-sm)",
                  }}
                  onClick={() => onJumpToSeq(row.seq)}
                  onMouseEnter={e => (e.currentTarget.style.background = "var(--bg-selected)")}
                  onMouseLeave={e => (e.currentTarget.style.background = "")}
                >
                  <span style={{ color: "var(--text-address)", marginRight: 8, flexShrink: 0 }}>
                    #{row.seq}
                  </span>
                  <span style={{
                    color: "var(--text-primary)",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}>
                    {row.summary}
                  </span>
                </div>
              );
            }
          })}
        </div>
      </div>

      {/* Status bar */}
      <div style={{
        padding: "3px 8px",
        borderTop: "1px solid var(--border-color)",
        color: "var(--text-secondary)",
        fontSize: 11,
        flexShrink: 0,
        background: "var(--bg-secondary)",
      }}>
        {filtered.length} functions, {filteredCalls} calls
      </div>
    </div>
  );
}
