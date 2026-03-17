import { useRef, useCallback, useEffect, useState } from "react";
import { useVirtualizerNoSync } from "../hooks/useVirtualizerNoSync";
import type { SearchMatch, TraceLine } from "../types/trace";
import type { ResolvedRow } from "../hooks/useFoldState";
import DisasmHighlight from "./DisasmHighlight";
import Minimap, { MINIMAP_WIDTH } from "./Minimap";
import { useSelectedSeq } from "../stores/selectedSeqStore";
import CustomScrollbar from "./CustomScrollbar";

interface SearchResultListProps {
  results: SearchMatch[];
  selectedSeq?: number | null;
  onJumpToSeq: (seq: number) => void;
  changesWidth?: number;
  onResizeChanges?: (e: React.MouseEvent) => void;
}

export default function SearchResultList({
  results,
  selectedSeq: selectedSeqProp,
  onJumpToSeq,
  changesWidth = 300,
  onResizeChanges,
}: SearchResultListProps) {
  const selectedSeqFromStore = useSelectedSeq();
  const selectedSeq = selectedSeqProp !== undefined ? selectedSeqProp : selectedSeqFromStore;

  const parentRef = useRef<HTMLDivElement>(null);
  const [selectedIdx, setSelectedIdx] = useState<number | null>(null);
  const [scrollRow, setScrollRow] = useState(0);
  const [containerHeight, setContainerHeight] = useState(0);

  const virtualizer = useVirtualizerNoSync({
    count: results.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 22,
    overscan: 20,
  });

  const handleRowClick = useCallback((match: SearchMatch, idx: number) => {
    setSelectedIdx(idx);
    onJumpToSeq(match.seq);
  }, [onJumpToSeq]);

  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key !== "ArrowUp" && e.key !== "ArrowDown") return;
    e.preventDefault();
    const len = results.length;
    if (len === 0) return;
    const cur = selectedIdx ?? -1;
    const next = e.key === "ArrowDown" ? Math.min(cur + 1, len - 1) : Math.max(cur - 1, 0);
    setSelectedIdx(next);
    onJumpToSeq(results[next].seq);
    virtualizer.scrollToIndex(next, { align: "auto" });
  }, [results, selectedIdx, onJumpToSeq, virtualizer]);

  // 滚动与容器尺寸监听
  useEffect(() => {
    const el = parentRef.current;
    if (!el) return;
    const handleScroll = () => { setScrollRow(Math.floor(el.scrollTop / 22)); };
    let timer = 0;
    const ro = new ResizeObserver((entries) => {
      clearTimeout(timer);
      const h = entries[0].contentRect.height;
      timer = window.setTimeout(() => { setContainerHeight(h); },
        document.documentElement.dataset.separatorDrag ? 300 : 0);
    });
    el.addEventListener("scroll", handleScroll);
    ro.observe(el);
    return () => { clearTimeout(timer); el.removeEventListener("scroll", handleScroll); ro.disconnect(); };
  }, [results.length]);

  // Minimap 适配函数
  const searchResolve = useCallback((vi: number): ResolvedRow => {
    return { type: "line", seq: results[vi]?.seq ?? vi } as ResolvedRow;
  }, [results]);

  const searchGetLines = useCallback(async (seqs: number[]): Promise<TraceLine[]> => {
    const seqSet = new Set(seqs);
    return results.filter(r => seqSet.has(r.seq)) as unknown as TraceLine[];
  }, [results]);

  const visibleRows = Math.floor(containerHeight / 22);
  const maxRow = Math.max(0, results.length - visibleRows);

  return (
    <>
      {/* 表头 */}
      <div style={{
        display: "flex", padding: "4px 8px",
        background: "var(--bg-secondary)",
        borderBottom: "1px solid var(--border-color)",
        fontSize: "var(--font-size-sm)", color: "var(--text-secondary)", flexShrink: 0,
      }}>
        <span style={{ width: 48, flexShrink: 0 }}></span>
        <span style={{ width: 30, flexShrink: 0 }}>R/W</span>
        <span style={{ width: 90, flexShrink: 0 }}>#</span>
        <span style={{ width: 90, flexShrink: 0 }}>Address</span>
        <span style={{ flex: 1 }}>Disassembly</span>
        {onResizeChanges && (
          <div
            onMouseDown={onResizeChanges}
            style={{
              width: 8, cursor: "col-resize", flexShrink: 0,
              display: "flex", alignItems: "center", justifyContent: "center",
            }}
          >
            <div style={{ width: 1, height: "100%", background: "var(--border-color)" }} />
          </div>
        )}
        <span style={{ width: changesWidth, flexShrink: 0 }}>Changes</span>
        <span style={{ width: MINIMAP_WIDTH + 12, flexShrink: 0 }}></span>
      </div>

      {/* 列表 + Minimap */}
      <div style={{ flex: 1, display: "flex", overflow: "hidden" }}>
        <div
          ref={parentRef}
          tabIndex={0}
          onKeyDown={handleKeyDown}
          style={{ flex: 1, overflow: "auto", outline: "none", scrollbarWidth: "none", fontSize: "var(--font-size-sm)" } as React.CSSProperties}
        >
          <div style={{ height: virtualizer.getTotalSize(), width: "100%", position: "relative" }}>
            {virtualizer.getVirtualItems().map((vRow) => {
              const match = results[vRow.index];
              if (!match) return null;
              const isSelected = selectedIdx === vRow.index;
              return (
                <div
                  key={vRow.index}
                  onClick={() => handleRowClick(match, vRow.index)}
                  style={{
                    position: "absolute", top: 0, left: 0, width: "100%", height: 22,
                    transform: `translateY(${vRow.start}px)`,
                    display: "flex", alignItems: "center", padding: "0 8px",
                    cursor: "pointer", fontSize: "var(--font-size-sm)",
                    background: isSelected ? "var(--bg-selected)"
                      : vRow.index % 2 === 0 ? "var(--bg-row-even)" : "var(--bg-row-odd)",
                  }}
                  onMouseEnter={(e) => { if (!isSelected) e.currentTarget.style.background = "rgba(255,255,255,0.04)"; }}
                  onMouseLeave={(e) => { if (!isSelected) e.currentTarget.style.background = vRow.index % 2 === 0 ? "var(--bg-row-even)" : "var(--bg-row-odd)"; }}
                >
                  <span style={{ width: 48, flexShrink: 0 }}></span>
                  <span style={{ width: 30, flexShrink: 0, color: "var(--text-secondary)" }}>
                    {match.mem_rw === "W" ? "W" : match.mem_rw === "R" ? "R" : ""}
                  </span>
                  <span style={{ width: 90, flexShrink: 0, color: "var(--text-secondary)" }}>{match.seq + 1}</span>
                  <span style={{ width: 90, flexShrink: 0, color: "var(--text-address)" }}>{match.address}</span>
                  <span style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    <DisasmHighlight text={match.disasm} />
                    {match.call_info && (
                      <span style={{
                        marginLeft: 8,
                        fontStyle: "italic",
                        color: match.call_info.is_jni ? "var(--asm-immediate)" : "var(--text-secondary)",
                      }}
                        title={match.call_info.tooltip}
                      >
                        {match.call_info.summary.length > 80
                          ? match.call_info.summary.slice(0, 80) + "..."
                          : match.call_info.summary}
                      </span>
                    )}
                  </span>
                  <span style={{ width: changesWidth, color: "var(--text-changes)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{match.changes}</span>
                </div>
              );
            })}
          </div>
        </div>
        {containerHeight > 0 && (
          <div style={{ width: MINIMAP_WIDTH + 12, flexShrink: 0, position: "relative" }}>
            <Minimap
              virtualTotalRows={results.length}
              visibleRows={visibleRows}
              currentRow={scrollRow}
              maxRow={maxRow}
              height={containerHeight}
              onScroll={(row) => { parentRef.current?.scrollTo({ top: row * 22 }); }}
              resolveVirtualIndex={searchResolve}
              getLines={searchGetLines}
              selectedSeq={selectedSeq}
              rightOffset={12}
            />
            <CustomScrollbar
              currentRow={scrollRow}
              maxRow={maxRow}
              visibleRows={visibleRows}
              virtualTotalRows={results.length}
              trackHeight={containerHeight}
              onScroll={(row) => { parentRef.current?.scrollTo({ top: row * 22 }); }}
            />
          </div>
        )}
      </div>
    </>
  );
}
