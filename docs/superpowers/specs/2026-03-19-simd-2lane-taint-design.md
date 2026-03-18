# SIMD 寄存器 2-Lane 污点追踪精度修复

**日期**: 2026-03-19
**范围**: 将每个 v 寄存器拆分为 lo/hi 两个 64-bit lane，精确追踪 lane 级部分写入操作的依赖

## 问题

当前系统将 `s0/d0/q0/b0/h0` 全部归一化到同一个 `RegId::V0`，每个 v 寄存器只有一个 `reg_last_def` 条目。当 lane 级操作（`ins v0.d[1]`、`fmov v0.d[1]`、`ld1 {v0.s}[3]`）仅修改寄存器的一部分时，系统将其视为整个寄存器的 DEF，切断了未修改部分的旧依赖链。

**具体场景**：
```asm
ldr q0, [x1]        ; line 0: 加载 128-bit → DEF V0
ins v0.d[1], x8     ; line 1: 仅写高 64-bit → 当前: DEF V0（错误地覆盖整个寄存器的 last_def）
mov x9, v0.d[0]     ; line 2: 读低 64-bit → 当前: 依赖 line 1（错误，应该依赖 line 0）
```

**重要澄清**：ARM64 ISA 规定所有 SIMD 标量 load（`ldr s/d/q`）都会将未写入的高位清零到 128 位，因此 `ldr s0` 和 `ldr q0` 在污点追踪层面都是完整的 128-bit DEF。此修复主要针对 **lane 级部分写入操作**（`ins`、`fmov v.d[1]`、`ld1 lane`、`ext` 等），这类操作在密码学代码（AES/SHA）中频繁出现。

## 方案

将每个 v 寄存器拆分为 2 个 sub-lane RegId（lo 64-bit / hi 64-bit），在 DEF/USE 分析阶段根据操作类型精确展开到对应的 lane。

## 修改文件与内容

### 1. `src/taint/types.rs` — RegId 扩展

**当前**：
- `RegId(0..30)` = x0..x30
- `RegId(31)` = sp
- `RegId(32)` = xzr
- `RegId(33..64)` = v0..v31（统一 128-bit）
- `RegId(65)` = nzcv
- `COUNT = 66`

**改为**：
- `RegId(33..64)` 重新定义为 **v0_lo..v31_lo**（低 64-bit lane）
- 新增 `RegId(66..97)` = **v0_hi..v31_hi**（高 64-bit lane）
- `COUNT = 98`

新增辅助方法：
```rust
impl RegId {
    /// v0_lo(33) → v0_hi(66)，仅对 SIMD lo-lane 有效
    pub fn simd_hi(self) -> Option<RegId> {
        if self.0 >= 33 && self.0 <= 64 {
            Some(RegId(self.0 + 33))
        } else {
            None
        }
    }

    /// 判断是否为 SIMD lo-lane
    pub fn is_simd_lo(self) -> bool { self.0 >= 33 && self.0 <= 64 }

    /// 判断是否为 SIMD hi-lane
    pub fn is_simd_hi(self) -> bool { self.0 >= 66 && self.0 <= 97 }

    /// 判断是否为 SIMD（lo 或 hi）
    pub fn is_simd(self) -> bool { self.is_simd_lo() || self.is_simd_hi() }
}
```

更新 `Display` 实现，66-97 范围显示为 `v{N}_hi`。

`parse_reg` 不变：所有 SIMD 寄存器名（s/d/q/b/h/v）仍 parse 到 lo-lane RegId。宽度区分在 DEF/USE 阶段处理。

### 2. `src/taint/scanner.rs` — RegLastDef 扩展

`RegLastDef` 内部数组从 `[u32; 66]` 扩展为 `[u32; 98]`。

`big_array` serde 模块需适配新大小（或用 `serde_big_array` 宏重新生成）。

前向扫描中 Step 4（reg_last_def 更新）的 SIMD DEF 写入逻辑：

- **完整 128-bit DEF**（大部分 SIMD 指令、所有 SIMD load/store）：同时更新 `reg_last_def[v_lo]` 和 `reg_last_def[v_hi]`
- **仅 lo-lane DEF**（lane 操作 lane_index ∈ {0,1} 对应 d[0]/s[0]/s[1]）：仅更新 `reg_last_def[v_lo]`
- **仅 hi-lane DEF**（lane 操作 lane_index 对应 d[1]/s[2]/s[3]）：仅更新 `reg_last_def[v_hi]`

### 3. `src/taint/def_use.rs` — DEF/USE 展开

核心变更：`determine_def_use()` 返回的 defs/uses 中，SIMD RegId 需要按操作类型展开。

新增辅助函数：
```rust
/// 将 SIMD lo-lane RegId 展开为 lo+hi 两个 RegId（128-bit 完整操作）
fn expand_simd_full(reg: RegId) -> SmallVec<[RegId; 2]> {
    if let Some(hi) = reg.simd_hi() {
        smallvec![reg, hi]
    } else {
        smallvec![reg]
    }
}

/// 根据 lane_index 判断属于 lo 还是 hi lane
fn simd_lane_reg(reg: RegId, lane_index: u8, elem_width: u8) -> RegId {
    // d[0], s[0], s[1] → lo lane; d[1], s[2], s[3] → hi lane
    let byte_offset = lane_index as u32 * elem_width as u32;
    if byte_offset >= 8 {
        reg.simd_hi().unwrap_or(reg)
    } else {
        reg  // lo lane
    }
}
```

**各 InsnClass 的展开规则**：

| InsnClass | DEF 展开 | USE 展开 |
|-----------|---------|---------|
| SimdArith / SimdMisc / SimdMove | lo+hi（128-bit 完整写入） | lo+hi（保守，见下文） |
| SimdRMW | lo+hi（128-bit RMW） | lo+hi（读旧值 + 源操作数） |
| SimdLoad（非 lane） | lo+hi（scalar load 清零高位） | 不变（base 寄存器是 x-reg） |
| SimdStore（非 lane） | 不变（writeback base 是 x-reg） | lo+hi（读完整寄存器写入内存） |
| SimdLaneLoad | 仅目标 lane 的 lo 或 hi | 旧值的 lo 或 hi + base |
| SimdRMW（lane 操作如 ins） | 仅目标 lane 的 lo 或 hi | 旧值的 lo 或 hi + 源操作数 |

**非内存 SIMD 指令的 USE**：当前 `ParsedLine` 不存储 arrangement specifier（`.4s` vs `.2s`），无法区分 64-bit 和 128-bit 操作。**保守策略：默认 USE lo+hi（128-bit）**，安全的过近似（多追踪，不会漏追踪）。DEF 无此问题（ARM64 64-bit SIMD op 清零高位 = 完整 DEF）。

### 4. `src/taint/insn_class.rs` — Lane 操作识别

需要扩展 lane 操作的识别逻辑，确保以下指令被正确分类为 lane 操作（SimdRMW 或 SimdLaneLoad）：

- `ins v0.d[1], x8` / `ins v0.s[2], w8` — 已有 SimdRMW
- `fmov v0.d[1], x8` — 需确认分类为 SimdRMW
- `ld1 {v0.s}[N], [x1]` — 已有 SimdLaneLoad
- `ext v0.16b, v1.16b, v2.16b, #N` — 128-bit 完整操作，不是 lane op

### 5. `src/taint/slicer.rs` — 后向切片

**无需修改**。lo/hi 拆分后，依赖边自然区分两个 lane。BFS 遍历的是 deps 数组中的行号，不涉及 RegId 解释。

### 6. `src/cache.rs` — 缓存兼容性

`MAGIC` 从 `b"TCACHE02"` 升级为 `b"TCACHE03"`。旧缓存自动失效，首次加载时重建。

### 7. 前端展示

`resolve_taint_*` 系列函数返回的寄存器变化信息中，如果涉及 SIMD hi-lane RegId，需要在显示时合并回完整寄存器名（如 `v0_hi` → 显示为 `v0` 的一部分）。具体影响取决于前端如何使用 RegId 显示名称，可能需要小幅调整。

## Lane 映射规则

```
128-bit register: |  hi (64-bit)  |  lo (64-bit)  |
                  | s[3] | s[2]   | s[1] | s[0]   |
                  |    d[1]       |    d[0]        |
                  |           q (full)              |

lane_index + elem_width → byte_offset → lo or hi:
  d[0] → offset 0  → lo
  d[1] → offset 8  → hi
  s[0] → offset 0  → lo
  s[1] → offset 4  → lo
  s[2] → offset 8  → hi
  s[3] → offset 12 → hi
  b[0..7]  → lo
  b[8..15] → hi
  h[0..3]  → lo
  h[4..7]  → hi
```

## 性能影响

- RegLastDef：264B → 392B（+128B），仍在 L1 缓存内
- 每条 SIMD 指令的 DEF/USE 最多多 1 个 RegId → deps 数组约增长 10-20%（SIMD 密集 trace）
- 前向扫描：约 5-10% 慢
- 后向 BFS：约 10% 慢
- 整体用户感知：极小

## 不在范围内

- 4-lane（32-bit 粒度）拆分 — 未来可升级
- 非内存 SIMD 指令的 arrangement specifier 解析 — 当前保守处理为 128-bit
- w/x 寄存器宽度区分 — ARM64 w 写入零扩展到 x，当前行为已正确
