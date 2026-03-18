# rkyv 零拷贝缓存设计

## 背景

23GB trace 文件首次打开耗时 ~24s（全量扫描），二次打开命中缓存仍需 ~14s。原因是 bincode 反序列化 4.2GB 缓存数据（Phase2 1.5GB + ScanState 2.7GB + LineIndex 5.7MB）需要逐条重建 HashMap、分配堆内存。

## 目标

缓存命中时文件打开耗时从 14s 降至 < 0.5s。

## 核心思路

用 rkyv 零拷贝替代 bincode 反序列化。对纯原始类型结构体使用 `#[rkyv(as = "Self")]` 使 archived 类型 = 原生类型，消除类型差异；对包含 String/Vec 的小结构体（CallTree）从 rkyv 急切反序列化；StringIndex 独立存储为 bincode（可变，scan_strings 需要修改它）。

## 缓存文件布局

### 文件拆分

| 后缀 | 内容 | 序列化 | 加载方式 |
|------|------|--------|---------|
| `.p2.rkyv` | FlatMemAccess + FlatRegCheckpoints + CallTree (rkyv) | rkyv | mmap 零拷贝 + CallTree 急切反序列化 |
| `.scan.rkyv` | FlatDeps + FlatMemLastDef + FlatPairSplit + FlatBitVec + RegLastDef | rkyv | mmap 零拷贝 |
| `.lidx.rkyv` | LineIndex | rkyv | mmap 零拷贝 |
| `.strings.bin` | StringIndex | bincode | 传统反序列化 |

MAGIC 版本号从 `TCACHE03` 升级为 `TCACHE04`，旧缓存自动失效。

### 文件内部格式

```
[0..8]    MAGIC ("TCACHE04")
[8..16]   原始文件大小 (u64 LE)
[16..48]  原始文件前 1MB 的 SHA-256 hash
[48..64]  保留/填充（确保 64 字节对齐）
[64..]    rkyv archived 数据（或 bincode 数据）
```

Header 从 48 字节填充到 **64 字节**，确保 rkyv 数据起始位置 8 字节对齐。

## 数据结构变更

### Phase2 拆分

当前 `Phase2State` 拆分为：

```
Phase2State {                     →  独立字段：
    call_tree: CallTree               call_tree: Option<CallTree>           // 原生，急切反序列化
    mem_accesses: MemAccessIndex      mem_accesses: Option<CachedData<..>>  // 零拷贝
    reg_checkpoints: RegCheckpoints   reg_checkpoints: Option<CachedData<..>> // 零拷贝
    string_index: StringIndex         string_index: Option<StringIndex>     // 独立 bincode
}
```

### 扁平化数据结构（纯原始类型，支持 `#[rkyv(as = "Self")]`）

#### FlatMemAccess（替代 MemAccessIndex 的 FxHashMap）

```rust
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(as = "Self")]
#[repr(C)]
pub struct FlatMemAccessRecord {
    pub seq: u32,
    pub insn_addr: u64,
    pub rw: u8,         // 0=Read, 1=Write（原 MemRw enum）
    pub data: u64,
    pub size: u8,
    pub _pad: [u8; 2],  // 对齐填充
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct FlatMemAccess {
    pub addrs: Vec<u64>,                    // 排序的唯一地址
    pub offsets: Vec<u32>,                  // CSR: addrs[i] 的记录 = records[offsets[i]..offsets[i+1]]
    pub records: Vec<FlatMemAccessRecord>,  // 扁平化记录数组
}
```

查询：`binary_search(&addrs, target_addr)` → `&records[offsets[i]..offsets[i+1]]`。

构建：扫描完成后，从 `FxHashMap<u64, Vec<MemAccessRecord>>` 一次性排序转换。

#### FlatRegCheckpoints（替代 RegCheckpoints）

```rust
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct FlatRegCheckpoints {
    pub interval: u32,
    pub count: u32,         // 快照数量
    pub data: Vec<u64>,     // 扁平化，每 REG_COUNT(235) 个 u64 为一组
}
```

查询：`&data[idx * 235 .. (idx+1) * 235]`。

#### FlatDeps（替代 DepsStorage）

```rust
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct FlatDeps {
    // chunk 信息（Single 时只有 1 个 chunk）
    pub chunk_start_lines: Vec<u32>,
    pub chunk_boundaries: Vec<u64>,  // 每个 chunk 在 all_offsets/all_data 中的 (offsets_start, data_start)
    pub all_offsets: Vec<u32>,       // 所有 chunk 的 offsets 拼接
    pub all_data: Vec<u32>,          // 所有 chunk 的 data 拼接

    // patch groups（跨 chunk 补丁依赖）
    pub patch_lines: Vec<u32>,       // 排序的行号
    pub patch_offsets: Vec<u32>,     // CSR: patch_data[patch_offsets[i]..patch_offsets[i+1]]
    pub patch_data: Vec<u32>,
}
```

查询 `row(global_line)`：
1. `binary_search chunk_start_lines` → chunk_idx
2. 从 `chunk_boundaries[chunk_idx]` 得到该 chunk 的 offsets/data 范围
3. `local = global_line - chunk_start_lines[chunk_idx]`
4. `&all_data[all_offsets[base + local] .. all_offsets[base + local + 1]]`

查询 `patch_row(global_line)`：
1. `binary_search patch_lines` → `&patch_data[patch_offsets[i]..patch_offsets[i+1]]`

#### FlatMemLastDef（替代 MemLastDef::Sorted）

```rust
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct FlatMemLastDef {
    pub addrs: Vec<u64>,   // 排序
    pub lines: Vec<u32>,
    pub values: Vec<u64>,
}
```

查询：`binary_search(&addrs, target)` → `(lines[i], values[i])`。与当前 `MemLastDef::Sorted` 逻辑相同。

#### FlatPairSplit（替代 FxHashMap<u32, PairSplitDeps>）

```rust
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct FlatPairSplit {
    pub keys: Vec<u32>,           // 排序的行号
    pub seg_offsets: Vec<u32>,    // 每个 key 有 3 段起始：[shared_start, half1_start, half2_start]
                                  // seg_offsets.len() = keys.len() * 3 + 1（末尾哨兵）
    pub data: Vec<u32>,           // 扁平化的依赖数据
}
```

查询 `get(line)` → `binary_search keys`：
- `shared = &data[seg_offsets[i*3] .. seg_offsets[i*3+1]]`
- `half1  = &data[seg_offsets[i*3+1] .. seg_offsets[i*3+2]]`
- `half2  = &data[seg_offsets[i*3+2] .. seg_offsets[(i+1)*3]]`

`contains_key(line)` → `keys.binary_search(&line).is_ok()`

#### FlatBitVec（替代 bitvec::BitVec）

```rust
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct FlatBitVec {
    pub data: Vec<u8>,  // 原始字节（小端位序）
    pub len: u32,       // bit 数
}
```

查询：`(data[idx / 8] >> (idx % 8)) & 1 != 0`。

#### LineIndex（已是纯原始类型）

```rust
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct FlatLineIndex {
    pub sampled_offsets: Vec<u64>,
    pub total: u32,
}
```

### 不变的结构体

- **CallTree / CallTreeNode**：包含 `Option<String>` 和 `Vec<u32>`，用 rkyv 标准 archive + 急切反序列化。大小很小（几 MB），反序列化 < 100ms。
- **RegLastDef**：`[u32; 235]` = 940 字节，直接 copy。
- **StringIndex / StringRecord**：独立 bincode 缓存，可变（scan_strings 修改后单独保存）。

## SessionState 变更

```rust
pub struct SessionState {
    pub mmap: Arc<Mmap>,
    pub file_path: String,
    pub total_lines: u32,
    pub file_size: u64,
    pub trace_format: TraceFormat,

    // Phase2 数据（拆分后）
    pub call_tree: Option<CallTree>,
    pub phase2_cache_mmap: Option<Mmap>,          // .p2.rkyv 的 mmap（保持存活）
    pub mem_accesses: Option<PhaseRef<FlatMemAccess>>,
    pub reg_checkpoints: Option<PhaseRef<FlatRegCheckpoints>>,
    pub string_index: Option<StringIndex>,

    // Scan 数据
    pub scan_cache_mmap: Option<Mmap>,             // .scan.rkyv 的 mmap（保持存活）
    pub deps: Option<PhaseRef<FlatDeps>>,
    pub mem_last_def: Option<PhaseRef<FlatMemLastDef>>,
    pub pair_split: Option<PhaseRef<FlatPairSplit>>,
    pub init_mem_loads: Option<PhaseRef<FlatBitVec>>,
    pub reg_last_def: Option<RegLastDef>,

    // LineIndex
    pub lidx_cache_mmap: Option<Mmap>,
    pub line_index: Option<PhaseRef<FlatLineIndex>>,

    // 其余字段不变
    pub slice_result: Option<bitvec::prelude::BitVec>,
    pub scan_strings_cancelled: Arc<AtomicBool>,
    pub call_annotations: HashMap<u32, CallAnnotation>,
    pub consumed_seqs: Vec<u32>,
}
```

### PhaseRef：零拷贝引用或拥有所有权

```rust
pub enum PhaseRef<T> {
    /// 首次扫描生成，拥有所有权
    Owned(T),
    /// 缓存加载，零拷贝引用（指向 *_cache_mmap 中的数据）
    /// offset 是 mmap 中 rkyv 数据的起始偏移（= HEADER_LEN = 64）
    Mapped { offset: usize },
}
```

对于 `#[rkyv(as = "Self")]` 的类型，`PhaseRef<T>` 的 `get()` 方法：
- `Owned(t)` → `&t`
- `Mapped { offset }` → `unsafe { rkyv::access_unchecked::<T>(&mmap[offset..]) }`

由于 archived 类型 = 原生类型，返回值类型一致，调用侧无需区分。

**注意**：`PhaseRef::Mapped` 引用的数据来自 SessionState 中的 `*_cache_mmap` 字段。两者生命周期相同（都在 SessionState 中），安全性由 SessionState 的整体生命周期保证。实际实现中 `PhaseRef` 持有对 mmap 的引用或通过 SessionState 方法提供安全访问。

## 缓存加载流程（命中时）

```
1. detect_format(data)
2. 并行 mmap 3 个 rkyv 缓存文件 + 1 个 bincode 缓存文件
3. 校验每个文件的 header（MAGIC + 文件大小 + SHA-256）
4. Phase2:
   a. mmap .p2.rkyv → phase2_cache_mmap
   b. rkyv::access FlatMemAccess, FlatRegCheckpoints → PhaseRef::Mapped
   c. rkyv::from_bytes CallTree → 原生 CallTree（急切反序列化，< 100ms）
5. Scan:
   a. mmap .scan.rkyv → scan_cache_mmap
   b. rkyv::access 所有 Flat 结构 → PhaseRef::Mapped
   c. copy RegLastDef（940 字节）
6. LineIndex:
   a. mmap .lidx.rkyv → lidx_cache_mmap
   b. rkyv::access FlatLineIndex → PhaseRef::Mapped
7. StringIndex: bincode::deserialize（几百 KB，< 10ms）
8. 写入 SessionState
```

总耗时：< 0.5s（主要是 CallTree 反序列化）。

## 缓存保存流程（首次扫描后）

后台线程中：

```
1. 从 SessionState 读取原生数据
2. 转换为 Flat 格式：
   - MemAccessIndex (HashMap) → FlatMemAccess（排序 + CSR）
   - RegCheckpoints → FlatRegCheckpoints（展平 snapshots）
   - DepsStorage → FlatDeps（拼接 chunks）
   - MemLastDef → FlatMemLastDef（已是 Sorted 变体，直接拆三数组）
   - pair_split (HashMap) → FlatPairSplit（排序 + CSR）
   - init_mem_loads (BitVec) → FlatBitVec
   - LineIndex → FlatLineIndex
3. 写入 rkyv 缓存文件（header + rkyv::to_bytes）
4. 写入 StringIndex bincode 缓存文件
```

## scan_strings 修改流程

```rust
// 之前：
phase2.string_index = new_index;
cache::save_cache(&fp, data, phase2);  // 重新序列化整个 1.5GB Phase2

// 之后：
session.string_index = Some(new_index);
cache::save_string_cache(&fp, data, &new_index);  // 只序列化几百 KB StringIndex
```

## rkyv 缓存文件内部布局

### `.p2.rkyv` 文件

单个 rkyv archive 包含一个顶层结构体：

```rust
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct Phase2Archive {
    pub mem_accesses: FlatMemAccess,
    pub reg_checkpoints: FlatRegCheckpoints,
    pub call_tree: CallTree,  // rkyv 标准 archive（含 ArchivedString 等）
}
```

加载时：
- `mem_accesses` 和 `reg_checkpoints`：零拷贝访问 archived 字段
- `call_tree`：调用 `archived.call_tree.deserialize(...)` 得到原生 `CallTree`

### `.scan.rkyv` 文件

```rust
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct ScanArchive {
    pub deps: FlatDeps,
    pub mem_last_def: FlatMemLastDef,
    pub pair_split: FlatPairSplit,
    pub init_mem_loads: FlatBitVec,
    pub reg_last_def_inner: Vec<u32>,  // [u32; 235] 序列化为 Vec
    pub line_count: u32,
    pub parsed_count: u32,
    pub mem_op_count: u32,
}
```

### `.lidx.rkyv` 文件

```rust
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct LineIndexArchive {
    pub sampled_offsets: Vec<u64>,
    pub total: u32,
}
```

## 受影响的调用点

### Phase2 相关

| 文件 | 当前访问 | 变更 |
|------|---------|------|
| `commands/call_tree.rs:57-62` | `phase2.call_tree.nodes.iter()` | `session.call_tree.as_ref()?.nodes.iter()` — 不变（原生类型） |
| `commands/call_tree.rs:73` | `phase2.call_tree.nodes.len()` | `session.call_tree.as_ref()?.nodes.len()` |
| `commands/call_tree.rs:91,101` | `phase2.call_tree.nodes.get(id)` | `session.call_tree.as_ref()?.nodes.get(id)` |
| `commands/memory.rs:65,80` | `phase2.mem_accesses.get(addr)` | `session.mem_accesses_ref()?.query(addr)` — 返回 `&[FlatMemAccessRecord]` |
| `commands/memory.rs:137` | `phase2.mem_accesses.get(addr)` | 同上 |
| `commands/registers.rs:43-45` | `phase2.reg_checkpoints.get_nearest_before(seq)` | `session.reg_checkpoints_ref()?.nearest_before(seq)` |
| `commands/strings.rs:49` | `phase2.string_index.strings.iter()` | `session.string_index.as_ref()?.strings.iter()` — 不变 |
| `commands/strings.rs:161` | `phase2.mem_accesses.iter_all()` | `session.mem_accesses_ref()?.iter_all()` |
| `commands/strings.rs:196` | `phase2.mem_accesses` (fill_xref_counts) | `session.mem_accesses_ref()?` |
| `commands/strings.rs:204-206` | `phase2.string_index = ..; save_cache(.., phase2)` | `session.string_index = ..; save_string_cache(..)` |
| `commands/index.rs:25` | `phase2.string_index.strings.is_empty()` | `session.string_index.as_ref().map(\|s\| !s.strings.is_empty())` |

### ScanState 相关

| 文件 | 当前访问 | 变更 |
|------|---------|------|
| `taint/slicer.rs:26` | `state.line_count` | `session.scan_line_count()` |
| `taint/slicer.rs:41` | `state.pair_split.get(&line)` | `session.pair_split_ref()?.query(&line)` |
| `taint/slicer.rs:66` | `state.deps.row(line).iter().chain(state.deps.patch_row(line))` | `session.deps_ref()?.row(line).iter().chain(session.deps_ref()?.patch_row(line))` |
| `taint/slicer.rs:86,93` | `pair_split.contains_key(&line)` | `session.pair_split_ref()?.contains(&line)` |
| `commands/slice.rs:36,56` | `scan_state.reg_last_def.get()`, `scan_state.mem_last_def.get()` | `session.reg_last_def.as_ref()?.get()`, `session.mem_last_def_ref()?.query()` |

### MemAccessRecord 类型变更

`FlatMemAccessRecord` 中 `rw` 改为 `u8`，调用侧需要 `rec.rw == 0` (Read) / `rec.rw == 1` (Write) 或提供辅助方法 `rec.is_read()` / `rec.is_write()`。

## 新增依赖

```toml
[dependencies]
rkyv = { version = "0.8", features = ["validation"] }
# bincode 保留（StringIndex 仍用）
```

## 可选优化：madvise 预热

打开文件后在后台线程调用 `madvise(MADV_WILLNEED)` 预热 mmap 数据：

```rust
#[cfg(unix)]
fn prefetch_mmap(mmap: &Mmap) {
    unsafe { libc::madvise(mmap.as_ptr() as _, mmap.len(), libc::MADV_WILLNEED); }
}
```

这不是必须的，但可以减少首次查询的 page fault 延迟。

## 性能预期

| 场景 | 当前 | 改后 |
|------|------|------|
| 首次打开（无缓存） | ~24s | ~24s + 后台转换 Flat 格式（< 2s） |
| 二次打开（缓存命中） | ~14s | **< 0.5s** |
| scan_strings 保存 | ~序列化整个 1.5GB Phase2 | ~序列化几百 KB StringIndex |
| 内存占用 | 堆上 4.2GB+ HashMap 开销 | 文件系统 page cache（OS 可回收） |
