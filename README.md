# Easy Decompiler

Binary static analysis and dual-engine C-like decompiler runtime executed in browser Web Worker threads via WebAssembly. Provides disassembly, control flow graph (CFG) generation, function boundary reconstruction, string cross-referencing, and C-like pseudocode generation for x86, x86-64, ARM, AArch64, MIPS, RISC-V, PowerPC, and WebAssembly targets.

## System Architecture

The application is structured around a decoupled worker-thread architecture. Heavy binary parsing, disassembly, control-flow graph construction, and decompilation run inside dedicated Web Workers to ensure the main UI thread remains responsive during compute-intensive tasks.

```
+-----------------------------------------------------------------------+
|                            Main UI Thread                             |
|  - React 19 SPA Workbench                                             |
|  - Virtualized Disassembly / Hex Viewers                              |
|  - CFG & Call Graph Canvas Renderers                                  |
+-------------------+-------------------------------+-------------------+
                    | MessageChannel (postMessage)  | MessageChannel (postMessage)
                    | (Transferable ArrayBuffers)   | (Transferable ArrayBuffers)
                    v                               v
+------------------------------------+  +-------------------------------+
|      Worker A: Rizin + jsdec       |  |   Worker B: Ghidra WASM Core  |
| - WebAssembly Rizin Analysis Core  |  | - WebAssembly Ghidra C++ Core |
| - Recursive Disassembler           |  | - Sleigh Spec Engine (.sla)   |
| - CFG & Basic Block Extraction     |  | - C-like AST Decompiler       |
| - Heuristic Function Classifier    |  | - Type & Variable Recovery    |
| - Shannon Entropy & Headers Parser |  +-------------------------------+
+------------------------------------+
                    |
                    v Local Persistence
+------------------------------------+
|         IndexedDB Storage          |
| - Custom Symbols & Function Names  |
| - User Comments & Cross-References |
+------------------------------------+
```

### Thread Model and Communication

1. **Main UI Thread**:
   - Manages state, layout docking, user events, and view synchronization.
   - Renders interactive assembly with opcode byte displays, cross-reference links, and jump targets.
   - Renders 2D canvas control flow graphs with hierarchical block placement and edge routing.
   - Dispatches jobs to workers via standard HTML5 `postMessage` interfaces.

2. **Engine Worker A (`rizin-jsdec.worker.ts`)**:
   - Compiles Rizin C core into WebAssembly.
   - Operates a virtualized session for binary inspection, string extraction, relocation analysis, and imports/exports parsing.
   - Integrates the `jsdec` decompiler engine for rule-based assembly-to-C translation across architectures.
   - Classifies functions by call topology (entry, exported, imported, thunk, recursive, constructor, stub).

3. **Engine Worker B (`ghidra.worker.ts`)**:
   - Compiles the Ghidra decompiler C++ codebase into WebAssembly.
   - Uses Sleigh processor specification binaries (`.sla`) and compiler definitions (`.cspec`, `.pspec`) fetched on demand.
   - Implements data-flow analysis, register renaming, control-flow structuring, and variable recovery to produce typed C pseudocode.

4. **Storage Layer (`local-db.ts`)**:
   - Backed by browser IndexedDB.
   - Persists project metadata, symbol renames, comments, and navigation history locally.
   - Does not perform network synchronization.

### Memory Isolation and Sandbox Boundary

- **Isolated Execution**: Web Workers run in a `DedicatedWorkerGlobalScope` without DOM access or local storage access outside of explicit message passing.
- **Network Boundaries**: Binary analysis and decompilation routines run offline within the client. The only outbound HTTP requests during runtime are for local static assets (processor `.sla` specifications and sample binaries).
- **Buffer Transfer**: Multi-megabyte executable payloads are transferred to the worker threads using transferable `ArrayBuffer` objects, avoiding memory duplication in the browser heap.
- **Resource Limits**: Worker operations are governed by watchdog timers to terminate stuck analysis runs on malformed or malicious inputs.

## Supported Binary Formats

The parser layer inspects headers and validates file structure across executable formats:

| Format | Magic Identifier | Supported Architectures | Endianness | Base Address Handling | Header & Section Parsing |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **ELF32 / ELF64** | `7F 45 4C 46` (`\x7fELF`) | x86, AMD64, ARM, AArch64, MIPS, RISC-V, PowerPC | Little / Big | Fixed `0x400000` (64-bit), `0x8048000` (32-bit), or `0x0` (PIE) | ELF Header, Program Headers, Section Headers, `.symtab`, `.dynsym`, `.strtab`, Relocations |
| **PE32 / PE32+** | `4D 5A` (DOS) / `50 45 00 00` (PE) | x86, AMD64, ARM, ARM64 | Little | Derived from `ImageBase` (Optional Header) | DOS Header, PE Header, Optional Header, Data Directories (Export, Import, Relocation, TLS, Debug) |
| **Mach-O 32/64** | `FEEDFACE`, `CEFAEDFE`, `FEEDFACF`, `CFFAEDFE` | x86, AMD64, ARM, ARM64 (Apple Silicon) | Little / Big | `0x100000000` (64-bit), `0x1000` (32-bit) | `mach_header`, Load Commands (`LC_SEGMENT`, `LC_SYMTAB`, `LC_DYSYMTAB`, `LC_MAIN`) |
| **WebAssembly** | `00 61 73 6D` (`\0asm`) | wasm32 | Little | `0x0` (Virtual VM offset) | WASM Sections: Type, Import, Function, Table, Memory, Global, Export, Code, Custom |
| **Raw Binary** | None (Fallback) | Configurable | Little / Big | `0x0` or user-defined | Shannon entropy calculation, sliding-window string analysis, byte distribution statistics |

## Memory and Data Structures

### Binary Metadata Record

```typescript
export interface BinaryMetadata {
  filename: string;
  size: number;
  sha256: string;
  format: string;
  architecture: string;
  bits: 16 | 32 | 64;
  endianness: 'little' | 'big';
  entryPoint: string;
  baseAddress: string;
  compiler: string;
  os: string;
  abi: string;
  machine: string;
  subsystem: string;
  hasSymbols: boolean;
  isStripped: boolean;
  isPackedOrProtected: boolean;
  packerDetails: string;
  entropy: number;
  libraries: string[];
}
```

### Function Information Record

```typescript
export interface FunctionInfo {
  address: string;
  virtualAddress: number;
  fileOffset: number;
  name: string;
  originalName: string;
  autoName: string;
  size: number;
  basicBlocksCount: number;
  edgesCount: number;
  callersCount: number;
  calleesCount: number;
  callers: string[];
  callees: string[];
  signature: string;
  callingConvention: string;
  category: FunctionCategory;
  isRecursive: boolean;
  isThunk: boolean;
  isExported: boolean;
  isImported: boolean;
  localVars: Array<{ name: string; type: string; offset: string; kind: 'stack' | 'reg' | 'arg' }>;
  stringsReferenced: string[];
  importsUsed: string[];
}
```

### Control Flow Graph Structure

```typescript
export interface CfgBlock {
  id: string;
  address: string;
  virtualAddress: number;
  size: number;
  label: string;
  isEntry: boolean;
  isExit: boolean;
  isLoopHeader: boolean;
  jump?: string;
  fail?: string;
  instructions: Array<{
    address: string;
    bytes: string;
    disasm: string;
    type: string;
    comment?: string;
  }>;
}

export interface CfgEdge {
  from: string;
  to: string;
  type: 'true' | 'false' | 'unconditional' | 'loop';
}

export interface CfgData {
  functionAddress: string;
  functionName: string;
  blocks: CfgBlock[];
  edges: CfgEdge[];
}
```

## Local Development and Verification

### Prerequisites

- Node.js 20.x or 22.x LTS
- npm 10.x or higher

### Installation

```bash
npm ci
```

### Test Suite Execution

Run the automated 10-point QA verification suite:

```bash
npm test
```

The test runner validates:
1. Binary header identification and architecture detection.
2. Function boundary reconstruction and basic block partitioning.
3. String extraction and heuristic categorization (URLs, IPs, paths, registry keys).
4. Import and export table resolution.
5. Decompilation worker initialization and message handling.
6. Markdown report generation and analysis serialization.

### Production Build

Compile TypeScript and bundle assets with Vite:

```bash
npm run build
```

Production artifacts are written to the `dist/` directory.

### Local Preview

To serve the production build locally:

```bash
npm run preview
```

## CI/CD Deployment Pipeline

The repository includes an automated GitHub Actions deployment workflow at `.github/workflows/deploy-to-portfolio.yml`.

On every push to `main` (or manual trigger via `workflow_dispatch`):
1. Installs pinned dependencies using `npm ci`.
2. Executes the Vitest test suite via `npm test`.
3. Compiles TypeScript and bundles production assets via `npm run build`.
4. Checks out the parent portfolio repository (`Spet001/Spet001.github.io`).
5. Completely wipes `tools/easy-decompiler/` in the target repo to prevent orphaned or stale hashed files.
6. Copies `dist/` production artifacts into `tools/easy-decompiler/`.
7. Commits changes and pushes to `main` on `Spet001/Spet001.github.io`, rebasing automatically if concurrent changes occur.

### Authentication Setup

To authorize cross-repository deployments to `Spet001/Spet001.github.io`:
1. Generate a GitHub Personal Access Token (classic `repo` scope or fine-grained `Contents: Read and write` on `Spet001/Spet001.github.io`).
2. Add the token to this repository under `Settings > Secrets and variables > Actions` as `PORTFOLIO_DEPLOY_TOKEN` (or `GH_PAT`).

## License

MIT License. See `LICENSE` for details.
