export interface EngineCapabilities {
  hasCLikeDecompiler: boolean;
  supportsCfg: boolean;
  supportsCallGraph: boolean;
  supportsFunctionNaming: boolean;
  supportsStrings: boolean;
  supportsImports: boolean;
  supportsExports: boolean;
  supportsHexView: boolean;
  supportedArchitectures: string[];
}

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
  timestamp?: string;
}

export type FunctionCategory =
  | 'entry'
  | 'exported'
  | 'imported'
  | 'thunk'
  | 'wrapper'
  | 'constructor'
  | 'destructor'
  | 'plt_got'
  | 'recursive'
  | 'unreferenced'
  | 'compiler_stub'
  | 'standard';

export interface FunctionInfo {
  address: string;
  virtualAddress: number;
  fileOffset: number;
  name: string;
  originalName: string;
  autoName: string;
  customName?: string;
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
  isWrapper: boolean;
  isExported: boolean;
  isImported: boolean;
  isUnreferenced: boolean;
  isFavorite?: boolean;
  comment?: string;
  hasPrologue: boolean;
  hasEpilogue: boolean;
  possiblyInlined: boolean;
  localVars: Array<{ name: string; type: string; offset: string; kind: 'stack' | 'reg' | 'arg' }>;
  stringsReferenced: string[];
  importsUsed: string[];
}

export type StringHeuristicCategory =
  | 'URL'
  | 'Email'
  | 'FilePath'
  | 'ShellCommand'
  | 'DLL/Library'
  | 'API/Symbol'
  | 'ErrorMessage'
  | 'HeuristicTokenOrKey'
  | 'FileFormat'
  | 'CryptoIndicator'
  | 'DebugIndicator'
  | 'General';

export interface StringInfo {
  address: string;
  virtualAddress: number;
  fileOffset: number;
  section: string;
  encoding: 'ASCII' | 'UTF-8' | 'UTF-16LE' | 'UTF-16BE';
  length: number;
  value: string;
  xrefs: string[];
  functions: string[];
  categories: StringHeuristicCategory[];
  heuristicNote?: string;
}

export interface ImportInfo {
  name: string;
  decoratedName?: string;
  library: string;
  address: string;
  virtualAddress: number;
  pltAddress?: string;
  ordinal?: number;
  bind: string;
  type: string;
  isUnresolved: boolean;
  xrefs: string[];
}

export interface ExportInfo {
  name: string;
  decoratedName?: string;
  address: string;
  virtualAddress: number;
  fileOffset: number;
  size: number;
  ordinal?: number;
  type: string;
  isForwarded?: boolean;
}

export interface SymbolInfo {
  name: string;
  demangledName?: string;
  address: string;
  virtualAddress: number;
  size: number;
  type: string;
  bind: string;
  section: string;
}

export interface RelocationInfo {
  name: string;
  address: string;
  virtualAddress: number;
  type: string;
  addend?: number;
  target?: string;
}

export interface SectionInfo {
  name: string;
  virtualAddress: string;
  virtualAddressNum: number;
  fileOffset: string;
  fileOffsetNum: number;
  size: number;
  virtualSize: number;
  permissions: string;
  flags: string;
  entropy: number;
  functionsCount: number;
  stringsCount: number;
}

export interface DisassemblyLine {
  address: string;
  virtualAddress: number;
  bytes: string;
  mnemonic: string;
  operands: string;
  disasm: string;
  type: string;
  comment?: string;
  userComment?: string;
  label?: string;
  jumpTarget?: string;
  failTarget?: string;
  callTarget?: string;
  stringRef?: string;
  importRef?: string;
  xrefsIn: Array<{ from: string; type: string; fnName?: string }>;
  xrefsOut: Array<{ to: string; type: string; targetName?: string }>;
}

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

export interface CallGraphNode {
  id: string;
  address: string;
  name: string;
  category: FunctionCategory;
  depth: number;
}

export interface CallGraphEdge {
  from: string;
  to: string;
  count: number;
}

export interface CallGraphData {
  rootAddress: string;
  nodes: CallGraphNode[];
  edges: CallGraphEdge[];
}

export interface DecompilationResult {
  engineId: string;
  engineName: string;
  engineVersion: string;
  functionAddress: string;
  functionName: string;
  architecture: string;
  code: string;
  rawCode?: string;
  durationMs: number;
  warnings: string[];
  errors: string[];
  variables: string[];
  calls: string[];
  strings: string[];
  lineMap?: Array<{ line: number; address?: string }>;
}

export interface AnalysisResult {
  metadata: BinaryMetadata;
  functions: FunctionInfo[];
  strings: StringInfo[];
  imports: ImportInfo[];
  exports: ExportInfo[];
  symbols: SymbolInfo[];
  relocations: RelocationInfo[];
  tlsCallbacks: string[];
  vtables: Array<{ address: string; entries: string[] }>;
  rttiEntries: Array<{ address: string; className: string }>;
  sections: SectionInfo[];
  callGraph: CallGraphData;
  analysisDurationMs: number;
}

export interface DecompilerEngine {
  id: string;
  name: string;
  version: string;
  supportedArchitectures: string[];
  supportedFormats: string[];
  capabilities: EngineCapabilities;

  initialize(): Promise<void>;

  openBinary(
    data: Uint8Array,
    filename: string
  ): Promise<BinaryMetadata>;

  analyze(): Promise<AnalysisResult>;

  listFunctions(): Promise<FunctionInfo[]>;

  getStrings(): Promise<StringInfo[]>;

  disassemble(address: string): Promise<string>;

  getDisassemblyLines?(address: string): Promise<DisassemblyLine[]>;

  getCfg?(address: string): Promise<CfgData>;

  decompile(address: string): Promise<DecompilationResult>;

  getImports(): Promise<ImportInfo[]>;

  getExports(): Promise<ExportInfo[]>;

  getSections(): Promise<SectionInfo[]>;

  executeRawCommand?(command: string): Promise<string>;

  syncSymbols?(symbols: Array<{ address: string; name: string }>): Promise<void>;

  close(): Promise<void>;
}

export interface FunctionRenameAction {
  address: string;
  previousName: string;
  newName: string;
  timestamp: number;
}

export interface AppSettings {
  theme: 'dark' | 'light';
  enhancedFonts: boolean;
  monospaceCodeFont: 'JetBrains Mono' | 'IBM Plex Mono' | 'System Mono';
  compactLayout: boolean;
  showAddresses: boolean;
  showBytes: boolean;
  showComments: boolean;
  showFunctionSignatures: boolean;
  showAnalysisDetails: boolean;
  showBackgroundStars: boolean;
  animations: boolean;
  reducedMotion: boolean;
  workerMemoryLimitMb: number;
  analysisTimeoutSec: number;
  minStringLength: number;
  autoAnalyzeOnOpen: boolean;
  autoNameFunctions: boolean;
  autoSaveProject: boolean;
}

export interface RecentFileEntry {
  id: string;
  filename: string;
  size: number;
  sha256: string;
  format: string;
  architecture: string;
  openedAt: number;
  binaryData?: Uint8Array;
}

export interface SavedProject {
  id: string;
  name: string;
  filename: string;
  sha256: string;
  updatedAt: number;
  customNames: Record<string, string>;
  comments: Record<string, string>;
  favorites: string[];
  renameHistory: FunctionRenameAction[];
  selectedFunctionAddress?: string;
}

export interface WorkerLogEntry {
  id: string;
  timestamp: number;
  source: 'System' | 'Engine A (Rizin+jsdec)' | 'Engine B (Ghidra WASM)' | 'Analysis' | 'Security';
  level: 'info' | 'warn' | 'error' | 'success';
  message: string;
}

export interface TestSuiteItemResult {
  id: number;
  name: string;
  status: 'pending' | 'running' | 'passed' | 'failed';
  durationMs: number;
  detail: string;
}
