import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  FolderOpen,
  Square,
  Download,
  Sliders,
  Search,
  Star,
  Edit3,
  MessageSquare,
  Cpu,
  Terminal,
  FileCode2,
  GitBranch,
  Network,
  Binary,
  ListFilter,
  AlertTriangle,
  Copy,
  Check,
  Sparkles,
  Layers,
  ChevronRight,
  Database,
  ArrowRight,
} from 'lucide-react';
import type {
  AnalysisResult,
  AppSettings,
  CfgData,
  DecompilationResult,
  DisassemblyLine,
  FunctionCategory,
  FunctionInfo,
  FunctionRenameAction,
  RecentFileEntry,
  SavedProject,
  StringHeuristicCategory,
  WorkerLogEntry,
} from './types';
import { GhidraWasmEngine, RizinJsdecEngine } from './engines/engine-manager';
import { applyCustomNamesToCode } from './analysis/function-naming';
import {
  downloadLocalBlob,
  formatFunctionsExport,
  formatStringsExport,
  generateMarkdownReport,
  serializeProjectBundle,
} from './analysis/report-export';
import {
  clearRecentFiles,
  loadAppSettings,
  loadRecentFiles,
  saveAppSettings,
  saveProjectToDb,
  saveRecentFile,
} from './storage/local-db';
import { CallGraphCanvasView, CfgCanvasView } from './components/GraphCanvases';
import { HexViewerPane } from './components/HexViewerPane';
import {
  AboutArchitectureModal,
  SettingsModal,
  ShortcutsModal,
} from './components/Modals';
import { PwaInstallButton } from './components/PwaInstallButton';
import { THEMES, ThemeId, DEFAULT_THEME } from './theme';

const getBaseUrl = (): string => {
  const meta = import.meta as unknown as { env?: { BASE_URL?: string } };
  return meta.env?.BASE_URL || './';
};

const SAMPLE_BINARIES = [
  {
    id: 'gfwl-setup',
    label: 'Games for Windows LIVE Setup (x86 PE32)',
    path: './samples/gfwlivesetup.exe',
    filename: 'gfwlivesetup.exe',
    badge: 'PE32 · Win32 GUI',
  },
];

type CenterTab = 'dual-decompiler' | 'decompiler-a' | 'decompiler-b' | 'disassembly' | 'cfg' | 'callgraph' | 'hex';
type RightInspectorTab = 'metadata' | 'strings' | 'imports' | 'exports' | 'sections' | 'xrefs';
type BottomDockTab = 'logs' | 'rizin-shell' | 'rename-history' | 'warnings';

function renderHighlightedCodeLine(
  line: string,
  onJumpFunction?: (name: string) => void
): React.ReactNode {
  const trimmed = line.trimStart();
  if (trimmed.startsWith('//') || trimmed.startsWith('/*')) {
    return <span className="text-[#64748b] italic">{line}</span>;
  }

  const TOKEN_REGEX =
    /(\/\*[\s\S]*?\*\/|\/\/[^\n]*|"(?:\\.|[^"\\])*"|0x[0-9a-fA-F]+|\b(?:int4|uint32_t|int32_t|uint16_t|int16_t|uint8_t|int8_t|uint64_t|int64_t|xunknown4|unknown|void|char|bool|int|long|short|unsigned|signed|float|double|size_t|uintptr_t|intptr_t|undefined\d*|code)\b|\b(?:xStack_\w+|iStack_\w+|param_\w+|auStack_\w+|uStack_\w+|sStack_\w+|var_\w+|arg_\w+)\b|\b(?:sub_[0-9a-fA-F]+|imp_\w+|thunk_\w+|sym_\w+|func_\w+)\b|\b(?:if|else|while|for|return|switch|case|break|continue|default|goto|do)\b)/g;

  const parts: React.ReactNode[] = [];
  let lastIndex = 0;
  let match: RegExpExecArray | null;

  while ((match = TOKEN_REGEX.exec(line)) !== null) {
    if (match.index > lastIndex) {
      parts.push(line.slice(lastIndex, match.index));
    }
    const token = match[0];
    if (token.startsWith('//') || token.startsWith('/*')) {
      parts.push(
        <span key={match.index} className="text-[#64748b] italic">
          {token}
        </span>
      );
    } else if (token.startsWith('"')) {
      parts.push(
        <span key={match.index} className="text-[#a5f3fc]">
          {token}
        </span>
      );
    } else if (token.startsWith('0x') || token.startsWith('0X')) {
      parts.push(
        <span key={match.index} className="text-[#34d399]">
          {token}
        </span>
      );
    } else if (
      /^(int4|uint32_t|int32_t|uint16_t|int16_t|uint8_t|int8_t|uint64_t|int64_t|xunknown4|unknown|void|char|bool|int|long|short|unsigned|signed|float|double|size_t|uintptr_t|intptr_t|undefined\d*|code)$/.test(
        token
      )
    ) {
      parts.push(
        <span key={match.index} className="text-[#38bdf8] font-semibold">
          {token}
        </span>
      );
    } else if (
      /^(xStack_\w+|iStack_\w+|param_\w+|auStack_\w+|uStack_\w+|sStack_\w+|var_\w+|arg_\w+)$/.test(
        token
      )
    ) {
      parts.push(
        <span key={match.index} className="text-[#fbbf24]">
          {token}
        </span>
      );
    } else if (/^(sub_[0-9a-fA-F]+|imp_\w+|thunk_\w+|sym_\w+|func_\w+)$/.test(token)) {
      parts.push(
        <span
          key={match.index}
          onClick={() => onJumpFunction?.(token)}
          className="text-[#f472b6] underline-offset-2 hover:underline cursor-pointer"
          title={`Click to jump to ${token}`}
        >
          {token}
        </span>
      );
    } else if (
      /^(if|else|while|for|return|switch|case|break|continue|default|goto|do)$/.test(token)
    ) {
      parts.push(
        <span key={match.index} className="text-[#c084fc] font-semibold">
          {token}
        </span>
      );
    } else {
      parts.push(token);
    }
    lastIndex = match.index + token.length;
  }
  if (lastIndex < line.length) {
    parts.push(line.slice(lastIndex));
  }
  return <>{parts}</>;
}

interface DecompilerCodePaneProps {
  code: string;
  errors?: string[];
  isLoading: boolean;
  loadingMessage: string;
  engineName: string;
  engineId: 'rizin-jsdec' | 'ghidra-wasm';
  durationMs?: number;
  copiedId: string | null;
  copyKey: string;
  onCopy: () => void;
  onDownload: () => void;
  onSwitchToGhidra?: () => void;
  onSwitchToRizin?: () => void;
  onSwitchToDisasm?: () => void;
  onJumpFunction?: (name: string) => void;
  baseAddress?: string;
  fontClass: string;
}

const DecompilerCodePane: React.FC<DecompilerCodePaneProps> = ({
  code,
  errors,
  isLoading,
  loadingMessage,
  engineName,
  engineId,
  durationMs,
  copiedId,
  copyKey,
  onCopy,
  onDownload,
  onSwitchToGhidra,
  onSwitchToRizin,
  onSwitchToDisasm,
  onJumpFunction,
  baseAddress,
  fontClass,
}) => {
  const isEngineError = useMemo(() => {
    if (errors && errors.length > 0) return true;
    if (!code) return false;
    const lower = code.toLowerCase();
    return (
      lower.includes('engine a error') ||
      lower.includes('engine b error') ||
      lower.includes('cannot read properties of undefined') ||
      lower.includes('ast control-flow recovery incomplete') ||
      lower.includes('worker request failed') ||
      lower.includes('typeerror') ||
      (code.trim().startsWith('//') && lower.includes('error'))
    );
  }, [code, errors]);

  const lines = useMemo(() => {
    if (!code) return [];
    return code.split('\n');
  }, [code]);

  const parsedBase = useMemo(() => {
    if (!baseAddress) return 0x00401000;
    const clean = baseAddress.replace(/^0x/i, '');
    const num = parseInt(clean, 16);
    return Number.isNaN(num) ? 0x00401000 : num;
  }, [baseAddress]);

  return (
    <div className="flex h-full min-h-0 flex-col overflow-hidden bg-[#06090f]">

      <div className="h-[26px] shrink-0 flex items-center justify-between border-b border-[#182232] bg-[#0c121d] px-2 text-[11px] font-mono select-none">
        <div className="flex items-center gap-1.5 truncate">
          <span className="text-[10px] font-bold text-[#00e5ff] shrink-0 font-mono">
            {engineId === 'rizin-jsdec' ? '[A: RIZIN+JSDEC]' : '[B: GHIDRA SLEIGH]'}
          </span>
          {isEngineError && (
            <span className="text-rose-400 font-bold shrink-0 font-mono">[!]</span>
          )}
          <span className="font-semibold text-slate-200 truncate">{engineName}</span>
          {typeof durationMs === 'number' && (
            <span className="text-[#64748b]">({durationMs} ms)</span>
          )}
        </div>
        <div className="flex items-center gap-1">
          <button
            type="button"
            onClick={onCopy}
            className="inline-flex items-center gap-1 border border-[#182232] bg-[#111a29] px-1.5 py-0.5 text-[10px] text-slate-300 hover:text-white hover:border-[#38bdf8]"
            title="Copy code to clipboard"
          >
            {copiedId === copyKey ? (
              <Check className="h-2.5 w-2.5 text-[#34d399]" />
            ) : (
              <Copy className="h-2.5 w-2.5" />
            )}
            Copy
          </button>
          <button
            type="button"
            onClick={onDownload}
            className="inline-flex items-center gap-1 border border-[#182232] bg-[#111a29] px-1.5 py-0.5 text-[10px] text-slate-300 hover:text-white hover:border-[#38bdf8]"
            title="Download .c file"
          >
            <Download className="h-2.5 w-2.5" /> .c
          </button>
        </div>
      </div>

      {isLoading ? (
        <div className="flex-1 flex flex-col items-center justify-center p-3 bg-[#06090f] text-center select-none font-mono">
          <div className="flex items-center gap-2 text-xs text-[#38bdf8]">
            <span className="h-2 w-2 animate-ping bg-[#38bdf8]" />
            <span>{loadingMessage}</span>
          </div>
        </div>
      ) : isEngineError ? (
        <div className="flex-1 flex flex-col items-center justify-center p-3 bg-[#06090f] text-center select-none font-mono">
          <div className="max-w-md p-3 bg-[#090d14] border border-[#182232] text-left">
            <div className="flex items-center gap-2 text-[#f59e0b] font-bold text-xs mb-2">
              <AlertTriangle className="h-4 w-4 shrink-0" />
              <span>[DECOMPILER ENGINE NOTICE]</span>
            </div>
            <p className="text-[11px] text-slate-300 leading-relaxed mb-3">
              {engineId === 'rizin-jsdec'
                ? 'AST Control-Flow recovery incomplete for this frame — fallback to Disassembly / Engine B active.'
                : 'AST Control-Flow recovery incomplete for this frame — fallback to Disassembly / Engine A active.'}
            </p>
            <div className="flex items-center gap-2">
              {onSwitchToGhidra && (
                <button
                  type="button"
                  onClick={onSwitchToGhidra}
                  className="h-[22px] px-2.5 bg-[#111a29] border border-[#38bdf8] text-[#38bdf8] text-[11px] hover:bg-[#38bdf8]/20 flex items-center gap-1"
                >
                  [Switch to Full Ghidra View]
                </button>
              )}
              {onSwitchToRizin && (
                <button
                  type="button"
                  onClick={onSwitchToRizin}
                  className="h-[22px] px-2.5 bg-[#111a29] border border-[#38bdf8] text-[#38bdf8] text-[11px] hover:bg-[#38bdf8]/20 flex items-center gap-1"
                >
                  [Switch to Full Rizin View]
                </button>
              )}
              {onSwitchToDisasm && (
                <button
                  type="button"
                  onClick={onSwitchToDisasm}
                  className="h-[22px] px-2.5 bg-[#090d14] border border-[#182232] text-slate-400 text-[11px] hover:text-white"
                >
                  View Disassembly
                </button>
              )}
            </div>
          </div>
        </div>
      ) : (
        <div className={`flex-1 select-text overflow-auto font-mono text-[12px] leading-5 ${fontClass}`}>
          {lines.map((l, idx) => {
            const lineAddr = `0x${(parsedBase + idx * 4).toString(16).padStart(8, '0')}`;
            return (
              <div
                key={idx}
                className="flex items-stretch hover:bg-[#38bdf8]/[0.06] group/line"
              >

                <div className="w-[78px] shrink-0 select-none text-right pr-2.5 text-[#475569] bg-[#06090f] border-r border-[#182232] font-mono text-[11px] tabular-nums group-hover/line:text-[#38bdf8]">
                  {lineAddr}
                </div>

                <div className="flex-1 pl-3 font-mono text-[12px] whitespace-pre text-[#cbd5e1]">
                  {renderHighlightedCodeLine(l, onJumpFunction)}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

export default function App() {
  const [settings, setSettings] = useState<AppSettings>(() => loadAppSettings());
  const [binaryData, setBinaryData] = useState<Uint8Array | null>(null);
  const [analysis, setAnalysis] = useState<AnalysisResult | null>(null);
  const [selectedFnAddr, setSelectedFnAddr] = useState<string>('');
  const [disasmLines, setDisasmLines] = useState<DisassemblyLine[]>([]);
  const [cfgData, setCfgData] = useState<CfgData | null>(null);
  const [decompA, setDecompA] = useState<DecompilationResult | null>(null);
  const [decompB, setDecompB] = useState<DecompilationResult | null>(null);

  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [isDecompilingA, setIsDecompilingA] = useState(false);
  const [isDecompilingB, setIsDecompilingB] = useState(false);
  const [statusMessage, setStatusMessage] = useState('Ready — Select a built-in sample or drop any binary');

  const [customNames, setCustomNames] = useState<Record<string, string>>({});
  const [fnComments, setFnComments] = useState<Record<string, string>>({});
  const [favorites, setFavorites] = useState<Set<string>>(new Set());
  const [renameHistory, setRenameHistory] = useState<FunctionRenameAction[]>([]);
  const [redoStack, setRedoStack] = useState<FunctionRenameAction[]>([]);

  const [fnSearch, setFnSearch] = useState('');
  const [fnCategoryFilter, setFnCategoryFilter] = useState<FunctionCategory | 'all' | 'favorites'>('all');
  const [stringSearch, setStringSearch] = useState('');
  const [stringCategoryFilter, setStringCategoryFilter] = useState<StringHeuristicCategory | 'all'>('all');

  const [currentTheme, setCurrentTheme] = useState<ThemeId>(() => {
    const saved = localStorage.getItem('spet-decompiler-theme');
    if (saved === 'oled' || saved === 'slade' || saved === 'cobalt' || saved === 'ida') {
      return saved as ThemeId;
    }
    return DEFAULT_THEME;
  });

  useEffect(() => {
    localStorage.setItem('spet-decompiler-theme', currentTheme);
    document.documentElement.setAttribute('data-theme', currentTheme);
    document.body.setAttribute('data-theme', currentTheme);
  }, [currentTheme]);

  const [centerTab, setCenterTab] = useState<CenterTab>('dual-decompiler');
  const [rightTab, setRightTab] = useState<RightInspectorTab>('metadata');
  const [bottomTab, setBottomTab] = useState<BottomDockTab>('logs');
  const [isBottomDockOpen, setIsBottomDockOpen] = useState(true);
  const [openMenu, setOpenMenu] = useState<string | null>(null);

  const [showSettingsModal, setShowSettingsModal] = useState(false);
  const [showShortcutsModal, setShowShortcutsModal] = useState(false);
  const [aboutModalTab, setAboutModalTab] = useState<'engines' | 'security' | 'about' | null>(null);
  const [renamingFn, setRenamingFn] = useState<{ address: string; currentName: string } | null>(null);
  const [commentingFn, setCommentingFn] = useState<{ address: string; currentComment: string } | null>(null);

  const [logs, setLogs] = useState<WorkerLogEntry[]>([]);
  const [rizinCmdInput, setRizinCmdInput] = useState('afl');
  const [rizinCmdOutput, setRizinCmdOutput] = useState<string>('');
  const [recentFiles, setRecentFiles] = useState<RecentFileEntry[]>([]);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [isDragOver, setIsDragOver] = useState(false);

  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const projectInputRef = useRef<HTMLInputElement | null>(null);
  const searchInputRef = useRef<HTMLInputElement | null>(null);

  const engineARef = useRef<RizinJsdecEngine | null>(null);
  const engineBRef = useRef<GhidraWasmEngine | null>(null);

  const appendLog = useCallback((entry: Omit<WorkerLogEntry, 'id' | 'timestamp'>) => {
    setLogs((prev) => [
      ...prev.slice(-199),
      {
        ...entry,
        id: `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
        timestamp: Date.now(),
      },
    ]);
  }, []);

  useEffect(() => {
    const engA = new RizinJsdecEngine(appendLog);
    const engB = new GhidraWasmEngine(appendLog);
    engineARef.current = engA;
    engineBRef.current = engB;

    loadRecentFiles().then(setRecentFiles).catch(() => {});

    return () => {
      engA.cancelAndRestart();
      engB.cancelAndRestart();
    };
  }, []);

  const loadSampleBinary = useCallback(async (sampleId: string = 'gfwl-setup') => {
    const smp = SAMPLE_BINARIES.find((s) => s.id === sampleId) || SAMPLE_BINARIES[0];
    const candidateUrls = [
      smp.path,
      './samples/' + smp.filename,
      'samples/' + smp.filename,
      '/tools/easy-decompiler/samples/' + smp.filename,
      '/samples/' + smp.filename,
    ];
    setIsAnalyzing(true);
    setStatusMessage(`Fetching authentic sample binary (${smp.filename})...`);
    for (const url of candidateUrls) {
      try {
        const resp = await fetch(url);
        if (resp.ok) {
          const ct = resp.headers.get('content-type') || '';
          if (ct.includes('text/html')) continue;
          const buf = await resp.arrayBuffer();
          await loadBinaryBuffer(new Uint8Array(buf), smp.filename);
          return;
        }
      } catch {

      }
    }
    setIsAnalyzing(false);
    setStatusMessage(`Failed to locate ${smp.filename} across candidate paths.`);
  }, []);

  useEffect(() => {
    saveAppSettings(settings);
    engineARef.current?.setMinStringLength(settings.minStringLength);
  }, [settings]);

  const fontClass = useMemo(() => {
    if (settings.monospaceCodeFont === 'IBM Plex Mono') return 'font-mono-ibm';
    if (settings.monospaceCodeFont === 'System Mono') return 'font-mono-system';
    return 'font-mono-jetbrains';
  }, [settings.monospaceCodeFont]);

  const inspectFunction = useCallback(
    async (
      addr: string,
      currentAnalysisObj?: AnalysisResult | null,
      overrideNames?: Record<string, string>
    ) => {
      if (!addr || !engineARef.current || !engineBRef.current) return;
      setSelectedFnAddr(addr);
      setIsDecompilingA(true);
      setIsDecompilingB(true);

      const activeAnalysis = currentAnalysisObj ?? analysis;
      const namesMap = overrideNames ?? customNames;
      if (activeAnalysis) {
        const symbols = activeAnalysis.functions.map((f) => ({
          address: f.address,
          name: namesMap[f.address] || f.customName || f.name,
        }));
        await Promise.all([
          engineARef.current.syncSymbols(symbols).catch(() => {}),
          engineBRef.current.syncContext(activeAnalysis.sections, symbols).catch(() => {}),
        ]);
      }

      engineARef.current
        .getDisassemblyLines(addr)
        .then(setDisasmLines)
        .catch(() => setDisasmLines([]));

      engineARef.current
        .getCfg(addr)
        .then(setCfgData)
        .catch(() => setCfgData(null));

      engineARef.current
        .decompile(addr)
        .then((resA) => {
          setDecompA(resA);
          setIsDecompilingA(false);
        })
        .catch((err) => {
          setDecompA({
            engineId: 'rizin-jsdec',
            engineName: 'Rizin + jsdec',
            engineVersion: '0.9.1',
            functionAddress: addr,
            functionName: addr,
            architecture: activeAnalysis?.metadata.architecture || 'x86',
            code: `// Engine A error: ${err.message}`,
            durationMs: 0,
            warnings: [],
            errors: [err.message],
            variables: [],
            calls: [],
            strings: [],
          });
          setIsDecompilingA(false);
        });

      engineBRef.current
        .decompile(addr)
        .then((resB) => {
          setDecompB(resB);
          setIsDecompilingB(false);
        })
        .catch((err) => {
          setDecompB({
            engineId: 'ghidra-wasm',
            engineName: 'Ghidra C++ Sleigh Decompiler',
            engineVersion: '11.2',
            functionAddress: addr,
            functionName: addr,
            architecture: activeAnalysis?.metadata.architecture || 'x86',
            code: `// Engine B error: ${err.message}`,
            durationMs: 0,
            warnings: [],
            errors: [err.message],
            variables: [],
            calls: [],
            strings: [],
          });
          setIsDecompilingB(false);
        });
    },
    [analysis, customNames]
  );

  const loadBinaryBuffer = async (
    data: Uint8Array,
    filename: string,
    restoredProject?: SavedProject
  ) => {
    if (!engineARef.current || !engineBRef.current) return;
    setIsAnalyzing(true);
    setStatusMessage(`Opening & analyzing ${filename} (${(data.byteLength / 1024).toFixed(1)} KB)...`);
    setBinaryData(data);

    try {
      const nextNames = restoredProject?.customNames || {};
      const nextComments = restoredProject?.comments || {};
      const nextFavs = new Set(restoredProject?.favorites || []);
      setCustomNames(nextNames);
      setFnComments(nextComments);
      setFavorites(nextFavs);
      setRenameHistory(restoredProject?.renameHistory || []);
      setRedoStack([]);

      await engineARef.current.openBinary(data, filename);
      const analysisRes = await engineARef.current.analyze();

      engineBRef.current.setSharedAnalysis(analysisRes);
      await engineBRef.current.openBinary(data, filename);

      setAnalysis(analysisRes);

      const recentEntry: RecentFileEntry = {
        id: analysisRes.metadata.sha256.slice(0, 16),
        filename,
        size: data.byteLength,
        sha256: analysisRes.metadata.sha256,
        format: analysisRes.metadata.format,
        architecture: `${analysisRes.metadata.architecture} (${analysisRes.metadata.bits}-bit)`,
        openedAt: Date.now(),
        binaryData: data,
      };
      await saveRecentFile(recentEntry);
      const updatedRecent = await loadRecentFiles();
      setRecentFiles(updatedRecent);

      const preferredFn =
        (restoredProject?.selectedFunctionAddress &&
          analysisRes.functions.find(
            (f) => f.address === restoredProject.selectedFunctionAddress
          )) ||
        analysisRes.functions.find((f) => f.name === 'main' || f.name.includes('verify_license')) ||
        analysisRes.functions[0];

      if (preferredFn) {
        await inspectFunction(preferredFn.address, analysisRes, nextNames);
      }

      setStatusMessage(
        `Analyzed ${filename} in ${analysisRes.analysisDurationMs} ms · ${analysisRes.functions.length} functions · ${analysisRes.strings.length} strings`
      );
    } catch (err: any) {
      setStatusMessage(`Analysis failed: ${err?.message || String(err)}`);
      appendLog({
        source: 'System',
        level: 'error',
        message: `Failed to analyze ${filename}: ${err?.message || String(err)}`,
      });
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleCancelAnalysis = () => {
    engineARef.current?.cancelAndRestart();
    engineBRef.current?.cancelAndRestart();
    setIsAnalyzing(false);
    setIsDecompilingA(false);
    setIsDecompilingB(false);
    setStatusMessage('Worker execution cancelled and reset.');
    appendLog({
      source: 'System',
      level: 'warn',
      message: 'User cancelled active Web Worker task; workers restarted cleanly.',
    });
  };

  const applyRename = async (address: string, rawNewName: string) => {
    const clean = rawNewName.trim().replace(/[^a-zA-Z0-9_]/g, '_');
    if (!clean || !analysis) return;

    const fn = analysis.functions.find((f) => f.address === address);
    const prevName = customNames[address] || fn?.name || address;
    if (prevName === clean) {
      setRenamingFn(null);
      return;
    }

    const updatedNames = { ...customNames, [address]: clean };
    setCustomNames(updatedNames);
    setRenameHistory((h) => [
      ...h,
      { address, previousName: prevName, newName: clean, timestamp: Date.now() },
    ]);
    setRedoStack([]);
    setRenamingFn(null);

    appendLog({
      source: 'Analysis',
      level: 'success',
      message: `Renamed function @ ${address}: ${prevName} → ${clean} (synced across Rizin & Ghidra)`,
    });

    if (selectedFnAddr === address) {
      await inspectFunction(address, analysis, updatedNames);
    }
  };

  const handleUndoRename = async () => {
    if (renameHistory.length === 0 || !analysis) return;
    const last = renameHistory[renameHistory.length - 1];
    const nextHistory = renameHistory.slice(0, -1);
    const updatedNames = { ...customNames, [last.address]: last.previousName };
    setRenameHistory(nextHistory);
    setRedoStack((r) => [...r, last]);
    setCustomNames(updatedNames);
    if (selectedFnAddr) {
      await inspectFunction(selectedFnAddr, analysis, updatedNames);
    }
  };

  const handleRedoRename = async () => {
    if (redoStack.length === 0 || !analysis) return;
    const next = redoStack[redoStack.length - 1];
    const updatedNames = { ...customNames, [next.address]: next.newName };
    setRedoStack((r) => r.slice(0, -1));
    setRenameHistory((h) => [...h, next]);
    setCustomNames(updatedNames);
    if (selectedFnAddr) {
      await inspectFunction(selectedFnAddr, analysis, updatedNames);
    }
  };

  const handleAutoNameAllFunctions = async () => {
    if (!analysis) return;
    const updated: Record<string, string> = { ...customNames };
    for (const fn of analysis.functions) {
      if (!updated[fn.address]) {
        updated[fn.address] = fn.autoName;
      }
    }
    setCustomNames(updated);
    appendLog({
      source: 'Analysis',
      level: 'success',
      message: `Applied IDA-style automatic naming (sub_* / thunk_* / imp_*) across ${analysis.functions.length} functions.`,
    });
    if (selectedFnAddr) {
      await inspectFunction(selectedFnAddr, analysis, updated);
    }
  };

  const handleSaveProject = async () => {
    if (!analysis) return;
    const proj: SavedProject = {
      id: analysis.metadata.sha256.slice(0, 16),
      name: `${analysis.metadata.filename} Project`,
      filename: analysis.metadata.filename,
      sha256: analysis.metadata.sha256,
      updatedAt: Date.now(),
      customNames,
      comments: fnComments,
      favorites: Array.from(favorites),
      renameHistory,
      selectedFunctionAddress: selectedFnAddr,
    };
    await saveProjectToDb(proj);
    downloadLocalBlob(
      serializeProjectBundle(proj),
      `${analysis.metadata.filename}.spetproj.json`,
      'application/json'
    );
    appendLog({
      source: 'System',
      level: 'success',
      message: `Saved project state to IndexedDB and exported ${analysis.metadata.filename}.spetproj.json`,
    });
  };

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      const tag = (e.target as HTMLElement)?.tagName;
      const isInput = tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT';

      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'o') {
        e.preventDefault();
        fileInputRef.current?.click();
        return;
      }
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        searchInputRef.current?.focus();
        return;
      }
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 's') {
        e.preventDefault();
        handleSaveProject();
        return;
      }
      if (e.key === 'Escape') {
        setOpenMenu(null);
        setShowSettingsModal(false);
        setShowShortcutsModal(false);
        setAboutModalTab(null);
        setRenamingFn(null);
        setCommentingFn(null);
        return;
      }

      if (isInput) return;

      if (e.key.toLowerCase() === 'n' && selectedFnAddr && analysis) {
        e.preventDefault();
        const fn = analysis.functions.find((f) => f.address === selectedFnAddr);
        if (fn) {
          setRenamingFn({
            address: fn.address,
            currentName: customNames[fn.address] || fn.name,
          });
        }
      } else if (e.key === ';' && selectedFnAddr) {
        e.preventDefault();
        setCommentingFn({
          address: selectedFnAddr,
          currentComment: fnComments[selectedFnAddr] || '',
        });
      } else if (e.key.toLowerCase() === 'd') {
        setCenterTab('dual-decompiler');
      } else if (e.key === '1') {
        setCenterTab('dual-decompiler');
      } else if (e.key === '2') {
        setCenterTab('disassembly');
      } else if (e.key === '3') {
        setCenterTab('cfg');
      } else if (e.key === '4') {
        setCenterTab('hex');
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [selectedFnAddr, analysis, customNames, fnComments]);

  const filteredFunctions = useMemo(() => {
    if (!analysis) return [];
    const q = fnSearch.trim().toLowerCase();
    return analysis.functions.filter((fn) => {
      const displayName = customNames[fn.address] || fn.name;
      if (fnCategoryFilter === 'favorites' && !favorites.has(fn.address)) return false;
      if (
        fnCategoryFilter !== 'all' &&
        fnCategoryFilter !== 'favorites' &&
        fn.category !== fnCategoryFilter
      ) {
        return false;
      }
      if (!q) return true;
      return (
        displayName.toLowerCase().includes(q) ||
        fn.originalName.toLowerCase().includes(q) ||
        fn.address.toLowerCase().includes(q)
      );
    });
  }, [analysis, fnSearch, fnCategoryFilter, customNames, favorites]);

  const filteredStrings = useMemo(() => {
    if (!analysis) return [];
    const q = stringSearch.trim().toLowerCase();
    return analysis.strings.filter((s) => {
      if (stringCategoryFilter !== 'all' && !s.categories.includes(stringCategoryFilter)) {
        return false;
      }
      if (!q) return true;
      return (
        s.value.toLowerCase().includes(q) ||
        s.address.toLowerCase().includes(q) ||
        s.section.toLowerCase().includes(q)
      );
    });
  }, [analysis, stringSearch, stringCategoryFilter]);

  const activeFnInfo: FunctionInfo | undefined = useMemo(
    () => analysis?.functions.find((f) => f.address === selectedFnAddr),
    [analysis, selectedFnAddr]
  );

  const formattedCodeA = useMemo(
    () =>
      applyCustomNamesToCode(
        decompA?.code || '',
        analysis?.functions || [],
        customNames,
        fnComments
      ),
    [decompA, analysis, customNames, fnComments]
  );

  const formattedCodeB = useMemo(
    () =>
      applyCustomNamesToCode(
        decompB?.code || '',
        analysis?.functions || [],
        customNames,
        fnComments
      ),
    [decompB, analysis, customNames, fnComments]
  );

  const copyText = (id: string, text: string) => {
    navigator.clipboard?.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 1500);
  };

  const jumpToFunctionByNameOrAddr = (query: string) => {
    if (!analysis) return;
    const match = analysis.functions.find(
      (f) =>
        f.address.toLowerCase() === query.toLowerCase() ||
        (customNames[f.address] && customNames[f.address].toLowerCase() === query.toLowerCase()) ||
        f.name.toLowerCase() === query.toLowerCase() ||
        f.autoName.toLowerCase() === query.toLowerCase()
    );
    if (match) {
      inspectFunction(match.address);
    }
  };

  const totalSectionSize = useMemo(() => {
    if (!analysis || analysis.sections.length === 0) return 1;
    return analysis.sections.reduce((acc, s) => acc + Math.max(s.size, s.virtualSize, 1), 0);
  }, [analysis]);

  return (
    <div
      className="h-screen w-screen overflow-hidden flex flex-col bg-[#06090f] text-[#cbd5e1] select-none font-mono"
      onDragOver={(e) => {
        e.preventDefault();
        setIsDragOver(true);
      }}
      onDragLeave={() => setIsDragOver(false)}
      onDrop={async (e) => {
        e.preventDefault();
        setIsDragOver(false);
        const file = e.dataTransfer.files?.[0];
        if (file) {
          const buf = await file.arrayBuffer();
          await loadBinaryBuffer(new Uint8Array(buf), file.name);
        }
      }}
      onClick={() => {
        if (openMenu) setOpenMenu(null);
      }}
    >

      <input
        ref={fileInputRef}
        type="file"
        className="hidden"
        onChange={async (e) => {
          const f = e.target.files?.[0];
          if (f) {
            const buf = await f.arrayBuffer();
            await loadBinaryBuffer(new Uint8Array(buf), f.name);
          }
          e.target.value = '';
        }}
      />
      <input
        ref={projectInputRef}
        type="file"
        accept=".json"
        className="hidden"
        onChange={async (e) => {
          const f = e.target.files?.[0];
          if (f) {
            try {
              const text = await f.text();
              const proj = JSON.parse(text) as SavedProject;
              setCustomNames(proj.customNames || {});
              setFnComments(proj.comments || {});
              setFavorites(new Set(proj.favorites || []));
              setRenameHistory(proj.renameHistory || []);
              appendLog({
                source: 'System',
                level: 'success',
                message: `Loaded project annotations from ${f.name}`,
              });
              if (proj.selectedFunctionAddress) {
                inspectFunction(proj.selectedFunctionAddress, analysis, proj.customNames || {});
              }
            } catch (err: any) {
              appendLog({
                source: 'System',
                level: 'error',
                message: `Invalid project JSON: ${err.message}`,
              });
            }
          }
          e.target.value = '';
        }}
      />

      {isDragOver && (
        <div className="pointer-events-none fixed inset-0 z-50 flex items-center justify-center bg-[#06090f]/90">
          <div className="flex flex-col items-center gap-2 border border-[#38bdf8] bg-[#090d14] p-8 text-center">
            <Binary className="h-8 w-8 text-[#38bdf8]" />
            <div className="text-sm font-semibold text-white">
              Drop Any Executable or Library for WASM Analysis
            </div>
            <div className="text-[11px] text-[#64748b]">
              ELF32/64 · PE32/PE+ (.exe, .dll, .sys) · Mach-O · WebAssembly (.wasm)
            </div>
          </div>
        </div>
      )}

      <header className="h-[28px] shrink-0 bg-[#06090f] border-b border-[#182232] px-2.5 flex items-center justify-between text-[11px] font-mono z-30 select-none">

        <div className="flex items-center gap-2 shrink-0">
          <div className="flex items-center gap-1.5 pr-2 select-none">
            <img
              src={`${getBaseUrl()}icons/executable-0.png`}
              alt=""
              className="pixelated shrink-0 w-3.5 h-3.5"
            />
            <span className="font-sans font-bold tracking-tight text-[#00e5ff]">Spet's</span>
            <span className="font-mono font-semibold text-slate-100 tracking-tight">Easy Online Decompiler</span>
          </div>

          <nav className="relative flex items-center gap-0.5 text-[11px]">

            <div className="relative">
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  setOpenMenu(openMenu === 'file' ? null : 'file');
                }}
                className={`px-1.5 py-0.5 text-slate-300 hover:text-white hover:bg-[#111a29] ${
                  openMenu === 'file' ? 'bg-[#111a29] text-white' : ''
                }`}
              >
                File
              </button>
              {openMenu === 'file' && (
                <div
                  onClick={(e) => e.stopPropagation()}
                  className="absolute left-0 top-full mt-0.5 w-64 border border-[#182232] bg-[#090d14] py-1 shadow-2xl z-50 text-[11px]"
                >
                  <button
                    type="button"
                    onClick={() => {
                      setOpenMenu(null);
                      fileInputRef.current?.click();
                    }}
                    className="flex w-full items-center justify-between px-3 py-1 text-left text-slate-200 hover:bg-[#111a29] hover:text-[#38bdf8]"
                  >
                    <span>Open Binary File...</span>
                    <span className="text-[10px] text-[#64748b]">Ctrl+O</span>
                  </button>
                  <div className="my-1 border-t border-[#182232]" />
                  <div className="px-3 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-[#64748b]">
                    Built-In Test Binaries
                  </div>
                  {SAMPLE_BINARIES.map((smp) => (
                    <button
                      key={smp.id}
                      type="button"
                      onClick={async () => {
                        setOpenMenu(null);
                        await loadSampleBinary(smp.id);
                      }}
                      className="flex w-full items-center justify-between px-3 py-1 text-left text-slate-300 hover:bg-[#111a29] hover:text-white"
                    >
                      <span className="truncate">{smp.filename}</span>
                      <span className="ml-2 shrink-0 border border-[#182232] bg-[#06090f] px-1 text-[10px] text-[#38bdf8]">
                        {smp.badge}
                      </span>
                    </button>
                  ))}
                  {recentFiles.length > 0 && (
                    <>
                      <div className="my-1 border-t border-[#182232]" />
                      <div className="flex items-center justify-between px-3 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-[#64748b]">
                        <span>Recent (IndexedDB)</span>
                        <button
                          type="button"
                          onClick={async () => {
                            await clearRecentFiles();
                            setRecentFiles([]);
                          }}
                          className="text-rose-400 hover:underline"
                        >
                          Clear
                        </button>
                      </div>
                      {recentFiles.slice(0, 4).map((rf) => (
                        <button
                          key={rf.id}
                          type="button"
                          onClick={() => {
                            setOpenMenu(null);
                            if (rf.binaryData) {
                              loadBinaryBuffer(rf.binaryData, rf.filename);
                            }
                          }}
                          className="flex w-full items-center justify-between px-3 py-0.5 text-left text-slate-300 hover:bg-[#111a29]"
                        >
                          <span className="truncate">{rf.filename}</span>
                          <span className="text-[10px] text-[#64748b]">
                            {(rf.size / 1024).toFixed(1)}K
                          </span>
                        </button>
                      ))}
                    </>
                  )}
                  <div className="my-1 border-t border-[#182232]" />
                  <button
                    type="button"
                    onClick={() => {
                      setOpenMenu(null);
                      handleSaveProject();
                    }}
                    className="flex w-full items-center justify-between px-3 py-1 text-left text-slate-200 hover:bg-[#111a29]"
                  >
                    <span>Save Project (.spetproj.json)</span>
                    <span className="text-[10px] text-[#64748b]">Ctrl+S</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setOpenMenu(null);
                      projectInputRef.current?.click();
                    }}
                    className="flex w-full items-center justify-between px-3 py-1 text-left text-slate-200 hover:bg-[#111a29]"
                  >
                    <span>Load Project Annotations...</span>
                  </button>
                  <div className="my-1 border-t border-[#182232]" />
                  <button
                    type="button"
                    onClick={() => {
                      setOpenMenu(null);
                      if (analysis) {
                        const md = generateMarkdownReport(analysis, decompA, decompB);
                        downloadLocalBlob(md, `${analysis.metadata.filename}-report.md`, 'text/markdown');
                      }
                    }}
                    className="flex w-full items-center justify-between px-3 py-1 text-left text-[#38bdf8] hover:bg-[#111a29]"
                  >
                    <span>Export Markdown Report (.md)</span>
                  </button>
                </div>
              )}
            </div>

            <div className="relative">
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  setOpenMenu(openMenu === 'analysis' ? null : 'analysis');
                }}
                className={`px-1.5 py-0.5 text-slate-300 hover:text-white hover:bg-[#111a29] ${
                  openMenu === 'analysis' ? 'bg-[#111a29] text-white' : ''
                }`}
              >
                Analysis
              </button>
              {openMenu === 'analysis' && (
                <div
                  onClick={(e) => e.stopPropagation()}
                  className="absolute left-0 top-full mt-0.5 w-64 border border-[#182232] bg-[#090d14] py-1 shadow-2xl z-50 text-[11px]"
                >
                  <button
                    type="button"
                    onClick={() => {
                      setOpenMenu(null);
                      if (binaryData && analysis) {
                        loadBinaryBuffer(binaryData, analysis.metadata.filename);
                      }
                    }}
                    className="flex w-full items-center justify-between px-3 py-1 text-left text-slate-200 hover:bg-[#111a29]"
                  >
                    <span>Re-Run Full Analysis (aaa)</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setOpenMenu(null);
                      handleAutoNameAllFunctions();
                    }}
                    className="flex w-full items-center justify-between px-3 py-1 text-left text-[#38bdf8] hover:bg-[#111a29]"
                  >
                    <span>Auto-Name All Functions (sub_*)</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setOpenMenu(null);
                      handleUndoRename();
                    }}
                    className="flex w-full items-center justify-between px-3 py-1 text-left text-slate-200 hover:bg-[#111a29]"
                  >
                    <span>Undo Last Function Rename</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setOpenMenu(null);
                      handleRedoRename();
                    }}
                    className="flex w-full items-center justify-between px-3 py-1 text-left text-slate-200 hover:bg-[#111a29]"
                  >
                    <span>Redo Function Rename</span>
                  </button>
                </div>
              )}
            </div>

            <div className="relative">
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  setOpenMenu(openMenu === 'view' ? null : 'view');
                }}
                className={`px-1.5 py-0.5 text-slate-300 hover:text-white hover:bg-[#111a29] ${
                  openMenu === 'view' ? 'bg-[#111a29] text-white' : ''
                }`}
              >
                View
              </button>
              {openMenu === 'view' && (
                <div
                  onClick={(e) => e.stopPropagation()}
                  className="absolute left-0 top-full mt-0.5 w-60 border border-[#182232] bg-[#090d14] py-1 shadow-2xl z-50 text-[11px]"
                >
                  {(
                    [
                      ['dual-decompiler', 'Dual C Decompilers (D)'],
                      ['decompiler-a', 'Engine A: Rizin + jsdec'],
                      ['decompiler-b', 'Engine B: Ghidra WASM'],
                      ['disassembly', 'Disassembly View (2)'],
                      ['cfg', 'Control Flow Graph (3)'],
                      ['callgraph', 'Call Graph'],
                      ['hex', 'Raw Hex View (4)'],
                    ] as Array<[CenterTab, string]>
                  ).map(([tabId, label]) => (
                    <button
                      key={tabId}
                      type="button"
                      onClick={() => {
                        setCenterTab(tabId);
                        setOpenMenu(null);
                      }}
                      className="flex w-full items-center justify-between px-3 py-1 text-left text-slate-200 hover:bg-[#111a29]"
                    >
                      <span>{label}</span>
                      {centerTab === tabId && <Check className="h-3 w-3 text-[#38bdf8]" />}
                    </button>
                  ))}
                  <div className="my-1 border-t border-[#182232]" />
                  <div className="px-3 py-0.5 text-[9px] font-semibold uppercase tracking-wider text-[#64748b]">
                    UI Color Theme
                  </div>
                  {THEMES.map((th) => (
                    <button
                      key={th.id}
                      type="button"
                      onClick={() => {
                        setCurrentTheme(th.id);
                        setOpenMenu(null);
                      }}
                      className="flex w-full items-center justify-between px-3 py-1 text-left text-slate-200 hover:bg-[#111a29]"
                    >
                      <span>{th.name}</span>
                      {currentTheme === th.id && <Check className="h-3 w-3 text-[#38bdf8]" />}
                    </button>
                  ))}
                  <div className="my-1 border-t border-[#182232]" />
                  <button
                    type="button"
                    onClick={() => {
                      setIsBottomDockOpen((v) => !v);
                      setOpenMenu(null);
                    }}
                    className="flex w-full items-center justify-between px-3 py-1 text-left text-slate-200 hover:bg-[#111a29]"
                  >
                    <span>Toggle Bottom Console</span>
                    <span className="text-[10px] text-[#64748b]">{isBottomDockOpen ? 'Hide' : 'Show'}</span>
                  </button>
                </div>
              )}
            </div>

            <button
              type="button"
              onClick={() => setCenterTab('hex')}
              className={`px-1.5 py-0.5 text-slate-300 hover:text-white hover:bg-[#111a29] ${
                centerTab === 'hex' ? 'bg-[#111a29] text-[#38bdf8]' : ''
              }`}
            >
              Hex
            </button>

            <button
              type="button"
              onClick={() => setShowSettingsModal(true)}
              className="px-1.5 py-0.5 text-slate-300 hover:text-white hover:bg-[#111a29]"
            >
              Settings
            </button>

            <div className="relative">
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  setOpenMenu(openMenu === 'help' ? null : 'help');
                }}
                className={`px-1.5 py-0.5 text-slate-300 hover:text-white hover:bg-[#111a29] ${
                  openMenu === 'help' ? 'bg-[#111a29] text-white' : ''
                }`}
              >
                Help
              </button>
              {openMenu === 'help' && (
                <div
                  onClick={(e) => e.stopPropagation()}
                  className="absolute left-0 top-full mt-0.5 w-60 border border-[#182232] bg-[#090d14] py-1 shadow-2xl z-50 text-[11px]"
                >
                  <button
                    type="button"
                    onClick={() => {
                      setOpenMenu(null);
                      setShowShortcutsModal(true);
                    }}
                    className="flex w-full items-center px-3 py-1 text-left text-slate-200 hover:bg-[#111a29]"
                  >
                    Keyboard Shortcuts
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setOpenMenu(null);
                      setAboutModalTab('engines');
                    }}
                    className="flex w-full items-center px-3 py-1 text-left text-slate-200 hover:bg-[#111a29]"
                  >
                    Engine Architecture
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setOpenMenu(null);
                      setAboutModalTab('security');
                    }}
                    className="flex w-full items-center px-3 py-1 text-left text-[#34d399] hover:bg-[#111a29]"
                  >
                    100% Local-First Sandbox
                  </button>
                </div>
              )}
            </div>
          </nav>
        </div>

        <div className="flex items-center gap-2">

          <div className="hidden xl:flex items-center gap-1.5 text-[11px] text-[#64748b] truncate max-w-xl">
            {analysis ? (
              <>
                <span className="text-slate-300 font-semibold truncate">Target: {analysis.metadata.filename}</span>
                <span>|</span>
                <span className="text-[#38bdf8]">{analysis.metadata.format}</span>
                <span>|</span>
                <span>{(analysis.metadata.size / 1048576).toFixed(2)} MB</span>
                <span>|</span>
                <span className="text-amber-400">{analysis.functions.length.toLocaleString()} funcs</span>
                <span>|</span>
                <span>{analysis.analysisDurationMs} ms</span>
              </>
            ) : (
              <span>Target: (No binary loaded)</span>
            )}
          </div>

          <div className="flex items-center gap-1 shrink-0">
            <span className="text-[10px] text-[#64748b]">Theme:</span>
            <select
              value={currentTheme}
              onChange={(e) => setCurrentTheme(e.target.value as ThemeId)}
              className="h-[20px] px-1 bg-[#090d14] border border-[#182232] text-[10px] text-slate-300 font-mono focus:border-[#38bdf8] focus:outline-none"
            >
              {THEMES.map((th) => (
                <option key={th.id} value={th.id}>
                  {th.name}
                </option>
              ))}
            </select>
          </div>

          <div className="flex items-center gap-1">
            <select
              value={SAMPLE_BINARIES.find((s) => s.filename === analysis?.metadata.filename)?.id || ''}
              onChange={async (e) => {
                await loadSampleBinary(e.target.value);
              }}
              className="h-[20px] px-1 bg-[#090d14] border border-[#182232] text-[10px] text-slate-300 font-mono focus:border-[#38bdf8] focus:outline-none"
            >
              <option value="" disabled>
                Demo Samples...
              </option>
              {SAMPLE_BINARIES.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.filename}
                </option>
              ))}
            </select>

            <button
              type="button"
              onClick={() => fileInputRef.current?.click()}
              className="h-[20px] px-2 bg-[#111a29] border border-[#26354d] hover:border-[#38bdf8] text-[10px] text-slate-200 font-mono flex items-center gap-1.5 cursor-pointer"
            >
              <img
                src={`${getBaseUrl()}icons/directory_open_file_mydocs-4.png`}
                alt=""
                className="pixelated shrink-0 w-3 h-3"
              />
              <span>[Load File]</span>
            </button>
          </div>

          {isAnalyzing || isDecompilingA || isDecompilingB ? (
            <button
              type="button"
              onClick={handleCancelAnalysis}
              className="h-[20px] px-2 bg-rose-950/40 border border-rose-800 text-rose-300 text-[10px] font-mono flex items-center gap-1"
            >
              <Square className="h-2 w-2 fill-current" /> Cancel Worker
            </button>
          ) : null}

          <PwaInstallButton />
        </div>
      </header>

      <div className="h-[24px] shrink-0 bg-[#0c121d] border-b border-[#182232] px-2.5 flex items-center justify-between text-[11px] font-mono select-none">

        <div className="flex items-center gap-2 flex-1 min-w-0 mr-4">
          <span className="text-[10px] uppercase tracking-wider text-[#64748b] shrink-0">
            Memory Map:
          </span>
          {analysis && analysis.sections.length > 0 ? (
            <div className="flex items-center h-[14px] flex-1 max-w-xl bg-[#06090f] border border-[#182232] overflow-hidden">
              {analysis.sections.map((sec) => {
                const proportion = Math.max(
                  1.5,
                  ((Math.max(sec.size, sec.virtualSize, 1) / totalSectionSize) * 100)
                );
                const isText = sec.name.includes('text');
                const isRdata = sec.name.includes('rdata') || sec.name.includes('rodata');
                const isData = sec.name.includes('data');
                const isRsrc = sec.name.includes('rsrc') || sec.name.includes('reloc');

                const bgClass = isText
                  ? 'bg-[#0284c7]/40 text-[#38bdf8]'
                  : isRdata
                    ? 'bg-[#38bdf8]/20 text-[#38bdf8]'
                    : isData
                      ? 'bg-[#f59e0b]/30 text-[#f59e0b]'
                      : isRsrc
                        ? 'bg-[#8b5cf6]/30 text-[#c084fc]'
                        : 'bg-[#475569]/30 text-slate-400';

                return (
                  <div
                    key={sec.name}
                    style={{ width: `${proportion}%` }}
                    className={`h-full border-r border-[#182232] flex items-center justify-center text-[9px] font-mono truncate px-0.5 cursor-pointer hover:brightness-125 ${bgClass}`}
                    title={`${sec.name} · VAddr: ${sec.virtualAddress} · Offset: ${sec.fileOffset} · ${sec.size} B (${sec.permissions})`}
                    onClick={() => {
                      setCenterTab('hex');
                    }}
                  >
                    {proportion > 8 ? sec.name : ''}
                  </div>
                );
              })}
            </div>
          ) : (
            <span className="text-[10px] text-slate-500">[No sections loaded]</span>
          )}
        </div>

        <div className="flex items-center gap-1.5 text-[11px] text-[#64748b] shrink-0">
          <span className="text-slate-500">Cursor:</span>
          <span className="text-[#38bdf8] font-bold">
            {selectedFnAddr || '0x00000000'}
          </span>
          <ChevronRight className="h-3 w-3 text-slate-600" />
          <span className="text-[#e2e8f0] font-medium truncate max-w-[200px]">
            {activeFnInfo ? customNames[activeFnInfo.address] || activeFnInfo.name : 'idle'}
          </span>
        </div>
      </div>

      <div className="flex-1 min-h-0 flex overflow-hidden">

        <aside className="w-[270px] shrink-0 border-r border-[#182232] flex flex-col bg-[#090d14] overflow-hidden select-none">

          <div className="h-[24px] bg-[#0c121d] border-b border-[#182232] px-2 flex items-center justify-between text-[11px] font-mono text-slate-300 font-semibold shrink-0">
            <div className="flex items-center gap-1.5 truncate">
              <img
                src={`${getBaseUrl()}icons/console_prompt-0.png`}
                alt=""
                className="pixelated shrink-0 w-3.5 h-3.5"
              />
              <span className="truncate">FUNCTIONS ({filteredFunctions.length})</span>
            </div>
            <div className="flex items-center gap-1">
              <button
                type="button"
                onClick={handleAutoNameAllFunctions}
                className="border border-[#182232] bg-[#111a29] px-1 py-0.2 text-[9px] text-[#38bdf8] hover:border-[#38bdf8]"
                title="Auto-name sub_* functions (IDA style)"
              >
                Auto sub_*
              </button>
              <button
                type="button"
                onClick={() => {
                  if (analysis) {
                    const out = formatFunctionsExport(analysis.functions, 'json');
                    downloadLocalBlob(out, `${analysis.metadata.filename}-functions.json`, 'application/json');
                  }
                }}
                className="border border-[#182232] bg-[#090d14] px-1 py-0.2 text-[9px] text-slate-400 hover:text-white"
                title="Export Function List (JSON)"
              >
                <Download className="h-2.5 w-2.5" />
              </button>
            </div>
          </div>

          <div className="p-1 border-b border-[#182232] bg-[#070a10] space-y-1 shrink-0">
            <div className="relative">
              <Search className="pointer-events-none absolute left-1.5 top-1 h-3 w-3 text-slate-600" />
              <input
                ref={searchInputRef}
                type="text"
                value={fnSearch}
                onChange={(e) => setFnSearch(e.target.value)}
                placeholder="Filter function or 0x addr (Ctrl+K)"
                className="w-full h-[22px] bg-[#06090f] border border-[#182232] pl-6 pr-1 text-[11px] font-mono text-slate-200 placeholder:text-slate-600 focus:border-[#38bdf8] focus:outline-none"
              />
            </div>
            <div className="flex items-center gap-1">
              <ListFilter className="h-2.5 w-2.5 text-slate-600 shrink-0" />
              <select
                value={fnCategoryFilter}
                onChange={(e) => setFnCategoryFilter(e.target.value as any)}
                className="w-full h-[20px] bg-[#06090f] border border-[#182232] px-1 text-[10px] font-mono text-slate-400 focus:border-[#38bdf8] focus:outline-none"
              >
                <option value="all">All Categories ({analysis?.functions.length || 0})</option>
                <option value="favorites">★ Favorites ({favorites.size})</option>
                <option value="entry">Entry Points (_start)</option>
                <option value="exported">Exported Functions</option>
                <option value="imported">Imported Stubs (imp_*)</option>
                <option value="thunk">Thunk Functions (j_*)</option>
                <option value="standard">Standard Internal (sub_*)</option>
                <option value="unreferenced">Unreferenced Functions</option>
              </select>
            </div>
          </div>

          <div className="flex-1 overflow-y-auto divide-y divide-[#182232]/40 bg-[#090d14]">
            {filteredFunctions.map((fn) => {
              const isSelected = fn.address === selectedFnAddr;
              const activeName = customNames[fn.address] || fn.name;
              const isFav = favorites.has(fn.address);
              const hasComment = Boolean(fnComments[fn.address]);

              return (
                <div
                  key={fn.address}
                  onClick={() => inspectFunction(fn.address)}
                  className={`group h-[22px] px-2 flex items-center justify-between text-[11px] font-mono cursor-pointer transition-colors ${
                    isSelected
                      ? 'bg-[#111a29] text-[#38bdf8] border-l-2 border-l-[#38bdf8]'
                      : 'hover:bg-[#38bdf8]/[0.08] text-slate-300'
                  }`}
                >

                  <span className="w-[75px] shrink-0 text-[#64748b] truncate text-[10px]">
                    {fn.address}
                  </span>

                  <span className={`flex-1 truncate pr-1 flex items-center gap-1 ${isSelected ? 'text-[#38bdf8] font-bold' : 'text-[#e2e8f0]'}`}>
                    <img
                      src={`${getBaseUrl()}icons/console_prompt-0.png`}
                      alt=""
                      className="pixelated shrink-0 w-3 h-3 opacity-70"
                    />
                    <span className="truncate">{activeName}</span>
                  </span>

                  {hasComment && (
                    <MessageSquare className="h-2.5 w-2.5 text-amber-400 shrink-0 mr-1" />
                  )}

                  <span className="w-[42px] shrink-0 text-right text-[#475569] text-[10px] group-hover:hidden">
                    {fn.size}B
                  </span>

                  <div className="hidden group-hover:flex items-center gap-1 shrink-0">
                    <span
                      className="text-[9px] px-1 py-0.2 border border-[#182232] bg-[#06090f] text-[#38bdf8] uppercase tracking-wider rounded-[2px]"
                      title={`Category: ${fn.category}`}
                    >
                      {fn.category.slice(0, 4)}
                    </span>
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        setRenamingFn({ address: fn.address, currentName: activeName });
                      }}
                      className="p-0.5 text-slate-400 hover:text-[#38bdf8]"
                      title="Rename Function (N)"
                    >
                      <Edit3 className="h-2.5 w-2.5" />
                    </button>
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        setFavorites((prev) => {
                          const next = new Set(prev);
                          if (next.has(fn.address)) next.delete(fn.address);
                          else next.add(fn.address);
                          return next;
                        });
                      }}
                      className={`p-0.5 ${isFav ? 'text-amber-400' : 'text-slate-500 hover:text-slate-300'}`}
                      title="Bookmark Function"
                    >
                      <Star className={`h-2.5 w-2.5 ${isFav ? 'fill-current' : ''}`} />
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </aside>

        <main className="flex-1 flex flex-col min-w-0 bg-[#080b11] overflow-hidden">

          <div className="h-[28px] shrink-0 bg-[#06090f] border-b border-[#182232] flex items-center justify-between select-none overflow-x-auto no-scrollbar">
            <div className="flex items-center h-full shrink-0">
              {(
                [
                  ['dual-decompiler', '[DUAL] Dual C View'],
                  ['decompiler-a', '[A: RIZIN+JSDEC]'],
                  ['decompiler-b', '[B: GHIDRA SLEIGH]'],
                  ['disassembly', '[ASM] Disassembly'],
                  ['cfg', '[CFG]'],
                  ['callgraph', '[CALL] Call Graph'],
                  ['hex', '[HEX]'],
                ] as Array<[CenterTab, string]>
              ).map(([id, label]) => {
                const active = centerTab === id;
                return (
                  <button
                    key={id}
                    type="button"
                    onClick={() => setCenterTab(id)}
                    className={`h-full px-3 text-[11px] font-mono whitespace-nowrap shrink-0 flex items-center gap-1.5 transition-colors cursor-pointer border-r border-[#182232] ${
                      active
                        ? 'text-white bg-[#090d14] border-t-2 border-t-[#38bdf8] font-bold'
                        : 'text-slate-400 hover:bg-[#0c121d] hover:text-slate-200'
                    }`}
                  >
                    <span>{label}</span>
                  </button>
                );
              })}
            </div>

            {activeFnInfo && (
              <div className="flex items-center gap-1.5 pr-2.5 text-[11px] font-mono">
                <button
                  type="button"
                  onClick={() =>
                    setRenamingFn({
                      address: activeFnInfo.address,
                      currentName: customNames[activeFnInfo.address] || activeFnInfo.name,
                    })
                  }
                  className="inline-flex items-center gap-1 border border-[#182232] bg-[#111a29] px-2 py-0.5 text-[10px] text-slate-300 hover:border-[#38bdf8] hover:text-[#38bdf8]"
                >
                  <Edit3 className="h-2.5 w-2.5" /> Rename (N)
                </button>
                <button
                  type="button"
                  onClick={() =>
                    setCommentingFn({
                      address: activeFnInfo.address,
                      currentComment: fnComments[activeFnInfo.address] || '',
                    })
                  }
                  className="inline-flex items-center gap-1 border border-[#182232] bg-[#111a29] px-2 py-0.5 text-[10px] text-slate-300 hover:border-amber-400 hover:text-amber-300"
                >
                  <MessageSquare className="h-2.5 w-2.5" /> Comment (;)
                </button>
              </div>
            )}
          </div>

          {renamingFn && (
            <form
              onSubmit={(e) => {
                e.preventDefault();
                applyRename(renamingFn.address, renamingFn.currentName);
              }}
              className="h-[28px] shrink-0 flex items-center justify-between gap-2 border-b border-[#38bdf8] bg-[#090d14] px-3 text-[11px] font-mono"
            >
              <div className="flex items-center gap-2">
                <span className="text-[#38bdf8] font-bold">Rename @ {renamingFn.address}:</span>
                <input
                  type="text"
                  autoFocus
                  value={renamingFn.currentName}
                  onChange={(e) => setRenamingFn({ ...renamingFn, currentName: e.target.value })}
                  className="h-[20px] w-64 bg-[#06090f] border border-[#38bdf8] px-2 text-white font-mono text-[11px] focus:outline-none"
                />
              </div>
              <div className="flex items-center gap-1">
                <button
                  type="submit"
                  className="h-[20px] px-2 bg-[#38bdf8] text-slate-950 font-bold hover:bg-[#38bdf8]/90 text-[10px]"
                >
                  Apply & Sync
                </button>
                <button
                  type="button"
                  onClick={() => setRenamingFn(null)}
                  className="h-[20px] px-2 border border-[#182232] text-slate-400 hover:text-white text-[10px]"
                >
                  Cancel
                </button>
              </div>
            </form>
          )}

          {commentingFn && (
            <form
              onSubmit={(e) => {
                e.preventDefault();
                setFnComments((prev) => ({
                  ...prev,
                  [commentingFn.address]: commentingFn.currentComment.trim(),
                }));
                setCommentingFn(null);
              }}
              className="h-[28px] shrink-0 flex items-center justify-between gap-2 border-b border-amber-400 bg-[#090d14] px-3 text-[11px] font-mono"
            >
              <div className="flex items-center gap-2 flex-1">
                <span className="text-amber-400 font-bold">Comment @ {commentingFn.address}:</span>
                <input
                  type="text"
                  autoFocus
                  value={commentingFn.currentComment}
                  onChange={(e) =>
                    setCommentingFn({ ...commentingFn, currentComment: e.target.value })
                  }
                  placeholder="Enter analyst note..."
                  className="h-[20px] flex-1 max-w-lg bg-[#06090f] border border-amber-400 px-2 text-white font-mono text-[11px] focus:outline-none"
                />
              </div>
              <div className="flex items-center gap-1">
                <button
                  type="submit"
                  className="h-[20px] px-2 bg-amber-400 text-slate-950 font-bold hover:bg-amber-300 text-[10px]"
                >
                  Save Note
                </button>
                <button
                  type="button"
                  onClick={() => setCommentingFn(null)}
                  className="h-[20px] px-2 border border-[#182232] text-slate-400 hover:text-white text-[10px]"
                >
                  Cancel
                </button>
              </div>
            </form>
          )}

          <div className="flex-1 min-h-0 overflow-hidden bg-[#080b11]">
            {!analysis ? (
              <div className="flex h-full flex-col items-center justify-center p-3 bg-[#06090f] text-center select-none font-mono">
                <div className="max-w-md p-3 border border-[#182232] bg-[#090d14]">
                  <div className="text-xs font-bold text-[#38bdf8] uppercase tracking-wider mb-1">
                    Spet&apos;s Easy Online Decompiler
                  </div>
                  <p className="text-[11px] text-slate-400 leading-normal mb-3">
                    Local WebAssembly Binary Analysis &amp; Dual C-Like Decompiler (Rizin + Ghidra).
                  </p>
                  <div className="flex items-center justify-center gap-2">
                    <button
                      type="button"
                      onClick={() => fileInputRef.current?.click()}
                      className="h-[22px] px-2.5 bg-[#111a29] border border-[#38bdf8] text-[#38bdf8] text-[10px] font-mono hover:bg-[#38bdf8]/20 flex items-center gap-1.5 cursor-pointer"
                    >
                      <img
                        src={`${getBaseUrl()}icons/directory_open_file_mydocs-4.png`}
                        alt=""
                        className="pixelated shrink-0 w-3 h-3"
                      />
                      <span>[Open Binary File]</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => loadSampleBinary('gfwl-setup')}
                      className="h-[22px] px-2.5 bg-[#090d14] border border-[#182232] text-slate-300 text-[10px] font-mono hover:border-slate-400 flex items-center gap-1.5 cursor-pointer"
                    >
                      <img
                        src={`${getBaseUrl()}icons/executable-0.png`}
                        alt=""
                        className="pixelated shrink-0 w-3 h-3"
                      />
                      <span>[Load GFWL Sample]</span>
                    </button>
                  </div>
                </div>
              </div>
            ) : (
              <>

                {centerTab === 'dual-decompiler' && (
                  <div className="grid h-full grid-cols-1 divide-y divide-[#182232] lg:grid-cols-2 lg:divide-x lg:divide-y-0">
                    <DecompilerCodePane
                      code={formattedCodeA}
                      errors={decompA?.errors}
                      isLoading={isDecompilingA}
                      loadingMessage="Running Rizin + jsdec AST control-flow structuring..."
                      engineName="Decompiler A: Rizin v0.9.1 + jsdec v0.9.0"
                      engineId="rizin-jsdec"
                      durationMs={decompA?.durationMs}
                      copiedId={copiedId}
                      copyKey="decA"
                      onCopy={() => copyText('decA', formattedCodeA)}
                      onDownload={() =>
                        downloadLocalBlob(
                          formattedCodeA,
                          `${activeFnInfo?.name || 'func'}-rizin.c`,
                          'text/x-c'
                        )
                      }
                      onSwitchToGhidra={() => setCenterTab('decompiler-b')}
                      onSwitchToDisasm={() => setCenterTab('disassembly')}
                      onJumpFunction={jumpToFunctionByNameOrAddr}
                      baseAddress={selectedFnAddr}
                      fontClass={fontClass}
                    />

                    <DecompilerCodePane
                      code={formattedCodeB}
                      errors={decompB?.errors}
                      isLoading={isDecompilingB}
                      loadingMessage="Lifting P-Code & running Ghidra SSA decompiler..."
                      engineName="Decompiler B: Ghidra C++ Sleigh WASM (v11.2)"
                      engineId="ghidra-wasm"
                      durationMs={decompB?.durationMs}
                      copiedId={copiedId}
                      copyKey="decB"
                      onCopy={() => copyText('decB', formattedCodeB)}
                      onDownload={() =>
                        downloadLocalBlob(
                          formattedCodeB,
                          `${activeFnInfo?.name || 'func'}-ghidra.c`,
                          'text/x-c'
                        )
                      }
                      onSwitchToRizin={() => setCenterTab('decompiler-a')}
                      onSwitchToDisasm={() => setCenterTab('disassembly')}
                      onJumpFunction={jumpToFunctionByNameOrAddr}
                      baseAddress={selectedFnAddr}
                      fontClass={fontClass}
                    />
                  </div>
                )}

                {centerTab === 'decompiler-a' && (
                  <DecompilerCodePane
                    code={formattedCodeA}
                    errors={decompA?.errors}
                    isLoading={isDecompilingA}
                    loadingMessage="Running Rizin + jsdec AST control-flow structuring..."
                    engineName="Decompiler A: Rizin v0.9.1 + jsdec v0.9.0"
                    engineId="rizin-jsdec"
                    durationMs={decompA?.durationMs}
                    copiedId={copiedId}
                    copyKey="decA"
                    onCopy={() => copyText('decA', formattedCodeA)}
                    onDownload={() =>
                      downloadLocalBlob(
                        formattedCodeA,
                        `${activeFnInfo?.name || 'func'}-rizin.c`,
                        'text/x-c'
                      )
                    }
                    onSwitchToGhidra={() => setCenterTab('decompiler-b')}
                    onSwitchToDisasm={() => setCenterTab('disassembly')}
                    onJumpFunction={jumpToFunctionByNameOrAddr}
                    baseAddress={selectedFnAddr}
                    fontClass={fontClass}
                  />
                )}

                {centerTab === 'decompiler-b' && (
                  <DecompilerCodePane
                    code={formattedCodeB}
                    errors={decompB?.errors}
                    isLoading={isDecompilingB}
                    loadingMessage="Lifting P-Code & running Ghidra SSA decompiler..."
                    engineName="Decompiler B: Ghidra C++ Sleigh WASM (v11.2)"
                    engineId="ghidra-wasm"
                    durationMs={decompB?.durationMs}
                    copiedId={copiedId}
                    copyKey="decB"
                    onCopy={() => copyText('decB', formattedCodeB)}
                    onDownload={() =>
                      downloadLocalBlob(
                        formattedCodeB,
                        `${activeFnInfo?.name || 'func'}-ghidra.c`,
                        'text/x-c'
                      )
                    }
                    onSwitchToRizin={() => setCenterTab('decompiler-a')}
                    onSwitchToDisasm={() => setCenterTab('disassembly')}
                    onJumpFunction={jumpToFunctionByNameOrAddr}
                    baseAddress={selectedFnAddr}
                    fontClass={fontClass}
                  />
                )}

                {centerTab === 'disassembly' && (
                  <div className="flex h-full flex-col overflow-hidden bg-[#06090f]">
                    <div className="h-[26px] shrink-0 flex items-center justify-between border-b border-[#182232] bg-[#0c121d] px-2.5 text-[11px] font-mono select-none">
                      <span className="text-slate-300">
                        Disassembly Listing — {disasmLines.length} instructions
                      </span>
                      <button
                        type="button"
                        onClick={() => {
                          const txt = disasmLines
                            .map((l) => `${l.address.padEnd(12)} ${l.bytes.padEnd(18)} ${l.disasm}`)
                            .join('\n');
                          downloadLocalBlob(txt, `${activeFnInfo?.name || 'disasm'}.asm`, 'text/plain');
                        }}
                        className="border border-[#182232] bg-[#111a29] px-2 py-0.5 text-[10px] text-slate-300 hover:text-white"
                      >
                        Export .asm
                      </button>
                    </div>
                    <div className={`flex-1 select-text overflow-auto font-mono text-xs leading-5 p-2 ${fontClass}`}>
                      {disasmLines.map((line, idx) => (
                        <div
                          key={`${line.address}-${idx}`}
                          className="flex items-baseline gap-4 px-1 py-0.2 hover:bg-[#38bdf8]/[0.08]"
                        >
                          {settings.showAddresses && (
                            <span className="w-24 shrink-0 text-[#38bdf8] font-mono">{line.address}</span>
                          )}
                          {settings.showBytes && (
                            <span className="w-32 shrink-0 text-[#64748b] font-mono">{line.bytes}</span>
                          )}
                          <span className="min-w-[200px] text-slate-200 font-mono">
                            <strong className="text-[#c084fc]">{line.mnemonic}</strong>{' '}
                            <span>{line.operands}</span>
                          </span>
                          {settings.showComments && line.comment && (
                            <span className="text-[#34d399]/80 font-mono">; {line.comment}</span>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {centerTab === 'cfg' && <CfgCanvasView cfg={cfgData} />}

                {centerTab === 'callgraph' && (
                  <CallGraphCanvasView
                    callGraph={analysis?.callGraph || null}
                    selectedAddress={selectedFnAddr}
                    onSelectFunction={(addr) => inspectFunction(addr)}
                  />
                )}

                {centerTab === 'hex' && (
                  <HexViewerPane
                    data={binaryData}
                    sections={analysis?.sections || []}
                    fontClass={fontClass}
                  />
                )}
              </>
            )}
          </div>

          {isBottomDockOpen && (
            <div className="h-[130px] shrink-0 flex flex-col border-t border-[#182232] bg-[#05070b] overflow-hidden select-none">
              <div className="h-[24px] shrink-0 flex items-center justify-between border-b border-[#182232] bg-[#090d14] px-2 text-[11px] font-mono">
                <div className="flex items-center gap-1">
                  {(
                    [
                      ['logs', `Worker Log (${logs.length})`],
                      ['rizin-shell', 'Rizin WASM Shell (rzpipe)'],
                      ['rename-history', `Renames (${renameHistory.length})`],
                      [
                        'warnings',
                        `Diagnostics (${
                          (decompA?.warnings.length || 0) + (decompB?.warnings.length || 0)
                        })`,
                      ],
                    ] as Array<[BottomDockTab, string]>
                  ).map(([tId, label]) => (
                    <button
                      key={tId}
                      type="button"
                      onClick={() => setBottomTab(tId)}
                      className={`px-2 py-0.5 text-[10px] font-mono ${
                        bottomTab === tId
                          ? 'bg-[#111a29] text-[#38bdf8] border border-[#182232]'
                          : 'text-slate-400 hover:text-white'
                      }`}
                    >
                      {label}
                    </button>
                  ))}
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-[10px] text-[#64748b] truncate max-w-sm">
                    {statusMessage}
                  </span>
                  <button
                    type="button"
                    onClick={() => setIsBottomDockOpen(false)}
                    className="text-slate-500 hover:text-white text-[10px]"
                    title="Collapse Console"
                  >
                    [hide]
                  </button>
                </div>
              </div>

              <div className="flex-1 min-h-0 overflow-y-auto p-1.5 text-[11px] font-mono">
                {bottomTab === 'logs' && (
                  <div className="space-y-0.5">
                    {logs.map((l) => (
                      <div key={l.id} className="flex items-baseline gap-2">
                        <span className="text-[#64748b]">
                          [{new Date(l.timestamp).toLocaleTimeString()}]
                        </span>
                        <span className="font-semibold text-[#38bdf8]">[{l.source}]</span>
                        <span
                          className={
                            l.level === 'error'
                              ? 'text-rose-400'
                              : l.level === 'warn'
                                ? 'text-amber-300'
                                : l.level === 'success'
                                  ? 'text-[#34d399]'
                                  : 'text-slate-300'
                          }
                        >
                          {l.message}
                        </span>
                      </div>
                    ))}
                  </div>
                )}

                {bottomTab === 'rizin-shell' && (
                  <div className="flex h-full flex-col gap-1">
                    <form
                      onSubmit={async (e) => {
                        e.preventDefault();
                        if (!engineARef.current || !rizinCmdInput.trim()) return;
                        const out = await engineARef.current.executeRawCommand(rizinCmdInput.trim());
                        setRizinCmdOutput(out || '(empty output)');
                      }}
                      className="flex items-center gap-1.5 shrink-0"
                    >
                      <span className="text-[11px] font-bold text-[#38bdf8]">
                        [0x00401000]&gt;
                      </span>
                      <input
                        type="text"
                        value={rizinCmdInput}
                        onChange={(e) => setRizinCmdInput(e.target.value)}
                        placeholder="Rizin cmd (e.g. afl, iI, iz, pdf @ main, agf)"
                        className="flex-1 h-[20px] bg-[#06090f] border border-[#182232] px-1.5 text-[11px] font-mono text-white focus:border-[#38bdf8] focus:outline-none"
                      />
                      <button
                        type="submit"
                        className="h-[20px] px-2 border border-[#182232] bg-[#111a29] text-[10px] text-[#38bdf8] hover:border-[#38bdf8]"
                      >
                        Execute
                      </button>
                    </form>
                    <pre className="flex-1 select-text overflow-auto bg-[#06090f] border border-[#182232] p-1 text-[10px] text-slate-300 font-mono">
                      {rizinCmdOutput || 'Run any native Rizin command directly inside the WASM worker.'}
                    </pre>
                  </div>
                )}

                {bottomTab === 'rename-history' && (
                  <div className="space-y-0.5">
                    {renameHistory.length === 0 ? (
                      <div className="text-[#64748b]">No renames recorded. Press N on any function to rename.</div>
                    ) : (
                      renameHistory.map((item, idx) => (
                        <div
                          key={`${item.address}-${idx}`}
                          className="flex items-center justify-between px-1 text-[11px]"
                        >
                          <span>
                            <strong className="text-[#38bdf8]">{item.address}</strong>:{' '}
                            <span className="text-slate-400">{item.previousName}</span> →{' '}
                            <strong className="text-[#34d399]">{item.newName}</strong>
                          </span>
                          <span className="text-[#64748b]">
                            {new Date(item.timestamp).toLocaleTimeString()}
                          </span>
                        </div>
                      ))
                    )}
                  </div>
                )}

                {bottomTab === 'warnings' && (
                  <div className="space-y-0.5">
                    {[...(decompA?.warnings || []), ...(decompB?.warnings || [])].length === 0 ? (
                      <div className="text-[#64748b]">No decompiler engine warnings.</div>
                    ) : (
                      [...(decompA?.warnings || []), ...(decompB?.warnings || [])].map((w, i) => (
                        <div key={i} className="flex items-center gap-1.5 text-amber-300">
                          <AlertTriangle className="h-3 w-3 shrink-0" />
                          <span>{w}</span>
                        </div>
                      ))
                    )}
                  </div>
                )}
              </div>
            </div>
          )}
        </main>

        <aside className="w-[280px] shrink-0 border-l border-[#182232] flex flex-col bg-[#090d14] overflow-hidden select-none">

          <div className="h-[28px] shrink-0 bg-[#06090f] border-b border-[#182232] flex items-center overflow-x-auto text-[11px] font-mono">
            {(
              [
                ['metadata', 'Info'],
                ['strings', `Strings (${analysis?.strings.length || 0})`],
                ['imports', `Imports (${analysis?.imports.length || 0})`],
                ['exports', `Exports (${analysis?.exports.length || 0})`],
                ['sections', `Sections (${analysis?.sections.length || 0})`],
                ['xrefs', 'Details'],
              ] as Array<[RightInspectorTab, string]>
            ).map(([tId, label]) => (
              <button
                key={tId}
                type="button"
                onClick={() => setRightTab(tId)}
                className={`h-full px-2 font-mono text-[10px] border-r border-[#182232] transition-colors whitespace-nowrap cursor-pointer ${
                  rightTab === tId
                    ? 'bg-[#090d14] text-white border-t-2 border-t-[#38bdf8]'
                    : 'text-slate-400 hover:bg-[#0c121d] hover:text-slate-200'
                }`}
              >
                {label}
              </button>
            ))}
          </div>

          <div className="flex-1 overflow-y-auto p-2 text-xs font-mono">

            {rightTab === 'metadata' && analysis && (
              <div className="border border-[#182232] bg-[#06090f]">
                <div className="h-[22px] px-2 bg-[#0c121d] border-b border-[#182232] flex items-center text-[10px] font-bold text-[#38bdf8] uppercase tracking-wider">
                  Executable Overview
                </div>
                {(
                  [
                    ['Filename', analysis.metadata.filename],
                    ['Format', analysis.metadata.format],
                    ['Architecture', `${analysis.metadata.architecture} (${analysis.metadata.bits}-bit)`],
                    ['Entry Point', analysis.metadata.entryPoint],
                    ['Base Address', analysis.metadata.baseAddress],
                    ['Compiler', analysis.metadata.compiler],
                    ['Shannon Entropy', `${analysis.metadata.entropy.toFixed(2)} bits/byte`],
                    ['File Size', `${analysis.metadata.size.toLocaleString()} B`],
                    ['Machine', analysis.metadata.machine],
                    ['OS / ABI', `${analysis.metadata.os} · ${analysis.metadata.abi}`],
                  ] as Array<[string, string]>
                ).map(([k, v]) => (
                  <div
                    key={k}
                    className="h-[22px] px-2 flex items-center justify-between border-b border-[#141d2b] text-[11px]"
                  >
                    <span className="text-[#64748b]">{k}</span>
                    <span className="text-[#e2e8f0] font-medium truncate max-w-[150px] text-right">
                      {v}
                    </span>
                  </div>
                ))}

                <div className="p-2 border-b border-[#141d2b]">
                  <div className="text-[10px] text-[#64748b]">SHA-256 Digest</div>
                  <div
                    onClick={() => copyText('sha', analysis.metadata.sha256)}
                    className="mt-0.5 break-all text-[10px] text-slate-300 font-mono select-all cursor-pointer hover:text-[#38bdf8]"
                    title="Click to copy SHA-256"
                  >
                    {analysis.metadata.sha256}
                  </div>
                </div>
              </div>
            )}

            {rightTab === 'strings' && (
              <div className="flex h-full flex-col gap-1">
                <div className="space-y-1 shrink-0 pb-1 border-b border-[#182232]">
                  <input
                    type="text"
                    value={stringSearch}
                    onChange={(e) => setStringSearch(e.target.value)}
                    placeholder="Search strings..."
                    className="w-full h-[22px] bg-[#06090f] border border-[#182232] px-2 text-[11px] font-mono text-slate-200 placeholder:text-slate-600 focus:border-[#38bdf8] focus:outline-none"
                  />
                  <div className="flex items-center gap-1">
                    <select
                      value={stringCategoryFilter}
                      onChange={(e) => setStringCategoryFilter(e.target.value as any)}
                      className="flex-1 h-[20px] bg-[#06090f] border border-[#182232] px-1 text-[10px] font-mono text-slate-400"
                    >
                      <option value="all">All Categories</option>
                      <option value="URL">URLs</option>
                      <option value="Email">Emails</option>
                      <option value="FilePath">Paths</option>
                      <option value="ShellCommand">Commands</option>
                      <option value="CryptoIndicator">Crypto</option>
                      <option value="ErrorMessage">Errors</option>
                      <option value="DLL/Library">DLLs</option>
                      <option value="API/Symbol">APIs</option>
                    </select>
                    <button
                      type="button"
                      onClick={() => {
                        if (analysis) {
                          const csv = formatStringsExport(analysis.strings, 'csv');
                          downloadLocalBlob(csv, `${analysis.metadata.filename}-strings.csv`, 'text/csv');
                        }
                      }}
                      className="h-[20px] px-1.5 border border-[#182232] bg-[#111a29] text-[10px] text-slate-300 hover:text-white"
                      title="Export CSV"
                    >
                      CSV
                    </button>
                  </div>
                </div>

                <div className="flex-1 overflow-y-auto divide-y divide-[#182232]">
                  {filteredStrings.map((s, idx) => (
                    <div key={`${s.address}-${idx}`} className="py-1">
                      <div className="flex items-center justify-between text-[10px] text-[#64748b]">
                        <span className="text-[#38bdf8]">{s.address}</span>
                        <span>{s.section}</span>
                      </div>
                      <div className="mt-0.5 break-all text-[11px] text-slate-200 select-all font-mono">
                        {s.value}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {rightTab === 'imports' && analysis && (
              <div className="divide-y divide-[#182232]">
                {analysis.imports.length === 0 ? (
                  <div className="p-2 text-[#64748b]">Static binary — zero imports.</div>
                ) : (
                  analysis.imports.map((imp, idx) => (
                    <div key={`${imp.name}-${idx}`} className="py-1">
                      <div className="font-semibold text-[#38bdf8] text-[11px] truncate">{imp.name}</div>
                      <div className="flex items-center justify-between text-[10px] text-[#64748b]">
                        <span>{imp.library}</span>
                        <span>{imp.address}</span>
                      </div>
                    </div>
                  ))
                )}
              </div>
            )}

            {rightTab === 'exports' && analysis && (
              <div className="divide-y divide-[#182232]">
                {analysis.exports.length === 0 ? (
                  <div className="p-2 text-[#64748b]">No exported symbols.</div>
                ) : (
                  analysis.exports.map((exp, idx) => (
                    <div
                      key={`${exp.name}-${idx}`}
                      onClick={() => inspectFunction(exp.address)}
                      className="py-1 cursor-pointer hover:bg-[#38bdf8]/10"
                    >
                      <div className="font-semibold text-[#34d399] text-[11px] truncate">{exp.name}</div>
                      <div className="flex items-center justify-between text-[10px] text-[#64748b]">
                        <span>{exp.address}</span>
                        <span>{exp.size}B</span>
                      </div>
                    </div>
                  ))
                )}
              </div>
            )}

            {rightTab === 'sections' && analysis && (
              <div className="space-y-1.5">
                {analysis.sections.map((sec) => (
                  <div
                    key={sec.name}
                    className="border border-[#182232] bg-[#06090f] p-1.5 font-mono text-[11px]"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-[#38bdf8]">{sec.name}</span>
                      <span className="border border-[#182232] bg-[#090d14] px-1 text-[9px] text-[#64748b]">
                        {sec.permissions}
                      </span>
                    </div>
                    <div className="mt-1 grid grid-cols-2 gap-0.5 text-[10px] text-[#64748b]">
                      <span>VAddr: {sec.virtualAddress}</span>
                      <span>Off: {sec.fileOffset}</span>
                      <span>Size: {sec.size}B</span>
                      <span>Entropy: {sec.entropy.toFixed(2)}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {rightTab === 'xrefs' && activeFnInfo && (
              <div className="border border-[#182232] bg-[#06090f] p-2 space-y-1.5 text-[11px] font-mono">
                <div className="text-[10px] font-bold text-[#38bdf8] uppercase tracking-wider pb-1 border-b border-[#182232]">
                  Function Intelligence
                </div>
                <div>
                  <span className="text-[#64748b]">Active Name: </span>
                  <strong className="text-white">
                    {customNames[activeFnInfo.address] || activeFnInfo.name}
                  </strong>
                </div>
                <div>
                  <span className="text-[#64748b]">Address: </span>
                  <span className="text-[#38bdf8]">{activeFnInfo.address}</span>
                </div>
                <div>
                  <span className="text-[#64748b]">Original Symbol: </span>
                  <span className="text-slate-300">{activeFnInfo.originalName}</span>
                </div>
                <div>
                  <span className="text-[#64748b]">Signature: </span>
                  <span className="text-[#34d399] break-all">{activeFnInfo.signature}</span>
                </div>
                <div>
                  <span className="text-[#64748b]">Calling Conv: </span>
                  <span className="text-slate-300">{activeFnInfo.callingConvention}</span>
                </div>
                <div>
                  <span className="text-[#64748b]">Basic Blocks: </span>
                  <span>{activeFnInfo.basicBlocksCount}</span>
                </div>
                <div>
                  <span className="text-[#64748b]">Callers (In): </span>
                  <span className="break-all">{activeFnInfo.callers.join(', ') || 'None'}</span>
                </div>
                <div>
                  <span className="text-[#64748b]">Callees (Out): </span>
                  <span className="break-all">{activeFnInfo.callees.join(', ') || 'None'}</span>
                </div>
              </div>
            )}
          </div>
        </aside>
      </div>

      <footer className="h-[22px] shrink-0 z-20 bg-[#05070b] border-t border-[#182232] px-3 flex items-center justify-between text-[10px] font-mono text-slate-400 select-none">
        <div className="flex items-center gap-2 truncate">
          <span className="inline-flex items-center gap-1.5">
            <span
              className={`h-1.5 w-1.5 ${
                isAnalyzing || isDecompilingA || isDecompilingB
                  ? 'bg-amber-400 animate-pulse'
                  : 'bg-[#34d399]'
              }`}
            />
            <span>
              {isAnalyzing
                ? 'ANALYZING'
                : isDecompilingA || isDecompilingB
                  ? 'DECOMPILING'
                  : 'READY'}
            </span>
          </span>
          <span>|</span>
          <span>Worker: {isAnalyzing || isDecompilingA || isDecompilingB ? 'Active' : 'Idle'}</span>
          <span>|</span>
          <span>Memory: WebAssembly Linear Heap</span>
          {analysis && (
            <>
              <span>|</span>
              <span className="truncate">Active: {analysis.metadata.filename}</span>
            </>
          )}
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <button
            type="button"
            onClick={() => setIsBottomDockOpen((v) => !v)}
            className="h-[18px] px-1.5 bg-[#111a29] border border-[#182232] hover:border-[#38bdf8] text-slate-300 hover:text-white text-[9px] font-mono flex items-center gap-1 cursor-pointer"
            title="Toggle Bottom Console (Worker Log & Shell)"
          >
            <span>[Console: {isBottomDockOpen ? 'Hide' : 'Show'}]</span>
          </button>
          <span className="text-[#34d399] flex items-center gap-1 font-semibold">
            [Sandbox ID: WASM_LOCAL // NO_NET]
          </span>
        </div>
      </footer>

      <SettingsModal
        open={showSettingsModal}
        settings={settings}
        onUpdate={setSettings}
        onClose={() => setShowSettingsModal(false)}
      />
      <ShortcutsModal open={showShortcutsModal} onClose={() => setShowShortcutsModal(false)} />
      <AboutArchitectureModal
        open={aboutModalTab !== null}
        tab={aboutModalTab || 'engines'}
        onClose={() => setAboutModalTab(null)}
      />
    </div>
  );
}
