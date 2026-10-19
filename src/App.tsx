import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  FolderOpen,
  Play,
  Square,
  Download,
  Sliders,
  Search,
  Star,
  Edit3,
  MessageSquare,
  RotateCcw,
  Cpu,
  Terminal,
  FileCode2,
  GitBranch,
  Network,
  Binary,
  ListFilter,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  Copy,
  Check,
  Sparkles,
  Layers,
  History,
  BookOpen,
  ChevronDown,
  Lock,
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
  TestSuiteItemResult,
  WorkerLogEntry,
} from './types';
import { GhidraWasmEngine, RizinJsdecEngine } from './engines/engine-manager';
import { applyCustomNamesToCode } from './analysis/function-naming';
import {
  downloadLocalBlob,
  formatFunctionsExport,
  formatStringsExport,
  generateCallGraphSvg,
  generateCfgSvg,
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
type RightInspectorTab = 'metadata' | 'strings' | 'imports' | 'exports' | 'sections' | 'symbols' | 'xrefs';
type BottomDockTab = 'logs' | 'rizin-shell' | 'rename-history' | 'warnings';

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

  // Function Naming, Comments, Favorites, Undo/Redo
  const [customNames, setCustomNames] = useState<Record<string, string>>({});
  const [fnComments, setFnComments] = useState<Record<string, string>>({});
  const [favorites, setFavorites] = useState<Set<string>>(new Set());
  const [renameHistory, setRenameHistory] = useState<FunctionRenameAction[]>([]);
  const [redoStack, setRedoStack] = useState<FunctionRenameAction[]>([]);

  // Filters & Navigation
  const [fnSearch, setFnSearch] = useState('');
  const [fnCategoryFilter, setFnCategoryFilter] = useState<FunctionCategory | 'all' | 'favorites'>('all');
  const [stringSearch, setStringSearch] = useState('');
  const [stringCategoryFilter, setStringCategoryFilter] = useState<StringHeuristicCategory | 'all'>('all');

  // Active Tabs & Menus
  const [centerTab, setCenterTab] = useState<CenterTab>('dual-decompiler');
  const [rightTab, setRightTab] = useState<RightInspectorTab>('metadata');
  const [bottomTab, setBottomTab] = useState<BottomDockTab>('logs');
  const [openMenu, setOpenMenu] = useState<string | null>(null);

  // Modals & Inline Dialogs
  const [showSettingsModal, setShowSettingsModal] = useState(false);
  const [showShortcutsModal, setShowShortcutsModal] = useState(false);
  const [aboutModalTab, setAboutModalTab] = useState<'engines' | 'security' | 'about' | null>(null);
  const [renamingFn, setRenamingFn] = useState<{ address: string; currentName: string } | null>(null);
  const [commentingFn, setCommentingFn] = useState<{ address: string; currentComment: string } | null>(null);

  // Logs, Rizin Console, Recent Files, Copy state
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

  // Initialize Engines once
  useEffect(() => {
    const engA = new RizinJsdecEngine(appendLog);
    const engB = new GhidraWasmEngine(appendLog);
    engineARef.current = engA;
    engineBRef.current = engB;

    loadRecentFiles().then(setRecentFiles).catch(() => {});

    // Automatically load the first sample binary on startup so the workbench is immediately alive
    (async () => {
      try {
        const resp = await fetch(SAMPLE_BINARIES[0].path);
        if (resp.ok) {
          const buf = await resp.arrayBuffer();
          await loadBinaryBuffer(new Uint8Array(buf), SAMPLE_BINARIES[0].filename);
        }
      } catch {
        // Ignore initial auto-load error
      }
    })();

    return () => {
      engA.cancelAndRestart();
      engB.cancelAndRestart();
    };
  }, []);

  // Sync theme & settings
  useEffect(() => {
    saveAppSettings(settings);
    const root = document.documentElement;
    if (settings.theme === 'light') {
      root.classList.add('light');
      root.classList.remove('dark');
    } else {
      root.classList.add('dark');
      root.classList.remove('light');
    }
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

      // Fetch Disassembly + CFG + Engine A Decompilation
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

      // Pick default function (`main` or `verify_license_key` or first function)
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

  // Function Rename & Undo/Redo
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

  // Keyboard shortcuts
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





  // Filtered Functions & Strings
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

  return (
    <div
      className="font-ui relative flex h-screen w-screen flex-col overflow-hidden bg-[var(--bg-canvas)] text-[var(--text-primary)] select-none"
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


      {/* Hidden File Inputs */}
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

      {/* Drag & Drop Overlay */}
      {isDragOver && (
        <div className="pointer-events-none fixed inset-0 z-50 flex items-center justify-center bg-[#05070B]/85 backdrop-blur-md">
          <div className="flex flex-col items-center gap-3 rounded-xl border-2 border-dashed border-[#00E5FF] bg-[#0B0F17] px-12 py-9 text-center shadow-2xl">
            <Binary className="h-10 w-10 text-[#00E5FF]" />
            <div className="text-base font-semibold text-white">
              Drop Any Binary Executable or Library for Local WASM Analysis
            </div>
            <div className="text-xs text-slate-400">
              ELF32/64 · PE/COFF (.exe, .dll, .sys) · Mach-O · WebAssembly (.wasm) · Raw Firmware
            </div>
          </div>
        </div>
      )}

      {/* Top Menu Bar & Command Header */}
      <header className="z-20 flex h-11 shrink-0 items-center justify-between border-b border-[var(--border-hairline)] bg-[var(--bg-panel)]/95 px-3 backdrop-blur-md">
        <div className="flex items-center gap-3">
          {/* Brand Title */}
          <div className="flex items-center gap-2 pr-2">
            <div className="flex h-6 w-6 items-center justify-center rounded border border-[#00E5FF]/50 bg-[#00E5FF]/10">
              <Cpu className="h-3.5 w-3.5 text-[#00E5FF]" />
            </div>
            <span className="text-xs font-bold tracking-tight text-white">
              Spet&apos;s Easy Decompiler
            </span>
          </div>

          {/* 5 Top Menus: File · Analysis · View · Settings · Help */}
          <nav className="relative flex items-center gap-1 text-xs">
            {/* FILE MENU */}
            <div className="relative">
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  setOpenMenu(openMenu === 'file' ? null : 'file');
                }}
                className="rounded px-2.5 py-1 text-slate-300 hover:bg-white/10 hover:text-white"
              >
                File
              </button>
              {openMenu === 'file' && (
                <div
                  onClick={(e) => e.stopPropagation()}
                  className="absolute left-0 top-full mt-1 w-64 rounded-md border border-white/15 bg-[#0B0F17] py-1.5 shadow-2xl"
                >
                  <button
                    type="button"
                    onClick={() => {
                      setOpenMenu(null);
                      fileInputRef.current?.click();
                    }}
                    className="flex w-full items-center justify-between px-3 py-1.5 text-left text-xs text-slate-200 hover:bg-[#00E5FF]/15 hover:text-[#00E5FF]"
                  >
                    <span>Open Binary File...</span>
                    <span className="font-mono-jetbrains text-[10px] text-slate-500">Ctrl+O</span>
                  </button>
                  <div className="my-1 border-t border-white/10" />
                  <div className="px-3 py-1 text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                    Built-In Test Binaries
                  </div>
                  {SAMPLE_BINARIES.map((smp) => (
                    <button
                      key={smp.id}
                      type="button"
                      onClick={async () => {
                        setOpenMenu(null);
                        const r = await fetch(smp.path);
                        const b = await r.arrayBuffer();
                        await loadBinaryBuffer(new Uint8Array(b), smp.filename);
                      }}
                      className="flex w-full items-center justify-between px-3 py-1.5 text-left text-xs text-slate-300 hover:bg-white/10 hover:text-white"
                    >
                      <span className="truncate">{smp.filename}</span>
                      <span className="ml-2 shrink-0 rounded bg-white/5 px-1.5 py-0.5 font-mono-jetbrains text-[10px] text-[#00E5FF]">
                        {smp.badge}
                      </span>
                    </button>
                  ))}
                  {recentFiles.length > 0 && (
                    <>
                      <div className="my-1 border-t border-white/10" />
                      <div className="flex items-center justify-between px-3 py-1 text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                        <span>Recent Files (IndexedDB)</span>
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
                          className="flex w-full items-center justify-between px-3 py-1 text-left text-xs text-slate-300 hover:bg-white/10"
                        >
                          <span className="truncate">{rf.filename}</span>
                          <span className="font-mono-jetbrains text-[10px] text-slate-500">
                            {(rf.size / 1024).toFixed(1)}K
                          </span>
                        </button>
                      ))}
                    </>
                  )}
                  <div className="my-1 border-t border-white/10" />
                  <button
                    type="button"
                    onClick={() => {
                      setOpenMenu(null);
                      handleSaveProject();
                    }}
                    className="flex w-full items-center justify-between px-3 py-1.5 text-left text-xs text-slate-200 hover:bg-white/10"
                  >
                    <span>Save / Export Project (.spetproj.json)</span>
                    <span className="font-mono-jetbrains text-[10px] text-slate-500">Ctrl+S</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setOpenMenu(null);
                      projectInputRef.current?.click();
                    }}
                    className="flex w-full items-center justify-between px-3 py-1.5 text-left text-xs text-slate-200 hover:bg-white/10"
                  >
                    <span>Load Project Annotations...</span>
                  </button>
                  <div className="my-1 border-t border-white/10" />
                  <button
                    type="button"
                    onClick={() => {
                      setOpenMenu(null);
                      if (analysis) {
                        const md = generateMarkdownReport(analysis, decompA, decompB);
                        downloadLocalBlob(md, `${analysis.metadata.filename}-report.md`, 'text/markdown');
                      }
                    }}
                    className="flex w-full items-center justify-between px-3 py-1.5 text-left text-xs text-[#00E5FF] hover:bg-[#00E5FF]/15"
                  >
                    <span>Export Full Markdown Report (.md)</span>
                  </button>
                </div>
              )}
            </div>

            {/* ANALYSIS MENU */}
            <div className="relative">
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  setOpenMenu(openMenu === 'analysis' ? null : 'analysis');
                }}
                className="rounded px-2.5 py-1 text-slate-300 hover:bg-white/10 hover:text-white"
              >
                Analysis
              </button>
              {openMenu === 'analysis' && (
                <div
                  onClick={(e) => e.stopPropagation()}
                  className="absolute left-0 top-full mt-1 w-64 rounded-md border border-white/15 bg-[#0B0F17] py-1.5 shadow-2xl"
                >
                  <button
                    type="button"
                    onClick={() => {
                      setOpenMenu(null);
                      if (binaryData && analysis) {
                        loadBinaryBuffer(binaryData, analysis.metadata.filename);
                      }
                    }}
                    className="flex w-full items-center justify-between px-3 py-1.5 text-left text-xs text-slate-200 hover:bg-white/10"
                  >
                    <span>Re-Run Full Binary Analysis (aaa)</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setOpenMenu(null);
                      handleAutoNameAllFunctions();
                    }}
                    className="flex w-full items-center justify-between px-3 py-1.5 text-left text-xs text-[#00E5FF] hover:bg-[#00E5FF]/15"
                  >
                    <span>Auto-Name All Functions (IDA sub_*)</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setOpenMenu(null);
                      handleUndoRename();
                    }}
                    className="flex w-full items-center justify-between px-3 py-1.5 text-left text-xs text-slate-200 hover:bg-white/10"
                  >
                    <span>Undo Last Function Rename</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setOpenMenu(null);
                      handleRedoRename();
                    }}
                    className="flex w-full items-center justify-between px-3 py-1.5 text-left text-xs text-slate-200 hover:bg-white/10"
                  >
                    <span>Redo Function Rename</span>
                  </button>

                </div>
              )}
            </div>

            {/* VIEW MENU */}
            <div className="relative">
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  setOpenMenu(openMenu === 'view' ? null : 'view');
                }}
                className="rounded px-2.5 py-1 text-slate-300 hover:bg-white/10 hover:text-white"
              >
                View
              </button>
              {openMenu === 'view' && (
                <div
                  onClick={(e) => e.stopPropagation()}
                  className="absolute left-0 top-full mt-1 w-60 rounded-md border border-white/15 bg-[#0B0F17] py-1.5 shadow-2xl"
                >
                  {(
                    [
                      ['dual-decompiler', 'Dual C-Like Decompiler Split (D)'],
                      ['decompiler-a', 'Engine A: Rizin + jsdec Only'],
                      ['decompiler-b', 'Engine B: Ghidra C++ WASM Only'],
                      ['disassembly', 'Disassembly View (2)'],
                      ['cfg', 'Control Flow Graph Canvas (3)'],
                      ['callgraph', 'Interactive Call Graph'],
                      ['hex', 'Raw Hex & Section Viewer (4)'],
                    ] as Array<[CenterTab, string]>
                  ).map(([tabId, label]) => (
                    <button
                      key={tabId}
                      type="button"
                      onClick={() => {
                        setCenterTab(tabId);
                        setOpenMenu(null);
                      }}
                      className="flex w-full items-center justify-between px-3 py-1.5 text-left text-xs text-slate-200 hover:bg-white/10"
                    >
                      <span>{label}</span>
                      {centerTab === tabId && <Check className="h-3.5 w-3.5 text-[#00E5FF]" />}
                    </button>
                  ))}
                </div>
              )}
            </div>

            {/* SETTINGS MENU */}
            <button
              type="button"
              onClick={() => setShowSettingsModal(true)}
              className="rounded px-2.5 py-1 text-slate-300 hover:bg-white/10 hover:text-white"
            >
              Settings
            </button>

            {/* HELP MENU */}
            <div className="relative">
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  setOpenMenu(openMenu === 'help' ? null : 'help');
                }}
                className="rounded px-2.5 py-1 text-slate-300 hover:bg-white/10 hover:text-white"
              >
                Help
              </button>
              {openMenu === 'help' && (
                <div
                  onClick={(e) => e.stopPropagation()}
                  className="absolute left-0 top-full mt-1 w-60 rounded-md border border-white/15 bg-[#0B0F17] py-1.5 shadow-2xl"
                >
                  <button
                    type="button"
                    onClick={() => {
                      setOpenMenu(null);
                      setShowShortcutsModal(true);
                    }}
                    className="flex w-full items-center px-3 py-1.5 text-left text-xs text-slate-200 hover:bg-white/10"
                  >
                    Keyboard Shortcuts
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setOpenMenu(null);
                      setAboutModalTab('engines');
                    }}
                    className="flex w-full items-center px-3 py-1.5 text-left text-xs text-slate-200 hover:bg-white/10"
                  >
                    Decompiler Engine Architecture
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setOpenMenu(null);
                      setAboutModalTab('security');
                    }}
                    className="flex w-full items-center px-3 py-1.5 text-left text-xs text-emerald-400 hover:bg-white/10"
                  >
                    100% Local-First Privacy Model
                  </button>

                </div>
              )}
            </div>
          </nav>
        </div>

        {/* Right Action Toolbar */}
        <div className="flex items-center gap-2">
          {/* Quick Sample Selector */}
          <div className="hidden items-center gap-1.5 lg:flex">
            <span className="text-[11px] text-slate-400">Sample:</span>
            <select
              value={
                SAMPLE_BINARIES.find((s) => s.filename === analysis?.metadata.filename)?.id || ''
              }
              onChange={async (e) => {
                const found = SAMPLE_BINARIES.find((s) => s.id === e.target.value);
                if (found) {
                  const r = await fetch(found.path);
                  const b = await r.arrayBuffer();
                  await loadBinaryBuffer(new Uint8Array(b), found.filename);
                }
              }}
              className="rounded border border-white/15 bg-[#05070B] px-2 py-1 text-xs text-slate-200 focus:border-[#00E5FF] focus:outline-none"
            >
              <option value="" disabled>
                Choose built-in binary...
              </option>
              {SAMPLE_BINARIES.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.label}
                </option>
              ))}
            </select>
          </div>

          <button
            type="button"
            onClick={() => fileInputRef.current?.click()}
            className="inline-flex items-center gap-1.5 rounded border border-white/15 bg-white/5 px-2.5 py-1 text-xs font-medium text-slate-200 hover:border-[#00E5FF]/50 hover:text-white"
          >
            <FolderOpen className="h-3.5 w-3.5 text-[#00E5FF]" />
            <span>Open Binary</span>
          </button>

          {isAnalyzing || isDecompilingA || isDecompilingB ? (
            <button
              type="button"
              onClick={handleCancelAnalysis}
              className="inline-flex items-center gap-1 rounded border border-rose-500/40 bg-rose-500/15 px-2.5 py-1 text-xs font-medium text-rose-300 hover:bg-rose-500/25"
            >
              <Square className="h-3 w-3 fill-current" /> Cancel Worker
            </button>
          ) : null}

          <PwaInstallButton />

          <button
            type="button"
            onClick={() => setShowSettingsModal(true)}
            className="rounded border border-white/10 bg-white/5 p-1.5 text-slate-300 hover:border-white/25 hover:text-white"
            title="Settings"
          >
            <Sliders className="h-3.5 w-3.5" />
          </button>
        </div>
      </header>

      {/* Main 3-Column Docked Workbench */}
      <div className="z-10 flex min-h-0 flex-1 overflow-hidden">
        {/* LEFT PANE: Function Navigator & Auto-Naming Controls */}
        <aside className="flex w-72 shrink-0 flex-col border-r border-[var(--border-hairline)] bg-[var(--bg-panel)]/90">
          <div className="flex items-center justify-between border-b border-white/10 px-3 py-2">
            <div className="flex items-center gap-1.5">
              <Layers className="h-3.5 w-3.5 text-[#00E5FF]" />
              <span className="text-xs font-semibold uppercase tracking-wider text-slate-200">
                Functions ({filteredFunctions.length})
              </span>
            </div>
            <div className="flex items-center gap-1">
              <button
                type="button"
                onClick={handleAutoNameAllFunctions}
                className="rounded border border-[#00E5FF]/30 bg-[#00E5FF]/10 px-1.5 py-0.5 text-[10px] font-medium text-[#00E5FF] hover:bg-[#00E5FF]/20"
                title="Generate IDA-style sub_* names for unnamed functions"
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
                className="rounded border border-white/10 bg-white/5 p-1 text-slate-400 hover:text-white"
                title="Export Function List (JSON)"
              >
                <Download className="h-3 w-3" />
              </button>
            </div>
          </div>

          {/* Search & Category Filter */}
          <div className="space-y-1.5 border-b border-white/10 p-2">
            <div className="relative">
              <Search className="pointer-events-none absolute left-2.5 top-2 h-3.5 w-3.5 text-slate-500" />
              <input
                ref={searchInputRef}
                type="text"
                value={fnSearch}
                onChange={(e) => setFnSearch(e.target.value)}
                placeholder="Filter functions or 0x addr (Ctrl+K)"
                className="w-full rounded border border-white/10 bg-[#05070B] py-1 pl-8 pr-2 text-xs text-slate-200 placeholder:text-slate-500 focus:border-[#00E5FF] focus:outline-none"
              />
            </div>
            <div className="flex items-center gap-1">
              <ListFilter className="h-3 w-3 shrink-0 text-slate-500" />
              <select
                value={fnCategoryFilter}
                onChange={(e) => setFnCategoryFilter(e.target.value as any)}
                className="w-full rounded border border-white/10 bg-[#05070B] px-1.5 py-1 text-[11px] text-slate-300 focus:border-[#00E5FF] focus:outline-none"
              >
                <option value="all">All Categories ({analysis?.functions.length || 0})</option>
                <option value="favorites">★ Bookmarked / Favorites ({favorites.size})</option>
                <option value="entry">Entry Points (_start / entry0)</option>
                <option value="exported">Exported Functions</option>
                <option value="imported">Imported Stubs (imp_*)</option>
                <option value="thunk">Thunk Functions (j_*)</option>
                <option value="standard">Standard Internal (sub_*)</option>
                <option value="unreferenced">Unreferenced Functions</option>
              </select>
            </div>
          </div>

          {/* Function List */}
          <div className="flex-1 divide-y divide-white/[0.04] overflow-y-auto">
            {filteredFunctions.map((fn) => {
              const isSelected = fn.address === selectedFnAddr;
              const activeName = customNames[fn.address] || fn.name;
              const isFav = favorites.has(fn.address);
              const hasComment = Boolean(fnComments[fn.address]);

              return (
                <div
                  key={fn.address}
                  onClick={() => inspectFunction(fn.address)}
                  className={`group flex cursor-pointer items-center justify-between px-2.5 py-2 transition-colors ${
                    isSelected
                      ? 'border-l-2 border-l-[#00E5FF] bg-[#00E5FF]/12'
                      : 'hover:bg-white/[0.04]'
                  }`}
                >
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-1.5">
                      <span
                        className={`truncate text-xs font-medium ${fontClass} ${
                          isSelected ? 'text-[#00E5FF]' : 'text-slate-200'
                        }`}
                      >
                        {activeName}
                      </span>
                      {customNames[fn.address] && (
                        <span className="rounded bg-[#8B5CF6]/20 px-1 py-0.2 text-[9px] font-semibold text-[#C4B5FD]">
                          renamed
                        </span>
                      )}
                      {hasComment && (
                        <MessageSquare className="h-2.5 w-2.5 shrink-0 text-amber-400" />
                      )}
                    </div>
                    <div className={`mt-0.5 flex items-center gap-2 text-[10.5px] text-slate-400 ${fontClass}`}>
                      <span className="text-slate-500">{fn.address}</span>
                      <span>·</span>
                      <span>{fn.size}B</span>
                      <span>·</span>
                      <span>{fn.basicBlocksCount} BB</span>
                      <span className="rounded bg-white/5 px-1 text-[9.5px] text-slate-400">
                        {fn.category}
                      </span>
                    </div>
                  </div>

                  {/* Quick Hover Actions: Favorite & Rename */}
                  <div className="ml-1 flex items-center gap-1 opacity-75 group-hover:opacity-100">
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        setRenamingFn({ address: fn.address, currentName: activeName });
                      }}
                      className="rounded p-1 text-slate-400 hover:bg-white/10 hover:text-[#00E5FF]"
                      title="Rename Function (N)"
                    >
                      <Edit3 className="h-3 w-3" />
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
                      className={`rounded p-1 ${
                        isFav ? 'text-amber-400' : 'text-slate-500 hover:text-slate-300'
                      }`}
                      title="Bookmark Function"
                    >
                      <Star className={`h-3 w-3 ${isFav ? 'fill-current' : ''}`} />
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </aside>

        {/* CENTER WORKSPACE: Dual C-Like Decompiler / Disassembly / CFG / Call Graph / Hex */}
        <main className="flex min-w-0 flex-1 flex-col overflow-hidden bg-[var(--bg-canvas)]">
          {/* Center Mode Tabs + Active Function Header Bar */}
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--border-hairline)] bg-[var(--bg-panel)] px-3 py-1.5">
            <div className="flex items-center gap-1">
              {(
                [
                  ['dual-decompiler', 'Dual C Decompilers', Sparkles],
                  ['decompiler-a', 'Rizin + jsdec', Terminal],
                  ['decompiler-b', 'Ghidra C++ WASM', Cpu],
                  ['disassembly', 'Disassembly', FileCode2],
                  ['cfg', 'CFG Graph', GitBranch],
                  ['callgraph', 'Call Graph', Network],
                  ['hex', 'Hex View', Binary],
                ] as Array<[CenterTab, string, any]>
              ).map(([id, label, Icon]) => {
                const active = centerTab === id;
                return (
                  <button
                    key={id}
                    type="button"
                    onClick={() => setCenterTab(id)}
                    className={`inline-flex items-center gap-1.5 rounded px-2.5 py-1 text-xs font-medium transition-colors ${
                      active
                        ? 'bg-[#00E5FF]/15 text-[#00E5FF] ring-1 ring-[#00E5FF]/40'
                        : 'text-slate-400 hover:bg-white/5 hover:text-slate-200'
                    }`}
                  >
                    <Icon className="h-3.5 w-3.5" />
                    <span>{label}</span>
                  </button>
                );
              })}
            </div>

            {/* Active Function Action Bar */}
            {activeFnInfo && (
              <div className="flex items-center gap-1.5 text-xs">
                <span className={`text-slate-400 ${fontClass}`}>
                  {customNames[activeFnInfo.address] || activeFnInfo.name} @ {activeFnInfo.address}
                </span>
                <button
                  type="button"
                  onClick={() =>
                    setRenamingFn({
                      address: activeFnInfo.address,
                      currentName: customNames[activeFnInfo.address] || activeFnInfo.name,
                    })
                  }
                  className="inline-flex items-center gap-1 rounded border border-white/10 bg-white/5 px-2 py-0.5 text-[11px] text-slate-300 hover:border-[#00E5FF]/40 hover:text-[#00E5FF]"
                >
                  <Edit3 className="h-3 w-3" /> Rename (N)
                </button>
                <button
                  type="button"
                  onClick={() =>
                    setCommentingFn({
                      address: activeFnInfo.address,
                      currentComment: fnComments[activeFnInfo.address] || '',
                    })
                  }
                  className="inline-flex items-center gap-1 rounded border border-white/10 bg-white/5 px-2 py-0.5 text-[11px] text-slate-300 hover:border-amber-400/40 hover:text-amber-300"
                >
                  <MessageSquare className="h-3 w-3" /> Comment (;)
                </button>
              </div>
            )}
          </div>

          {/* Inline Rename / Comment Bar when triggered */}
          {renamingFn && (
            <form
              onSubmit={(e) => {
                e.preventDefault();
                applyRename(renamingFn.address, renamingFn.currentName);
              }}
              className="flex items-center justify-between gap-2 border-b border-[#00E5FF]/30 bg-[#00E5FF]/10 px-4 py-2 text-xs"
            >
              <div className="flex items-center gap-2">
                <Edit3 className="h-3.5 w-3.5 text-[#00E5FF]" />
                <span className="font-medium text-white">
                  Rename Function @ {renamingFn.address}:
                </span>
                <input
                  type="text"
                  autoFocus
                  value={renamingFn.currentName}
                  onChange={(e) =>
                    setRenamingFn({ ...renamingFn, currentName: e.target.value })
                  }
                  className={`w-64 rounded border border-[#00E5FF]/50 bg-[#05070B] px-2.5 py-1 text-xs text-white focus:outline-none ${fontClass}`}
                />
              </div>
              <div className="flex items-center gap-1.5">
                <button
                  type="submit"
                  className="rounded bg-[#00E5FF] px-3 py-1 font-semibold text-slate-950 hover:bg-[#00E5FF]/90"
                >
                  Apply & Sync Engines
                </button>
                <button
                  type="button"
                  onClick={() => setRenamingFn(null)}
                  className="rounded border border-white/15 px-2.5 py-1 text-slate-300 hover:text-white"
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
              className="flex items-center justify-between gap-2 border-b border-amber-400/30 bg-amber-500/10 px-4 py-2 text-xs"
            >
              <div className="flex flex-1 items-center gap-2">
                <MessageSquare className="h-3.5 w-3.5 text-amber-400" />
                <span className="font-medium text-white">
                  Annotation @ {commentingFn.address}:
                </span>
                <input
                  type="text"
                  autoFocus
                  value={commentingFn.currentComment}
                  onChange={(e) =>
                    setCommentingFn({ ...commentingFn, currentComment: e.target.value })
                  }
                  placeholder="Enter analyst note or reverse engineering hypothesis..."
                  className="flex-1 rounded border border-amber-400/50 bg-[#05070B] px-2.5 py-1 text-xs text-white focus:outline-none"
                />
              </div>
              <div className="flex items-center gap-1.5">
                <button
                  type="submit"
                  className="rounded bg-amber-400 px-3 py-1 font-semibold text-slate-950 hover:bg-amber-300"
                >
                  Save Note
                </button>
                <button
                  type="button"
                  onClick={() => setCommentingFn(null)}
                  className="rounded border border-white/15 px-2.5 py-1 text-slate-300 hover:text-white"
                >
                  Cancel
                </button>
              </div>
            </form>
          )}

          {/* Center Content Area */}
          <div className="min-h-0 flex-1 overflow-hidden">
            {centerTab === 'dual-decompiler' && (
              <div className="grid h-full grid-cols-1 divide-y divide-[var(--border-hairline)] lg:grid-cols-2 lg:divide-x lg:divide-y-0">
                {/* Engine A Pane: Rizin + jsdec */}
                <div className="flex h-full min-h-0 flex-col overflow-hidden">
                  <div className="flex items-center justify-between border-b border-white/10 bg-[#0B0F17] px-3 py-1.5 text-xs">
                    <div className="flex items-center gap-2">
                      <span className="h-2 w-2 rounded-full bg-[#00E5FF]" />
                      <span className="font-semibold text-white">
                        Decompiler A: Rizin v0.9.1 + jsdec v0.9.0
                      </span>
                      {decompA && (
                        <span className="font-mono-jetbrains text-[11px] text-slate-400">
                          ({decompA.durationMs} ms)
                        </span>
                      )}
                    </div>
                    <div className="flex items-center gap-1">
                      <button
                        type="button"
                        onClick={() => copyText('decA', formattedCodeA)}
                        className="inline-flex items-center gap-1 rounded border border-white/10 bg-white/5 px-2 py-0.5 text-[11px] text-slate-300 hover:text-white"
                      >
                        {copiedId === 'decA' ? (
                          <Check className="h-3 w-3 text-emerald-400" />
                        ) : (
                          <Copy className="h-3 w-3" />
                        )}
                        Copy
                      </button>
                      <button
                        type="button"
                        onClick={() =>
                          downloadLocalBlob(
                            formattedCodeA,
                            `${activeFnInfo?.name || 'func'}-rizin-jsdec.c`,
                            'text/x-c'
                          )
                        }
                        className="inline-flex items-center gap-1 rounded border border-white/10 bg-white/5 px-2 py-0.5 text-[11px] text-slate-300 hover:text-white"
                      >
                        <Download className="h-3 w-3" /> .c
                      </button>
                    </div>
                  </div>
                  <pre
                    className={`flex-1 select-text overflow-auto p-3.5 text-xs leading-relaxed text-slate-200 ${fontClass}`}
                  >
                    {isDecompilingA ? '// Running Rizin + jsdec control-flow structuring...' : formattedCodeA}
                  </pre>
                </div>

                {/* Engine B Pane: Ghidra C++ Sleigh Decompiler WASM */}
                <div className="flex h-full min-h-0 flex-col overflow-hidden">
                  <div className="flex items-center justify-between border-b border-white/10 bg-[#0B0F17] px-3 py-1.5 text-xs">
                    <div className="flex items-center gap-2">
                      <span className="h-2 w-2 rounded-full bg-[#8B5CF6]" />
                      <span className="font-semibold text-white">
                        Decompiler B: Ghidra C++ Sleigh WASM (v11.2)
                      </span>
                      {decompB && (
                        <span className="font-mono-jetbrains text-[11px] text-slate-400">
                          ({decompB.durationMs} ms)
                        </span>
                      )}
                    </div>
                    <div className="flex items-center gap-1">
                      <button
                        type="button"
                        onClick={() => copyText('decB', formattedCodeB)}
                        className="inline-flex items-center gap-1 rounded border border-white/10 bg-white/5 px-2 py-0.5 text-[11px] text-slate-300 hover:text-white"
                      >
                        {copiedId === 'decB' ? (
                          <Check className="h-3 w-3 text-emerald-400" />
                        ) : (
                          <Copy className="h-3 w-3" />
                        )}
                        Copy
                      </button>
                      <button
                        type="button"
                        onClick={() =>
                          downloadLocalBlob(
                            formattedCodeB,
                            `${activeFnInfo?.name || 'func'}-ghidra.c`,
                            'text/x-c'
                          )
                        }
                        className="inline-flex items-center gap-1 rounded border border-white/10 bg-white/5 px-2 py-0.5 text-[11px] text-slate-300 hover:text-white"
                      >
                        <Download className="h-3 w-3" /> .c
                      </button>
                    </div>
                  </div>
                  <pre
                    className={`flex-1 select-text overflow-auto p-3.5 text-xs leading-relaxed text-slate-200 ${fontClass}`}
                  >
                    {isDecompilingB
                      ? '// Lifting P-Code & running Ghidra SSA decompiler...'
                      : formattedCodeB}
                  </pre>
                </div>
              </div>
            )}

            {centerTab === 'decompiler-a' && (
              <pre
                className={`h-full select-text overflow-auto p-4 text-xs leading-relaxed text-slate-200 ${fontClass}`}
              >
                {formattedCodeA}
              </pre>
            )}

            {centerTab === 'decompiler-b' && (
              <pre
                className={`h-full select-text overflow-auto p-4 text-xs leading-relaxed text-slate-200 ${fontClass}`}
              >
                {formattedCodeB}
              </pre>
            )}

            {centerTab === 'disassembly' && (
              <div className="flex h-full flex-col overflow-hidden">
                <div className="flex items-center justify-between border-b border-white/10 bg-[#0B0F17] px-3 py-1.5 text-xs">
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
                    className="inline-flex items-center gap-1 rounded border border-white/10 bg-white/5 px-2 py-0.5 text-[11px] text-slate-300 hover:text-white"
                  >
                    <Download className="h-3 w-3" /> Export .asm
                  </button>
                </div>
                <div className={`flex-1 select-text overflow-auto p-3 text-xs leading-6 ${fontClass}`}>
                  {disasmLines.map((line, idx) => (
                    <div
                      key={`${line.address}-${idx}`}
                      className="flex items-baseline gap-4 rounded px-2 py-0.5 hover:bg-white/[0.04]"
                    >
                      {settings.showAddresses && (
                        <span className="w-24 shrink-0 text-[#00E5FF]">{line.address}</span>
                      )}
                      {settings.showBytes && (
                        <span className="w-36 shrink-0 text-slate-500">{line.bytes}</span>
                      )}
                      <span className="min-w-[240px] text-slate-100">
                        <strong className="text-[#C4B5FD]">{line.mnemonic}</strong>{' '}
                        <span>{line.operands}</span>
                      </span>
                      {settings.showComments && line.comment && (
                        <span className="text-emerald-400/80">; {line.comment}</span>
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
          </div>

          {/* BOTTOM DOCK: Worker Execution Log, Interactive Rizin Shell, Rename History & Warnings */}
          <div className="flex h-44 shrink-0 flex-col border-t border-[var(--border-hairline)] bg-[var(--bg-panel)]">
            <div className="flex items-center justify-between border-b border-white/10 px-3 py-1 text-xs">
              <div className="flex items-center gap-1">
                {(
                  [
                    ['logs', `Worker Execution Log (${logs.length})`],
                    ['rizin-shell', 'Interactive Rizin WASM Shell (rzpipe)'],
                    ['rename-history', `Symbol Rename History (${renameHistory.length})`],
                    [
                      'warnings',
                      `Engine Diagnostics (${
                        (decompA?.warnings.length || 0) + (decompB?.warnings.length || 0)
                      })`,
                    ],
                  ] as Array<[BottomDockTab, string]>
                ).map(([tId, label]) => (
                  <button
                    key={tId}
                    type="button"
                    onClick={() => setBottomTab(tId)}
                    className={`rounded px-2.5 py-0.5 text-[11px] font-medium ${
                      bottomTab === tId
                        ? 'bg-white/10 text-[#00E5FF]'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {label}
                  </button>
                ))}
              </div>
              <span className="font-mono-jetbrains text-[11px] text-slate-400">
                {statusMessage}
              </span>
            </div>

            <div className="flex-1 overflow-y-auto p-2.5 text-xs">
              {bottomTab === 'logs' && (
                <div className={`space-y-1 ${fontClass}`}>
                  {logs.map((l) => (
                    <div key={l.id} className="flex items-baseline gap-2 text-[11px]">
                      <span className="text-slate-500">
                        [{new Date(l.timestamp).toLocaleTimeString()}]
                      </span>
                      <span className="font-semibold text-[#00E5FF]">[{l.source}]</span>
                      <span
                        className={
                          l.level === 'error'
                            ? 'text-rose-400'
                            : l.level === 'warn'
                              ? 'text-amber-300'
                              : l.level === 'success'
                                ? 'text-emerald-400'
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
                <div className="flex h-full flex-col gap-2">
                  <form
                    onSubmit={async (e) => {
                      e.preventDefault();
                      if (!engineARef.current || !rizinCmdInput.trim()) return;
                      const out = await engineARef.current.executeRawCommand(rizinCmdInput.trim());
                      setRizinCmdOutput(out || '(empty output)');
                    }}
                    className="flex items-center gap-2"
                  >
                    <span className="font-mono-jetbrains text-xs font-bold text-[#00E5FF]">
                      [0x00401000]&gt;
                    </span>
                    <input
                      type="text"
                      value={rizinCmdInput}
                      onChange={(e) => setRizinCmdInput(e.target.value)}
                      placeholder="Enter any Rizin command (e.g. afl, iI, iz, pdf @ main, agf)"
                      className={`flex-1 rounded border border-white/15 bg-[#05070B] px-2.5 py-1 text-xs text-white focus:border-[#00E5FF] focus:outline-none ${fontClass}`}
                    />
                    <button
                      type="submit"
                      className="rounded bg-[#00E5FF]/20 px-3 py-1 font-medium text-[#00E5FF] hover:bg-[#00E5FF]/30"
                    >
                      Execute
                    </button>
                  </form>
                  <pre
                    className={`flex-1 select-text overflow-auto rounded border border-white/5 bg-[#05070B] p-2 text-[11px] text-slate-300 ${fontClass}`}
                  >
                    {rizinCmdOutput || 'Run any native Rizin command directly inside the WASM worker.'}
                  </pre>
                </div>
              )}

              {bottomTab === 'rename-history' && (
                <div className="space-y-1.5">
                  {renameHistory.length === 0 ? (
                    <div className="text-slate-500">
                      No custom function renames recorded yet. Select any function and press N to rename.
                    </div>
                  ) : (
                    renameHistory.map((item, idx) => (
                      <div
                        key={`${item.address}-${idx}`}
                        className={`flex items-center justify-between rounded bg-white/[0.03] px-2.5 py-1 text-[11px] ${fontClass}`}
                      >
                        <span>
                          <strong className="text-[#00E5FF]">{item.address}</strong>:{' '}
                          <span className="text-slate-400">{item.previousName}</span> →{' '}
                          <strong className="text-emerald-400">{item.newName}</strong>
                        </span>
                        <span className="text-slate-500">
                          {new Date(item.timestamp).toLocaleTimeString()}
                        </span>
                      </div>
                    ))
                  )}
                </div>
              )}

              {bottomTab === 'warnings' && (
                <div className={`space-y-1 text-[11px] ${fontClass}`}>
                  {[...(decompA?.warnings || []), ...(decompB?.warnings || [])].length === 0 ? (
                    <div className="text-slate-500">No decompiler warnings on current function.</div>
                  ) : (
                    [...(decompA?.warnings || []), ...(decompB?.warnings || [])].map((w, i) => (
                      <div key={i} className="flex items-center gap-2 text-amber-300">
                        <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
                        <span>{w}</span>
                      </div>
                    ))
                  )}
                </div>
              )}
            </div>
          </div>
        </main>

        {/* RIGHT INSPECTOR PANE: Binary Metadata, Strings, Imports, Exports, Sections, Xrefs */}
        <aside className="flex w-80 shrink-0 flex-col border-l border-[var(--border-hairline)] bg-[var(--bg-panel)]/90">
          {/* Inspector Mode Tabs */}
          <div className="flex flex-wrap border-b border-white/10 bg-[#05070B]/60 p-1 text-[11px]">
            {(
              [
                ['metadata', 'Binary Info'],
                ['strings', `Strings (${analysis?.strings.length || 0})`],
                ['imports', `Imports (${analysis?.imports.length || 0})`],
                ['exports', `Exports (${analysis?.exports.length || 0})`],
                ['sections', `Sections (${analysis?.sections.length || 0})`],
                ['xrefs', 'Function Details'],
              ] as Array<[RightInspectorTab, string]>
            ).map(([tId, label]) => (
              <button
                key={tId}
                type="button"
                onClick={() => setRightTab(tId)}
                className={`rounded px-2 py-1 font-medium transition-colors ${
                  rightTab === tId
                    ? 'bg-[#00E5FF]/15 text-[#00E5FF]'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {label}
              </button>
            ))}
          </div>

          {/* Inspector Body */}
          <div className="flex-1 overflow-y-auto p-3 text-xs">
            {rightTab === 'metadata' && analysis && (
              <div className="space-y-3">
                <div className="rounded border border-emerald-500/25 bg-emerald-500/5 p-2.5">
                  <div className="flex items-center gap-1.5 font-semibold text-emerald-400">
                    <Lock className="h-3.5 w-3.5" />
                    <span>100% Local Sandbox Verified</span>
                  </div>
                  <p className="mt-1 text-[11px] leading-relaxed text-slate-300">
                    Zero network uploads. Decompiled entirely in browser WebAssembly Workers.
                  </p>
                </div>

                <div className="space-y-2 rounded border border-white/10 bg-[#05070B]/70 p-3">
                  <div className="text-[11px] font-semibold uppercase tracking-wider text-[#00E5FF]">
                    Executable Overview
                  </div>
                  {(
                    [
                      ['Filename', analysis.metadata.filename],
                      ['File Size', `${analysis.metadata.size.toLocaleString()} bytes`],
                      ['Format', analysis.metadata.format],
                      [
                        'Architecture',
                        `${analysis.metadata.architecture} (${analysis.metadata.bits}-bit, ${analysis.metadata.endianness})`,
                      ],
                      ['Machine', analysis.metadata.machine],
                      ['OS / ABI', `${analysis.metadata.os} · ${analysis.metadata.abi}`],
                      ['Entry Point', analysis.metadata.entryPoint],
                      ['Base Address', analysis.metadata.baseAddress],
                      ['Compiler', analysis.metadata.compiler],
                      [
                        'Symbols',
                        analysis.metadata.hasSymbols ? 'Present (Not Stripped)' : 'Stripped Binary',
                      ],
                      ['Shannon Entropy', `${analysis.metadata.entropy.toFixed(2)} bits/byte`],
                    ] as Array<[string, string]>
                  ).map(([k, v]) => (
                    <div key={k} className="flex items-baseline justify-between gap-2 border-b border-white/[0.04] pb-1">
                      <span className="text-slate-400">{k}</span>
                      <span className={`truncate text-right font-medium text-slate-200 ${fontClass}`}>
                        {v}
                      </span>
                    </div>
                  ))}
                  <div className="pt-1">
                    <div className="text-[10px] text-slate-400">SHA-256 Digest</div>
                    <div
                      className={`mt-0.5 break-all rounded bg-white/[0.03] p-1.5 text-[10px] text-slate-300 select-all ${fontClass}`}
                    >
                      {analysis.metadata.sha256}
                    </div>
                  </div>
                </div>
              </div>
            )}

            {rightTab === 'strings' && (
              <div className="flex h-full flex-col gap-2">
                <div className="space-y-1.5">
                  <input
                    type="text"
                    value={stringSearch}
                    onChange={(e) => setStringSearch(e.target.value)}
                    placeholder="Search ASCII / UTF-16 strings..."
                    className="w-full rounded border border-white/10 bg-[#05070B] px-2.5 py-1 text-xs text-slate-200 focus:border-[#00E5FF] focus:outline-none"
                  />
                  <div className="flex items-center justify-between gap-1">
                    <select
                      value={stringCategoryFilter}
                      onChange={(e) => setStringCategoryFilter(e.target.value as any)}
                      className="flex-1 rounded border border-white/10 bg-[#05070B] px-2 py-1 text-[11px] text-slate-300"
                    >
                      <option value="all">All String Categories</option>
                      <option value="URL">URLs & Endpoints</option>
                      <option value="Email">Email Addresses</option>
                      <option value="FilePath">File Paths & Configs</option>
                      <option value="ShellCommand">Shell Commands</option>
                      <option value="CryptoIndicator">Crypto Indicators</option>
                      <option value="ErrorMessage">Error / Status Messages</option>
                      <option value="DLL/Library">DLLs & Shared Libraries</option>
                      <option value="API/Symbol">API Symbols</option>
                      <option value="HeuristicTokenOrKey">Heuristic Token/Key Pattern</option>
                    </select>
                    <button
                      type="button"
                      onClick={() => {
                        if (analysis) {
                          const csv = formatStringsExport(analysis.strings, 'csv');
                          downloadLocalBlob(csv, `${analysis.metadata.filename}-strings.csv`, 'text/csv');
                        }
                      }}
                      className="rounded border border-white/10 bg-white/5 px-2 py-1 text-[11px] text-slate-300 hover:text-white"
                      title="Export Strings CSV"
                    >
                      CSV
                    </button>
                  </div>
                </div>

                <div className="flex-1 divide-y divide-white/[0.05] overflow-y-auto">
                  {filteredStrings.map((s, idx) => (
                    <div key={`${s.address}-${idx}`} className="py-2">
                      <div className="flex items-center justify-between text-[10px] text-slate-400">
                        <span className={`text-[#00E5FF] ${fontClass}`}>{s.address}</span>
                        <span>
                          {s.encoding} · {s.section}
                        </span>
                      </div>
                      <div
                        className={`mt-0.5 break-all text-xs text-slate-200 select-all ${fontClass}`}
                      >
                        {s.value}
                      </div>
                      <div className="mt-1 flex flex-wrap gap-1">
                        {s.categories.map((cat) => (
                          <span
                            key={cat}
                            className={`rounded px-1.5 py-0.2 text-[9.5px] font-medium ${
                              cat === 'HeuristicTokenOrKey'
                                ? 'bg-amber-500/20 text-amber-300'
                                : cat === 'URL' || cat === 'ShellCommand'
                                  ? 'bg-[#00E5FF]/15 text-[#00E5FF]'
                                  : 'bg-white/5 text-slate-400'
                            }`}
                          >
                            {cat}
                          </span>
                        ))}
                      </div>
                      {s.heuristicNote && (
                        <div className="mt-1 text-[10px] italic text-amber-300/90">
                          {s.heuristicNote}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {rightTab === 'imports' && analysis && (
              <div className="divide-y divide-white/[0.05]">
                {analysis.imports.length === 0 ? (
                  <div className="py-4 text-slate-500">
                    Static binary — no dynamic imports indexed.
                  </div>
                ) : (
                  analysis.imports.map((imp, idx) => (
                    <div key={`${imp.name}-${idx}`} className="py-2">
                      <div className={`font-medium text-[#00E5FF] ${fontClass}`}>{imp.name}</div>
                      <div className="mt-0.5 flex items-center justify-between text-[11px] text-slate-400">
                        <span>{imp.library}</span>
                        <span className={fontClass}>{imp.address}</span>
                      </div>
                    </div>
                  ))
                )}
              </div>
            )}

            {rightTab === 'exports' && analysis && (
              <div className="divide-y divide-white/[0.05]">
                {analysis.exports.length === 0 ? (
                  <div className="py-4 text-slate-500">No exported symbol table entries.</div>
                ) : (
                  analysis.exports.map((exp, idx) => (
                    <div
                      key={`${exp.name}-${idx}`}
                      onClick={() => inspectFunction(exp.address)}
                      className="cursor-pointer py-2 hover:bg-white/[0.03]"
                    >
                      <div className={`font-medium text-emerald-400 ${fontClass}`}>{exp.name}</div>
                      <div className="mt-0.5 flex items-center justify-between text-[11px] text-slate-400">
                        <span className={fontClass}>{exp.address}</span>
                        <span>{exp.size} bytes</span>
                      </div>
                    </div>
                  ))
                )}
              </div>
            )}

            {rightTab === 'sections' && analysis && (
              <div className="space-y-2">
                {analysis.sections.map((sec) => (
                  <div
                    key={sec.name}
                    className="rounded border border-white/10 bg-[#05070B]/70 p-2.5"
                  >
                    <div className="flex items-center justify-between">
                      <span className={`font-semibold text-[#00E5FF] ${fontClass}`}>
                        {sec.name}
                      </span>
                      <span className={`rounded bg-white/5 px-1.5 py-0.5 text-[10px] ${fontClass}`}>
                        {sec.permissions}
                      </span>
                    </div>
                    <div className={`mt-1 grid grid-cols-2 gap-1 text-[11px] text-slate-400 ${fontClass}`}>
                      <span>VAddr: {sec.virtualAddress}</span>
                      <span>Offset: {sec.fileOffset}</span>
                      <span>Size: {sec.size} B</span>
                      <span>Entropy: {sec.entropy.toFixed(2)}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {rightTab === 'xrefs' && activeFnInfo && (
              <div className="space-y-3">
                <div className="rounded border border-white/10 bg-[#05070B]/70 p-3">
                  <div className="text-[11px] font-semibold uppercase tracking-wider text-[#00E5FF]">
                    Active Function Intelligence
                  </div>
                  <div className={`mt-2 space-y-1.5 text-[11px] ${fontClass}`}>
                    <div>
                      <span className="text-slate-400">Active Name: </span>
                      <strong className="text-white">
                        {customNames[activeFnInfo.address] || activeFnInfo.name}
                      </strong>
                    </div>
                    <div>
                      <span className="text-slate-400">Original Symbol: </span>
                      <span className="text-slate-300">{activeFnInfo.originalName}</span>
                    </div>
                    <div>
                      <span className="text-slate-400">IDA Auto-Name: </span>
                      <span className="text-[#00E5FF]">{activeFnInfo.autoName}</span>
                    </div>
                    <div>
                      <span className="text-slate-400">Signature: </span>
                      <span className="text-emerald-400">{activeFnInfo.signature}</span>
                    </div>
                    <div>
                      <span className="text-slate-400">Calling Conv: </span>
                      <span className="text-slate-300">{activeFnInfo.callingConvention}</span>
                    </div>
                    <div>
                      <span className="text-slate-400">Callers (Xrefs In): </span>
                      <span>{activeFnInfo.callers.join(', ') || 'None'}</span>
                    </div>
                    <div>
                      <span className="text-slate-400">Callees (Xrefs Out): </span>
                      <span>{activeFnInfo.callees.join(', ') || 'None'}</span>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </aside>
      </div>

      {/* Modals */}
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
