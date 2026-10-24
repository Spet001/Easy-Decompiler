import { calculateEntropy, computeSha256Hex, inspectBinaryHeaders } from '../analysis/metadata';
import { classifyFunction, generateIdaStyleFunctionName } from '../analysis/function-naming';
import { extractBinaryStrings } from '../analysis/string-analysis';
import type {
  AnalysisResult,
  BinaryMetadata,
  CallGraphData,
  CallGraphEdge,
  CallGraphNode,
  CfgBlock,
  CfgData,
  CfgEdge,
  DecompilationResult,
  DisassemblyLine,
  ExportInfo,
  FunctionInfo,
  ImportInfo,
  RelocationInfo,
  SectionInfo,
  StringInfo,
  SymbolInfo,
} from '../types';

declare const self: DedicatedWorkerGlobalScope & {
  Module?: any;
  Global?: () => Record<string, any>;
  Limits?: Record<string, bigint>;
  rizin?: {
    command: (cmd: string) => string;
    graph: () => any;
  };
};

let rizinModule: any = null;
let sessionId = 0;
let createSessionFn: (() => number) | null = null;
let closeSessionFn: ((sid: number) => void) | null = null;
let openFileFn: ((sid: number, path: string) => number) | null = null;
let cmdFn: ((sid: number, cmd: string) => string) | null = null;

let currentBinaryData: Uint8Array | null = null;
let currentFilename = '';
let currentMetadata: BinaryMetadata | null = null;
let currentAnalysis: AnalysisResult | null = null;

let jsdecLoaded = false;
let libdecMod: any = null;
let PrinterMod: any = null;
let WarningMod: any = null;
let LongMod: any = null;
let JSONexMod: any = null;
let rzutilMod: any = null;

const sharedGlobalState: Record<string, any> = {};

function postProgress(message: string, level: 'info' | 'warn' | 'error' | 'success' = 'info') {
  self.postMessage({ type: 'log', source: 'Engine A (Rizin+jsdec)', level, message });
}

function runRizinCmd(command: string): string {
  if (!cmdFn || !sessionId) return '';
  try {
    return cmdFn(sessionId, command) || '';
  } catch (err: any) {
    postProgress(`Rizin command error (${command}): ${err?.message || String(err)}`, 'warn');
    return '';
  }
}

function parseJsonSafe<T>(raw: string, fallback: T): T {
  if (!raw || !raw.trim()) return fallback;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

async function fetchArtifact(
  filename: string,
  cdnFallback?: string
): Promise<{ text: string; buffer: ArrayBuffer }> {
  const cleanRel = filename.replace(/^\/+/, '');
  const candidates: string[] = [];

  try {
    if (typeof self !== 'undefined' && self.location && self.location.href) {
      candidates.push(new URL(`../wasm/${cleanRel}`, self.location.href).href);
      candidates.push(new URL(`wasm/${cleanRel}`, self.location.href).href);
      candidates.push(new URL(`./wasm/${cleanRel}`, self.location.href).href);
    }
  } catch {}

  candidates.push(
    `./wasm/${cleanRel}`,
    `wasm/${cleanRel}`,
    `../wasm/${cleanRel}`,
    `/tools/easy-decompiler/wasm/${cleanRel}`,
    `/wasm/${cleanRel}`
  );
  if (cdnFallback) candidates.push(cdnFallback);

  for (const url of candidates) {
    try {
      const resp = await fetch(url);
      if (resp.ok) {
        const ct = resp.headers.get('content-type') || '';
        if (ct.includes('text/html')) continue;
        const buffer = await resp.arrayBuffer();
        if (cleanRel.endsWith('.wasm')) {
          const header = new Uint8Array(buffer, 0, Math.min(4, buffer.byteLength));
          if (header.length < 4 || header[0] !== 0x00 || header[1] !== 0x61 || header[2] !== 0x73 || header[3] !== 0x6d) {
            continue;
          }
        }
        const text = cleanRel.endsWith('.js') ? new TextDecoder().decode(buffer) : '';
        return { text, buffer };
      }
    } catch {

    }
  }
  throw new Error(`Failed to fetch ${filename} from any candidate path`);
}

async function ensureRizinLoaded(): Promise<void> {
  if (rizinModule && createSessionFn && cmdFn) return;

  postProgress('Fetching Rizin v0.9.1 WebAssembly runtime...', 'info');

  const [jsArtifact, wasmArtifact] = await Promise.all([
    fetchArtifact('rizin.js', 'https://indalok.github.io/rzwasi/rizin.js'),
    fetchArtifact('rizin.wasm', 'https://indalok.github.io/rzwasi/rizin.wasm'),
  ]);

  const jsText = jsArtifact.text;
  const wasmBuf = wasmArtifact.buffer;

  await new Promise<void>((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('Rizin WASM initialization timed out')), 60000);
    self.Module = {
      wasmBinary: new Uint8Array(wasmBuf),
      noInitialRun: true,
      locateFile: (path: string) => `/wasm/${path}`,
      print: () => {},
      printErr: () => {},
      onRuntimeInitialized: () => {
        clearTimeout(timeout);
        resolve();
      },
      onAbort: (reason: any) => {
        clearTimeout(timeout);
        reject(new Error(`Rizin WASM aborted: ${String(reason)}`));
      },
    };

    try {
      (0, eval)(jsText);
    } catch (err) {
      clearTimeout(timeout);
      reject(err);
    }
  });

  rizinModule = self.Module;
  createSessionFn = rizinModule.cwrap('rzweb_create_session', 'number', []);
  closeSessionFn = rizinModule.cwrap('rzweb_close_session', null, ['number']);
  openFileFn = rizinModule.cwrap('rzweb_open_file', 'number', ['number', 'string']);
  cmdFn = rizinModule.cwrap('rzweb_cmd', 'string', ['number', 'string']);

  try {
    rizinModule.FS.mkdir('/work');
  } catch {

  }

  postProgress('Rizin v0.9.1 WASM core initialized in Web Worker.', 'success');
}

async function ensureJsdecLoaded(): Promise<void> {
  if (jsdecLoaded) return;

  self.Global = () => sharedGlobalState;
  self.Limits = {
    UT16_MAX: 0xffffn,
    UT32_MAX: 0xffffffffn,
    UT64_MAX: 0xffffffffffffffffn,
    ST16_MAX: 0x7fffn,
    ST32_MAX: 0x7fffffffn,
    ST64_MAX: 0x7fffffffffffffffn,
  };

  const [longImport, jsonexImport, libdecImport, printerImport, warningImport, rzutilImport] =
    await Promise.all([
      import('../jsdec-src/libdec/long.js'),
      import('../jsdec-src/libdec/JSONex.js'),
      import('../jsdec-src/libdec/libdec.js'),
      import('../jsdec-src/libdec/printer.js'),
      import('../jsdec-src/libdec/warning.js'),
      import('../jsdec-src/libdec/rzutil.js'),
    ]);

  LongMod = longImport.default;
  JSONexMod = jsonexImport.default;
  libdecMod = libdecImport.default;
  PrinterMod = printerImport.default;
  WarningMod = warningImport.default;
  rzutilMod = rzutilImport.default;

  self.rizin = {
    command: (cmd: string) => runRizinCmd(cmd),
    graph: () => {
      const pdfRaw = runRizinCmd('pdfj');
      const agfRaw = runRizinCmd('agf json_disasm');
      const pdf = parseJsonSafe<any>(pdfRaw, null);
      const agf = parseJsonSafe<any[]>(agfRaw, []);

      if (Array.isArray(agf) && agf.length > 0 && agf[0]?.blocks) {
        const g = agf[0];
        return [
          {
            name: g.name || pdf?.name || 'fcn',
            blocks: (g.blocks || []).map((b: any) => ({
              addr: LongMod.fromValue(BigInt(b.offset ?? b.addr ?? 0), true),
              jump: b.jump !== undefined ? LongMod.fromValue(BigInt(b.jump), true) : undefined,
              fail: b.fail !== undefined ? LongMod.fromValue(BigInt(b.fail), true) : undefined,
              ops: (b.ops || []).map((op: any) => ({
                offset: LongMod.fromValue(BigInt(op.offset ?? op.addr ?? 0), true),
                ptr:
                  op.ptr !== undefined && op.ptr !== null
                    ? LongMod.fromValue(BigInt(op.ptr), true)
                    : undefined,
                refptr: Boolean(op.refptr),
                opcode: op.opcode || op.disasm || '',
                disasm: op.disasm || op.opcode || '',
                type: op.type || 'mov',
                jump: op.jump !== undefined ? LongMod.fromValue(BigInt(op.jump), true) : undefined,
                fail: op.fail !== undefined ? LongMod.fromValue(BigInt(op.fail), true) : undefined,
                 comment: op.comment
                  ? (() => {
                      try {
                        return atob(op.comment);
                      } catch {
                        return String(op.comment);
                      }
                    })()
                  : undefined,
              })),
            })),
          },
        ];
      }

      if (pdf && Array.isArray(pdf.ops)) {
        return [
          {
            name: pdf.name || 'fcn',
            blocks: [
              {
                addr: LongMod.fromValue(BigInt(pdf.addr ?? pdf.ops[0]?.offset ?? 0), true),
                ops: pdf.ops.map((op: any) => ({
                  offset: LongMod.fromValue(BigInt(op.offset ?? 0), true),
                  ptr:
                    op.ptr !== undefined && op.ptr !== null
                      ? LongMod.fromValue(BigInt(op.ptr), true)
                      : undefined,
                  refptr: Boolean(op.refptr),
                  opcode: op.opcode || op.disasm || '',
                  disasm: op.disasm || op.opcode || '',
                  type: op.type || 'mov',
                  jump:
                    op.jump !== undefined ? LongMod.fromValue(BigInt(op.jump), true) : undefined,
                  fail:
                    op.fail !== undefined ? LongMod.fromValue(BigInt(op.fail), true) : undefined,
                })),
              },
            ],
          },
        ];
      }

      return [];
    },
  };

  jsdecLoaded = true;
  postProgress('jsdec v0.9.0 AST & Control-Flow Decompiler loaded in Worker.', 'success');
}

async function handleOpenBinary(data: Uint8Array, filename: string): Promise<BinaryMetadata> {
  await ensureRizinLoaded();
  await ensureJsdecLoaded();

  if (sessionId && closeSessionFn) {
    try {
      closeSessionFn(sessionId);
    } catch {

    }
    sessionId = 0;
  }

  currentBinaryData = new Uint8Array(data);
  currentFilename = filename;

  sessionId = createSessionFn!();
  const safePath = `/work/${filename.replace(/[^a-zA-Z0-9._-]/g, '_')}`;
  try {
    rizinModule.FS.unlink(safePath);
  } catch {

  }
  rizinModule.FS.writeFile(safePath, currentBinaryData);

  const opened = openFileFn!(sessionId, safePath);
  if (!opened) {
    postProgress(`Rizin open_file returned 0 for ${safePath}; proceeding with raw binary fallback.`, 'warn');
  }

  runRizinCmd('e scr.color=0');
  runRizinCmd('e asm.lines=false');
  runRizinCmd('e io.cache=true');

  const ij = parseJsonSafe<Record<string, any>>(runRizinCmd('ij'), {});
  const ie = parseJsonSafe<any[]>(runRizinCmd('iej'), []);
  const il = parseJsonSafe<string[]>(runRizinCmd('ilj'), []);
  const sha256 = await computeSha256Hex(currentBinaryData);

  currentMetadata = inspectBinaryHeaders(currentBinaryData, filename, sha256, {
    overview: ij,
    entries: ie,
    libraries: il,
  });

  postProgress(
    `Opened ${filename} (${currentMetadata.format} · ${currentMetadata.architecture} ${currentMetadata.bits}-bit · EP ${currentMetadata.entryPoint})`,
    'success'
  );
  return currentMetadata;
}

async function handleAnalyze(minStringLength = 4): Promise<AnalysisResult> {
  if (!currentBinaryData || !currentMetadata) {
    throw new Error('No binary opened in Engine A');
  }
  const t0 = performance.now();
  postProgress('Running Rizin full binary analysis (aaa)...', 'info');
  runRizinCmd('aaa');

  const rawSections = parseJsonSafe<any[]>(runRizinCmd('iSj'), []);
  const sections: SectionInfo[] = rawSections
    .filter((s) => s && s.name && Number(s.size) > 0)
    .map((s) => {
      const paddr = Number(s.paddr ?? 0);
      const rawVaddr = BigInt(s.vaddr ?? 0);

      const vaddr = rawVaddr > 0xffffffffffff0000n ? paddr : Number(rawVaddr);
      const sz = Number(s.size ?? 0);
      const slice =
        paddr >= 0 && paddr + sz <= currentBinaryData!.length
          ? currentBinaryData!.subarray(paddr, paddr + sz)
          : new Uint8Array(0);
      const secEntropy = slice.length > 0 ? calculateEntropy(slice) : 0;
      return {
        name: String(s.name),
        virtualAddress: `0x${vaddr.toString(16)}`,
        virtualAddressNum: vaddr,
        fileOffset: `0x${paddr.toString(16)}`,
        fileOffsetNum: paddr,
        size: sz,
        virtualSize: Number(s.vsize ?? sz),
        permissions: String(s.perm ?? 'r--'),
        flags: Array.isArray(s.flags) ? s.flags.join(', ') : String(s.type ?? 'PROGBITS'),
        entropy: secEntropy,
        functionsCount: 0,
        stringsCount: 0,
      };
    });

  const rawImports = parseJsonSafe<any[]>(runRizinCmd('iij'), []);
  const imports: ImportInfo[] = rawImports.map((imp) => {
    const vaddr = Number(imp.plt ?? imp.vaddr ?? 0);
    return {
      name: String(imp.name || 'unknown_import'),
      decoratedName: imp.realname ? String(imp.realname) : undefined,
      library: String(imp.libname || imp.lib || 'EXTERNAL'),
      address: `0x${vaddr.toString(16)}`,
      virtualAddress: vaddr,
      pltAddress: imp.plt ? `0x${Number(imp.plt).toString(16)}` : undefined,
      ordinal: typeof imp.ordinal === 'number' ? imp.ordinal : undefined,
      bind: String(imp.bind || 'GLOBAL'),
      type: String(imp.type || 'FUNC'),
      isUnresolved: vaddr === 0,
      xrefs: [],
    };
  });

  const rawExports = parseJsonSafe<any[]>(runRizinCmd('iEj'), []);
  const exportsList: ExportInfo[] = rawExports.map((exp) => {
    const vaddr = Number(exp.vaddr ?? exp.paddr ?? 0);
    return {
      name: String(exp.name || 'export'),
      decoratedName: exp.realname ? String(exp.realname) : undefined,
      address: `0x${vaddr.toString(16)}`,
      virtualAddress: vaddr,
      fileOffset: Number(exp.paddr ?? 0),
      size: Number(exp.size ?? 0),
      ordinal: typeof exp.ordinal === 'number' ? exp.ordinal : undefined,
      type: String(exp.type || 'FUNC'),
      isForwarded: Boolean(exp.is_forwarded),
    };
  });

  const rawSymbols = parseJsonSafe<any[]>(runRizinCmd('isj'), []);
  const symbols: SymbolInfo[] = rawSymbols.map((sym) => {
    const vaddr = Number(sym.vaddr ?? sym.paddr ?? 0);
    return {
      name: String(sym.name || 'sym'),
      demangledName: sym.realname ? String(sym.realname) : undefined,
      address: `0x${vaddr.toString(16)}`,
      virtualAddress: vaddr,
      size: Number(sym.size ?? 0),
      type: String(sym.type || 'FUNC'),
      bind: String(sym.bind || 'LOCAL'),
      section: String(sym.section || '.text'),
    };
  });

  const rawRelocs = parseJsonSafe<any[]>(runRizinCmd('irj'), []);
  const relocations: RelocationInfo[] = rawRelocs.map((rel) => {
    const vaddr = Number(rel.vaddr ?? rel.paddr ?? 0);
    return {
      name: String(rel.name || 'reloc'),
      address: `0x${vaddr.toString(16)}`,
      virtualAddress: vaddr,
      type: String(rel.type || 'REL64'),
      addend: typeof rel.addend === 'number' ? rel.addend : undefined,
      target: rel.target_vaddr ? `0x${Number(rel.target_vaddr).toString(16)}` : undefined,
    };
  });

  const rawStrings = parseJsonSafe<any[]>(runRizinCmd('izzj'), []);
  const strings: StringInfo[] = extractBinaryStrings(
    currentBinaryData,
    sections,
    minStringLength,
    rawStrings
  );

  const rawFunctions = parseJsonSafe<any[]>(runRizinCmd('aflj'), []);
  const entryPointAddr = parseInt(currentMetadata.entryPoint, 16) || 0;
  const exportAddrs = new Set(exportsList.map((e) => e.virtualAddress));
  const importAddrs = new Set(imports.map((i) => i.virtualAddress));

  const mapVaddrToFileOffset = (vaddr: number): number => {
    for (const sec of sections) {
      if (vaddr >= sec.virtualAddressNum && vaddr < sec.virtualAddressNum + Math.max(sec.size, sec.virtualSize)) {
        return sec.fileOffsetNum + (vaddr - sec.virtualAddressNum);
      }
    }
    return 0;
  };

  const functions: FunctionInfo[] = rawFunctions.map((f) => {
    const vaddr = Number(f.offset ?? f.vaddr ?? 0);
    const rawName = String(f.name || `fcn.${vaddr.toString(16)}`);
    const size = Number(f.size ?? f.realsz ?? 0);
    const nbbs = Number(f.nbbs ?? 1);
    const edges = Number(f.edges ?? 0);

    const callrefs: any[] = Array.isArray(f.callrefs) ? f.callrefs : [];
    const codexrefs: any[] = Array.isArray(f.codexrefs) ? f.codexrefs : [];

    const callees = Array.from(
      new Set<string>(
        callrefs
          .filter((r) => r.type === 'CALL' || r.type === 'C' || r.type === 'J')
          .map((r) => `0x${Number(r.to ?? r.addr ?? 0).toString(16)}`)
      )
    );
    const callers = Array.from(
      new Set<string>(
        codexrefs
          .filter((r) => r.type === 'CALL' || r.type === 'C')
          .map((r) => `0x${Number(r.from ?? r.addr ?? 0).toString(16)}`)
      )
    );

    const cls = classifyFunction(
      rawName,
      vaddr,
      size,
      nbbs,
      callees,
      callers,
      entryPointAddr,
      exportAddrs,
      importAddrs
    );

    const { autoName } = generateIdaStyleFunctionName(rawName, vaddr, currentMetadata!.bits, {
      isThunk: cls.isThunk,
      isImported: cls.isImported,
      isExported: cls.isExported,
      isEntry: cls.category === 'entry',
    });

    const localVars: FunctionInfo['localVars'] = [];
    if (Array.isArray(f.stackvars)) {
      for (const sv of f.stackvars) {
        localVars.push({
          name: String(sv.name || 'var'),
          type: String(sv.type || 'int64_t'),
          offset: String(sv.storage?.stack ?? 0),
          kind: sv.arg ? 'arg' : 'stack',
        });
      }
    }
    if (Array.isArray(f.regvars)) {
      for (const rv of f.regvars) {
        localVars.push({
          name: String(rv.name || 'reg'),
          type: String(rv.type || 'int64_t'),
          offset: String(rv.storage?.reg ?? 'reg'),
          kind: 'reg',
        });
      }
    }

    const datarefs: any[] = Array.isArray(f.datarefs) ? f.datarefs : [];
    const stringsReferenced: string[] = [];
    for (const dr of datarefs) {
      const targetAddr = Number(dr.to ?? dr.addr ?? 0);
      const strMatch = strings.find(
        (s) => Math.abs(s.virtualAddress - targetAddr) <= 4 || Math.abs(s.fileOffset - targetAddr) <= 4
      );
      if (strMatch) {
        stringsReferenced.push(strMatch.value);
        if (!strMatch.functions.includes(autoName)) {
          strMatch.functions.push(autoName);
        }
      }
    }

    return {
      address: `0x${vaddr.toString(16)}`,
      virtualAddress: vaddr,
      fileOffset: mapVaddrToFileOffset(vaddr),
      name: autoName,
      originalName: rawName,
      autoName,
      size,
      basicBlocksCount: nbbs,
      edgesCount: edges,
      callersCount: callers.length,
      calleesCount: callees.length,
      callers,
      callees,
      signature: String(f.signature || `${autoName}()`),
      callingConvention: String(f.calltype || currentMetadata!.abi),
      category: cls.category,
      isRecursive: cls.isRecursive,
      isThunk: cls.isThunk,
      isWrapper: cls.isWrapper,
      isExported: cls.isExported,
      isImported: cls.isImported,
      isUnreferenced: cls.isUnreferenced,
      hasPrologue: Number(f.stackframe ?? 0) > 0,
      hasEpilogue: true,
      possiblyInlined: size > 0 && size <= 24 && callers.length >= 2,
      localVars,
      stringsReferenced,
      importsUsed: [],
    };
  });

  for (const sec of sections) {
    sec.functionsCount = functions.filter(
      (fn) =>
        fn.virtualAddress >= sec.virtualAddressNum &&
        fn.virtualAddress < sec.virtualAddressNum + Math.max(sec.size, sec.virtualSize)
    ).length;
    sec.stringsCount = strings.filter((s) => s.section === sec.name).length;
  }

  const cgNodes: CallGraphNode[] = functions.map((fn, idx) => ({
    id: fn.address,
    address: fn.address,
    name: fn.name,
    category: fn.category,
    depth: fn.category === 'entry' ? 0 : fn.name === 'main' ? 1 : (idx % 3) + 1,
  }));
  const cgEdges: CallGraphEdge[] = [];
  for (const fn of functions) {
    for (const target of fn.callees) {
      if (functions.some((x) => x.address === target)) {
        cgEdges.push({ from: fn.address, to: target, count: 1 });
      }
    }
  }
  const callGraph: CallGraphData = {
    rootAddress: functions.find((f) => f.name === 'main')?.address || functions[0]?.address || '0x0',
    nodes: cgNodes,
    edges: cgEdges,
  };

  currentMetadata = inspectBinaryHeaders(
    currentBinaryData,
    currentFilename,
    currentMetadata.sha256,
    null,
    sections
  );

  const durationMs = Math.round(performance.now() - t0);
  currentAnalysis = {
    metadata: currentMetadata,
    functions,
    strings,
    imports,
    exports: exportsList,
    symbols,
    relocations,
    tlsCallbacks: [],
    vtables: [],
    rttiEntries: [],
    sections,
    callGraph,
    analysisDurationMs: durationMs,
  };

  postProgress(
    `Analysis complete in ${durationMs} ms: ${functions.length} functions, ${strings.length} strings, ${sections.length} sections.`,
    'success'
  );
  return currentAnalysis;
}

function getDisassemblyLinesForAddress(address: string): DisassemblyLine[] {
  runRizinCmd(`s ${address}`);
  const pdf = parseJsonSafe<any>(runRizinCmd('pdfj'), null);
  const ops: any[] = Array.isArray(pdf?.ops)
    ? pdf.ops
    : parseJsonSafe<any[]>(runRizinCmd('pdj 48'), []);

  return ops.map((op) => {
    const vaddr = Number(op.offset ?? op.addr ?? 0);
    const disasm = String(op.disasm || op.opcode || 'nop');
    const parts = disasm.trim().split(/\s+/);
    const mnemonic = parts[0] || 'nop';
    const operands = parts.slice(1).join(' ');
    let comment = '';
    if (op.comment) {
      try {
        comment = atob(String(op.comment));
      } catch {
        comment = String(op.comment);
      }
    }
    return {
      address: `0x${vaddr.toString(16)}`,
      virtualAddress: vaddr,
      bytes: String(op.bytes || ''),
      mnemonic,
      operands,
      disasm,
      type: String(op.type || 'mov'),
      comment: comment || undefined,
      jumpTarget: op.jump !== undefined ? `0x${Number(op.jump).toString(16)}` : undefined,
      failTarget: op.fail !== undefined ? `0x${Number(op.fail).toString(16)}` : undefined,
      xrefsIn: Array.isArray(op.xrefs)
        ? op.xrefs.map((x: any) => ({
            from: `0x${Number(x.addr ?? 0).toString(16)}`,
            type: String(x.type || 'CODE'),
          }))
        : [],
      xrefsOut: [],
    };
  });
}

function getCfgForAddress(address: string): CfgData {
  runRizinCmd(`s ${address}`);
  const agf = parseJsonSafe<any[]>(runRizinCmd('agf json_disasm'), []);
  const g = agf[0];
  const fnName =
    currentAnalysis?.functions.find((f) => f.address.toLowerCase() === address.toLowerCase())?.name ||
    g?.name ||
    address;

  if (!g || !Array.isArray(g.blocks)) {
    const lines = getDisassemblyLinesForAddress(address);
    return {
      functionAddress: address,
      functionName: fnName,
      blocks: [
        {
          id: address,
          address,
          virtualAddress: parseInt(address, 16) || 0,
          size: lines.length * 4,
          label: `${fnName}_entry`,
          isEntry: true,
          isExit: true,
          isLoopHeader: false,
          instructions: lines.map((l) => ({
            address: l.address,
            bytes: l.bytes,
            disasm: l.disasm,
            type: l.type,
            comment: l.comment,
          })),
        },
      ],
      edges: [],
    };
  }

  const blocks: CfgBlock[] = [];
  const edges: CfgEdge[] = [];
  const seenAddrs = new Set<string>();

  g.blocks.forEach((b: any, idx: number) => {
    const vaddr = Number(b.offset ?? b.addr ?? 0);
    const addrHex = `0x${vaddr.toString(16)}`;
    seenAddrs.add(addrHex);

    const jumpHex = b.jump !== undefined ? `0x${Number(b.jump).toString(16)}` : undefined;
    const failHex = b.fail !== undefined ? `0x${Number(b.fail).toString(16)}` : undefined;
    const ops: any[] = Array.isArray(b.ops) ? b.ops : [];

    blocks.push({
      id: addrHex,
      address: addrHex,
      virtualAddress: vaddr,
      size: Number(b.size ?? ops.length * 4),
      label: idx === 0 ? `${fnName} (Entry)` : `loc_${vaddr.toString(16)}`,
      isEntry: idx === 0,
      isExit: !jumpHex && !failHex,
      isLoopHeader: Boolean(jumpHex && seenAddrs.has(jumpHex)),
      jump: jumpHex,
      fail: failHex,
      instructions: ops.map((op) => ({
        address: `0x${Number(op.offset ?? op.addr ?? 0).toString(16)}`,
        bytes: String(op.bytes || ''),
        disasm: String(op.disasm || op.opcode || ''),
        type: String(op.type || 'mov'),
      })),
    });

    if (jumpHex && failHex) {
      edges.push({ from: addrHex, to: jumpHex, type: 'true' });
      edges.push({ from: addrHex, to: failHex, type: 'false' });
    } else if (jumpHex) {
      const isLoop = seenAddrs.has(jumpHex);
      edges.push({ from: addrHex, to: jumpHex, type: isLoop ? 'loop' : 'unconditional' });
    }
  });

  return {
    functionAddress: address,
    functionName: fnName,
    blocks,
    edges,
  };
}

async function handleDecompile(address: string): Promise<DecompilationResult> {
  await ensureRizinLoaded();
  await ensureJsdecLoaded();

  const t0 = performance.now();
  runRizinCmd(`s ${address}`);

  const fnInfo = currentAnalysis?.functions.find(
    (f) => f.address.toLowerCase() === address.toLowerCase()
  );
  const fnName = fnInfo?.name || `sub_${address.replace(/^0x/i, '')}`;
  const arch = currentMetadata?.architecture || 'x86';

  const outputLines: string[] = [];
  const warnings: string[] = [];
  const errors: string[] = [];

  sharedGlobalState.printer = new PrinterMod((msg: string) => {
    if (msg !== undefined && msg !== null) {
      outputLines.push(String(msg));
    }
  });
  sharedGlobalState.warning = new WarningMod((msg: string) => {
    if (msg) warnings.push(String(msg));
  });
  sharedGlobalState.evars = {
    arch,
    archbits: currentMetadata?.bits || 64,
    honor: {
      casts: true,
      assembly: false,
      blocks: false,
      offsets: false,
      paddr: false,
      pseudo: false,
    },
    extra: {
      allfunctions: false,
      ascodeline: false,
      ascomment: false,
      debug: true,
      file: currentFilename || 'binary',
       highlights: false,
      offset: LongMod.fromValue(BigInt(parseInt(address, 16) || 0), true),
      slow: false,
      theme: 'default',
    },
  };

  try {
    const architecture = libdecMod.archs[arch];
    if (!architecture) {
      throw new Error(`Architecture '${arch}' not directly registered in jsdec`);
    }
    const data = new rzutilMod.data();
    const session = new libdecMod.core.session(data, architecture);
    const archContext = architecture.context(data);
    architecture.pre_analysis(session, archContext);
    architecture.decompile(session, archContext);
    architecture.post_analysis(session, archContext);
    session.print();
  } catch (err: any) {
    errors.push(err?.message || String(err));
  }

  let code = outputLines.join('\n').trim();
  if (!code) {

    const lines = getDisassemblyLinesForAddress(address);
    const body = lines
      .map((l) => `    /* ${l.address} */ ${l.disasm};`)
      .join('\n');
    code = `// Rizin + jsdec fallback reconstruction for ${fnName} @ ${address}\nint64_t ${fnName}(void) {\n${body}\n    return 0;\n}`;
  }

  const durationMs = Math.round(performance.now() - t0);
  return {
    engineId: 'rizin-jsdec',
    engineName: 'Rizin v0.9.1 + jsdec',
    engineVersion: '0.9.1 / 0.9.0',
    functionAddress: address,
    functionName: fnName,
    architecture: arch,
    code,
    rawCode: code,
    durationMs,
    warnings,
    errors,
    variables: fnInfo?.localVars.map((v) => v.name) || [],
    calls: fnInfo?.callees || [],
    strings: fnInfo?.stringsReferenced || [],
  };
}

self.onmessage = async (event: MessageEvent) => {
  const { id, action, payload } = event.data || {};
  try {
    let result: any = null;
    switch (action) {
      case 'initialize':
        await ensureRizinLoaded();
        await ensureJsdecLoaded();
        result = { ok: true };
        break;
      case 'openBinary':
        result = await handleOpenBinary(payload.data, payload.filename);
        break;
      case 'analyze':
        result = await handleAnalyze(payload?.minStringLength ?? 4);
        break;
      case 'getDisassemblyLines':
        result = getDisassemblyLinesForAddress(payload.address);
        break;
      case 'getCfg':
        result = getCfgForAddress(payload.address);
        break;
      case 'decompile':
        result = await handleDecompile(payload.address);
        break;
      case 'executeRawCommand':
        result = runRizinCmd(payload.command);
        break;
      case 'syncSymbols':
        if (Array.isArray(payload.symbols)) {
          for (const sym of payload.symbols) {
            if (sym.address && sym.name) {
              const safe = String(sym.name).replace(/[^a-zA-Z0-9_]/g, '_');
              runRizinCmd(`afn ${safe} @ ${sym.address}`);
            }
          }
        }
        result = { ok: true };
        break;
      case 'close':
        if (sessionId && closeSessionFn) {
          closeSessionFn(sessionId);
          sessionId = 0;
        }
        result = { ok: true };
        break;
      default:
        throw new Error(`Unknown worker action: ${action}`);
    }
    self.postMessage({ id, ok: true, result });
  } catch (err: any) {
    const message = err?.message || String(err);
    postProgress(`Worker error (${action}): ${message}`, 'error');
    self.postMessage({ id, ok: false, error: message });
  }
};
