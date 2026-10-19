import { computeSha256Hex, inspectBinaryHeaders } from '../analysis/metadata';
import type {
  BinaryMetadata,
  DecompilationResult,
  SectionInfo,
} from '../types';

declare const self: DedicatedWorkerGlobalScope & {
  GhidraDecompiler?: (arg?: any) => Promise<any>;
};

let ghidraMod: any = null;
let processorsList: Array<{
  id: string;
  description: string;
  sla: string;
  pspec: string;
  compilers: Array<{ name: string; id: string; spec: string }>;
}> = [];

const specCache = new Map<
  string,
  { slaData: Uint8Array; pspecContent: string; cspecContent: string }
>();

let currentBinaryData: Uint8Array | null = null;
let currentFilename = '';
let currentMetadata: BinaryMetadata | null = null;
let currentSections: SectionInfo[] = [];
let currentSymbols: Array<{ address: string; name: string }> = [];
let activeArchId = 'x86:LE:64:default';

function postProgress(message: string, level: 'info' | 'warn' | 'error' | 'success' = 'info') {
  self.postMessage({ type: 'log', source: 'Engine B (Ghidra WASM)', level, message });
}

function bytesToHex(bytes: Uint8Array): string {
  const hexChars: string[] = new Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) {
    hexChars[i] = bytes[i].toString(16).padStart(2, '0');
  }
  return hexChars.join('');
}

function escapeXml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

async function fetchGhidraArtifact(
  filename: string
): Promise<{ text: string; buffer: ArrayBuffer; json?: any }> {
  const cleanRel = filename.replace(/^\/+/, '');
  const candidates: string[] = [];

  try {
    if (typeof self !== 'undefined' && self.location && self.location.href) {
      candidates.push(new URL(`../wasm/${cleanRel}`, self.location.href).href);
      candidates.push(new URL(`wasm/${cleanRel}`, self.location.href).href);
      candidates.push(new URL(`./wasm/${cleanRel}`, self.location.href).href);
      candidates.push(new URL(`../${cleanRel}`, self.location.href).href);
    }
  } catch {}

  candidates.push(
    `./wasm/${cleanRel}`,
    `wasm/${cleanRel}`,
    `../wasm/${cleanRel}`,
    `/tools/easy-decompiler/wasm/${cleanRel}`,
    `/wasm/${cleanRel}`
  );

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
        const text = new TextDecoder().decode(buffer);
        let json: any = undefined;
        if (cleanRel.endsWith('.json')) {
          try {
            json = JSON.parse(text);
          } catch {
            continue;
          }
        }
        return { text, buffer, json };
      }
    } catch {
      // try next candidate
    }
  }
  throw new Error(`Failed to fetch ${filename} from any candidate path`);
}

async function ensureGhidraLoaded(): Promise<void> {
  if (ghidraMod && processorsList.length > 0) return;

  postProgress('Fetching Ghidra C++ Decompiler WASM runtime...', 'info');
  const [jsArt, wasmArt, procArt] = await Promise.all([
    fetchGhidraArtifact('ghidra.js'),
    fetchGhidraArtifact('ghidra.wasm'),
    fetchGhidraArtifact('processors.json'),
  ]);

  processorsList = procArt.json;
  (0, eval)(`${jsArt.text}\nself.GhidraDecompiler = GhidraDecompiler;`);

  if (typeof self.GhidraDecompiler !== 'function') {
    throw new Error('GhidraDecompiler factory function not exposed');
  }

  ghidraMod = await self.GhidraDecompiler({
    wasmBinary: new Uint8Array(wasmArt.buffer),
    locateFile: (p: string) => {
      try {
        return new URL(`../wasm/${p}`, self.location.href).href;
      } catch {
        return `wasm/${p}`;
      }
    },
    print: () => {},
    printErr: () => {},
  });

  ghidraMod._init_decompiler();
  postProgress('Ghidra C++ Sleigh Decompiler WASM initialized in Web Worker.', 'success');
}

function resolveGhidraArchId(data: Uint8Array, meta: BinaryMetadata): string {
  if (ghidraMod) {
    const ptr = ghidraMod._malloc(data.length);
    ghidraMod.HEAPU8.set(data, ptr);
    const detected = ghidraMod.ccall(
      'detect_architecture',
      'string',
      ['number', 'number'],
      [ptr, data.length]
    );
    ghidraMod._free(ptr);
    if (detected && processorsList.some((p) => p.id === detected)) {
      return detected;
    }
  }

  const arch = meta.architecture.toLowerCase();
  const isBE = meta.endianness === 'big';
  const endianTag = isBE ? 'BE' : 'LE';

  if (arch.includes('arm') || arch.includes('aarch64')) {
    if (meta.bits === 64) return `AARCH64:${endianTag}:64:v8A`;
    return `ARM:${endianTag}:32:v8`;
  }
  if (arch.includes('mips')) {
    return `MIPS:${endianTag}:${meta.bits === 64 ? 64 : 32}:default`;
  }
  if (arch.includes('riscv')) {
    return `RISCV:LE:${meta.bits === 64 ? 64 : 32}:default`;
  }
  if (arch.includes('ppc') || arch.includes('powerpc')) {
    return `PowerPC:${endianTag}:${meta.bits === 64 ? 64 : 32}:default`;
  }
  return meta.bits === 32 ? 'x86:LE:32:default' : 'x86:LE:64:default';
}

async function getSpecsForArch(
  archId: string,
  osHint: string
): Promise<{ slaData: Uint8Array; pspecContent: string; cspecContent: string }> {
  const isWindows = /windows|pe32/i.test(osHint);
  const cacheKey = `${archId}:${isWindows ? 'win' : 'default'}`;
  const cached = specCache.get(cacheKey);
  if (cached) return cached;

  const proc =
    processorsList.find((p) => p.id === archId) ||
    processorsList.find((p) => p.id === 'x86:LE:64:default')!;

  let compiler = proc.compilers[0];
  if (isWindows) {
    const winComp = proc.compilers.find((c) => /windows|win|visual/i.test(c.id || c.name));
    if (winComp) compiler = winComp;
  } else {
    const gccComp = proc.compilers.find((c) => /gcc|default/i.test(c.id || c.name));
    if (gccComp) compiler = gccComp;
  }

  postProgress(`Loading Sleigh SLA/PSPEC/CSPEC for ${proc.id} (${compiler.id})...`, 'info');
  const [slaArt, pspecArt, cspecArt] = await Promise.all([
    fetchGhidraArtifact(proc.sla),
    fetchGhidraArtifact(proc.pspec),
    fetchGhidraArtifact(compiler.spec),
  ]);

  const entry = {
    slaData: new Uint8Array(slaArt.buffer),
    pspecContent: pspecArt.text,
    cspecContent: cspecArt.text,
  };
  specCache.set(cacheKey, entry);
  return entry;
}

function buildImageXml(
  data: Uint8Array,
  archId: string,
  meta: BinaryMetadata,
  sections: SectionInfo[],
  symbols: Array<{ address: string; name: string }>,
  targetAddress: string
): { xml: string; queryTarget: string } {
  const chunksXml: string[] = [];

  // Map sections into virtual memory space="ram"
  const validSections = sections.filter(
    (s) => s.size > 0 && s.fileOffsetNum >= 0 && s.fileOffsetNum + s.size <= data.length
  );

  if (validSections.length > 0) {
    for (const sec of validSections) {
      // Cap individual section chunk to 128 KB around functions or section start for fast XML ingest
      const maxLen = Math.min(sec.size, 131072);
      const slice = data.subarray(sec.fileOffsetNum, sec.fileOffsetNum + maxLen);
      const isReadOnly = !sec.permissions.includes('w') && !sec.permissions.includes('x');
      chunksXml.push(
        `  <bytechunk space="ram" offset="${sec.virtualAddress}"${
          isReadOnly ? ' readonly="true"' : ''
        }>\n    ${bytesToHex(slice)}\n  </bytechunk>`
      );
    }
  } else {
    // Fallback: parse ELF/PE headers directly or map entire binary at baseAddress
    const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
    let mappedFromHeaders = false;

    if (
      data.length >= 64 &&
      data[0] === 0x7f &&
      data[1] === 0x45 &&
      data[2] === 0x4c &&
      data[3] === 0x46
    ) {
      const is64 = data[4] === 2;
      const isLE = data[5] !== 2;
      const phoff = is64 ? Number(dv.getBigUint64(32, isLE)) : dv.getUint32(28, isLE);
      const phentsize = dv.getUint16(is64 ? 54 : 42, isLE);
      const phnum = dv.getUint16(is64 ? 56 : 44, isLE);

      for (let i = 0; i < phnum; i++) {
        const off = phoff + i * phentsize;
        if (off + phentsize > data.length) break;
        const p_type = dv.getUint32(off, isLE);
        if (p_type === 1) {
          // PT_LOAD
          const p_offset = is64 ? Number(dv.getBigUint64(off + 8, isLE)) : dv.getUint32(off + 4, isLE);
          const p_vaddr = is64 ? Number(dv.getBigUint64(off + 16, isLE)) : dv.getUint32(off + 8, isLE);
          const p_filesz = is64 ? Number(dv.getBigUint64(off + 32, isLE)) : dv.getUint32(off + 16, isLE);
          if (p_filesz > 0 && p_offset + p_filesz <= data.length) {
            const slice = data.subarray(p_offset, p_offset + Math.min(p_filesz, 131072));
            chunksXml.push(
              `  <bytechunk space="ram" offset="0x${p_vaddr.toString(16)}">\n    ${bytesToHex(slice)}\n  </bytechunk>`
            );
            mappedFromHeaders = true;
          }
        }
      }
    }

    if (!mappedFromHeaders) {
      const slice = data.subarray(0, Math.min(data.length, 131072));
      chunksXml.push(
        `  <bytechunk space="ram" offset="${meta.baseAddress || '0x0'}">\n    ${bytesToHex(slice)}\n  </bytechunk>`
      );
    }
  }

  // Register symbols so Ghidra emits clean function names on calls
  const symXml: string[] = [];
  const seenOffsets = new Set<string>();
  let queryTarget = targetAddress;

  for (const sym of symbols) {
    if (!sym.address || !sym.name) continue;
    const normAddr = `0x${(parseInt(sym.address, 16) || 0).toString(16)}`;
    if (seenOffsets.has(normAddr)) continue;
    seenOffsets.add(normAddr);

    const safeName = sym.name.replace(/[^a-zA-Z0-9_]/g, '_');
    symXml.push(
      `  <symbol space="ram" offset="${normAddr}" name="${escapeXml(safeName)}"/>`
    );

    if (normAddr.toLowerCase() === targetAddress.toLowerCase()) {
      queryTarget = safeName;
    }
  }

  // Ensure targetAddress itself has a symbol entry if not already in symbols
  const normTarget = `0x${(parseInt(targetAddress, 16) || 0).toString(16)}`;
  if (!seenOffsets.has(normTarget)) {
    const autoTargetName = `sub_${normTarget.replace(/^0x/, '')}`;
    symXml.push(
      `  <symbol space="ram" offset="${normTarget}" name="${autoTargetName}"/>`
    );
    queryTarget = autoTargetName;
  }

  const xml = `<binaryimage arch="${escapeXml(archId)}">\n${chunksXml.join('\n')}\n${symXml.join(
    '\n'
  )}\n</binaryimage>`;
  return { xml, queryTarget };
}

async function handleOpenBinary(
  data: Uint8Array,
  filename: string,
  sections?: SectionInfo[],
  symbols?: Array<{ address: string; name: string }>
): Promise<BinaryMetadata> {
  await ensureGhidraLoaded();
  currentBinaryData = new Uint8Array(data);
  currentFilename = filename;
  if (Array.isArray(sections)) currentSections = sections;
  if (Array.isArray(symbols)) currentSymbols = symbols;

  const sha256 = await computeSha256Hex(currentBinaryData);
  currentMetadata = inspectBinaryHeaders(currentBinaryData, filename, sha256, null, currentSections);
  activeArchId = resolveGhidraArchId(currentBinaryData, currentMetadata);

  // Pre-warm Sleigh specification cache for instant decompilation
  await getSpecsForArch(activeArchId, currentMetadata.os);

  postProgress(`Ghidra Sleigh architecture ready: ${activeArchId}`, 'success');
  return currentMetadata;
}

async function handleDecompile(address: string): Promise<DecompilationResult> {
  await ensureGhidraLoaded();
  if (!currentBinaryData || !currentMetadata) {
    throw new Error('No binary loaded in Ghidra Worker');
  }

  const t0 = performance.now();
  const specs = await getSpecsForArch(activeArchId, currentMetadata.os);
  const { xml, queryTarget } = buildImageXml(
    currentBinaryData,
    activeArchId,
    currentMetadata,
    currentSections,
    currentSymbols,
    address
  );

  const slaPtr = ghidraMod._malloc(specs.slaData.length);
  ghidraMod.HEAPU8.set(specs.slaData, slaPtr);

  let rawOutput = '';
  const warnings: string[] = [];
  const errors: string[] = [];

  try {
    const resPtr = ghidraMod.ccall(
      'decompile_pcode',
      'number',
      ['number', 'number', 'string', 'string', 'string', 'string'],
      [
        slaPtr,
        specs.slaData.length,
        specs.pspecContent,
        specs.cspecContent,
        xml,
        queryTarget,
      ]
    );
    rawOutput = ghidraMod.UTF8ToString(resPtr) || '';
    ghidraMod._free_string(resPtr);
  } catch (err: any) {
    errors.push(err?.message || String(err));
  } finally {
    ghidraMod._free(slaPtr);
  }

  // Extract Decompiler Messages comment block if present
  let cleanCode = rawOutput.trim();
  const msgMatch = cleanCode.match(/^\/\* Decompiler Messages:\n([\s\S]*?)\*\/\n?/);
  if (msgMatch) {
    const msgLines = msgMatch[1]
      .split('\n')
      .map((l) => l.trim())
      .filter(Boolean);
    warnings.push(...msgLines);
    cleanCode = cleanCode.slice(msgMatch[0].length).trim();
  }

  if (cleanCode.startsWith('Error:') || cleanCode.startsWith('Lowlevel Error:')) {
    errors.push(cleanCode);
  }

  const durationMs = Math.round(performance.now() - t0);
  return {
    engineId: 'ghidra-wasm',
    engineName: 'Ghidra C++ Sleigh Decompiler',
    engineVersion: '11.2 / WASM 0.0.4',
    functionAddress: address,
    functionName: queryTarget,
    architecture: activeArchId,
    code: cleanCode || `// Ghidra returned empty output for ${queryTarget} @ ${address}`,
    rawCode: rawOutput,
    durationMs,
    warnings,
    errors,
    variables: [],
    calls: [],
    strings: [],
  };
}

self.onmessage = async (event: MessageEvent) => {
  const { id, action, payload } = event.data || {};
  try {
    let result: any = null;
    switch (action) {
      case 'initialize':
        await ensureGhidraLoaded();
        result = { ok: true };
        break;
      case 'openBinary':
        result = await handleOpenBinary(
          payload.data,
          payload.filename,
          payload.sections,
          payload.symbols
        );
        break;
      case 'syncContext':
        if (Array.isArray(payload.sections)) currentSections = payload.sections;
        if (Array.isArray(payload.symbols)) currentSymbols = payload.symbols;
        result = { ok: true };
        break;
      case 'decompile':
        result = await handleDecompile(payload.address);
        break;
      case 'close':
        currentBinaryData = null;
        result = { ok: true };
        break;
      default:
        throw new Error(`Unknown Ghidra worker action: ${action}`);
    }
    self.postMessage({ id, ok: true, result });
  } catch (err: any) {
    const message = err?.message || String(err);
    postProgress(`Ghidra Worker error (${action}): ${message}`, 'error');
    self.postMessage({ id, ok: false, error: message });
  }
};
