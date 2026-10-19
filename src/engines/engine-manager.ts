import type {
  AnalysisResult,
  BinaryMetadata,
  CfgData,
  DecompilationResult,
  DecompilerEngine,
  DisassemblyLine,
  ExportInfo,
  FunctionInfo,
  ImportInfo,
  SectionInfo,
  StringInfo,
  WorkerLogEntry,
} from '../types';

type LogCallback = (entry: Omit<WorkerLogEntry, 'id' | 'timestamp'>) => void;

class WorkerRpcClient {
  private worker: Worker | null = null;
  private reqId = 1;
  private pending = new Map<
    number,
    { resolve: (val: any) => void; reject: (err: Error) => void; timer: any }
  >();
  private createWorkerFn: () => Worker;
  private onLog?: LogCallback;

  constructor(createWorkerFn: () => Worker, onLog?: LogCallback) {
    this.createWorkerFn = createWorkerFn;
    this.onLog = onLog;
  }

  private ensureWorker(): Worker {
    if (!this.worker) {
      this.worker = this.createWorkerFn();
      this.worker.onmessage = (event: MessageEvent) => {
        const data = event.data || {};
        if (data.type === 'log') {
          this.onLog?.({
            source: data.source || 'System',
            level: data.level || 'info',
            message: String(data.message || ''),
          });
          return;
        }
        const { id, ok, result, error } = data;
        const entry = this.pending.get(id);
        if (!entry) return;
        clearTimeout(entry.timer);
        this.pending.delete(id);
        if (ok) {
          entry.resolve(result);
        } else {
          entry.reject(new Error(error || 'Worker request failed'));
        }
      };
      this.worker.onerror = (err) => {
        this.onLog?.({
          source: 'System',
          level: 'error',
          message: `Worker runtime error: ${err.message || 'Unknown error'}`,
        });
      };
    }
    return this.worker;
  }

  public call<T = any>(action: string, payload?: any, timeoutMs = 45000): Promise<T> {
    const w = this.ensureWorker();
    const id = this.reqId++;
    return new Promise<T>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`Worker action '${action}' timed out after ${timeoutMs}ms`));
      }, timeoutMs);
      this.pending.set(id, { resolve, reject, timer });
      w.postMessage({ id, action, payload });
    });
  }

  public terminate(): void {
    for (const [, p] of this.pending) {
      clearTimeout(p.timer);
      p.reject(new Error('Worker terminated by user'));
    }
    this.pending.clear();
    if (this.worker) {
      this.worker.terminate();
      this.worker = null;
    }
  }
}

export class RizinJsdecEngine implements DecompilerEngine {
  public readonly id = 'rizin-jsdec';
  public readonly name = 'Rizin v0.9.1 + jsdec v0.9.0';
  public readonly version = '0.9.1-wasm';
  public readonly supportedArchitectures = [
    'x86',
    'x86_64',
    'arm',
    'aarch64',
    'mips',
    'ppc',
    'riscv',
    'sparc',
    'm68k',
    'dalvik',
    'wasm',
    'v850',
  ];
  public readonly supportedFormats = [
    'ELF32',
    'ELF64',
    'PE32',
    'PE32+',
    'Mach-O',
    'WASM',
    'COFF',
    'DEX',
    'Raw Binary',
  ];
  public readonly capabilities = {
    hasCLikeDecompiler: true,
    supportsCfg: true,
    supportsCallGraph: true,
    supportsFunctionNaming: true,
    supportsStrings: true,
    supportsImports: true,
    supportsExports: true,
    supportsHexView: true,
    supportedArchitectures: [
      'x86',
      'x86_64',
      'arm',
      'aarch64',
      'mips',
      'ppc',
      'riscv',
      'sparc',
      'm68k',
      'dalvik',
      'wasm',
    ],
  };

  private rpc: WorkerRpcClient;
  private lastAnalysis: AnalysisResult | null = null;
  private minStringLength = 4;

  constructor(onLog?: LogCallback) {
    this.rpc = new WorkerRpcClient(
      () =>
        new Worker(new URL('../workers/rizin-jsdec.worker.ts', import.meta.url), {
          type: 'module',
        }),
      onLog
    );
  }

  public setMinStringLength(len: number): void {
    this.minStringLength = Math.max(2, len);
  }

  public async initialize(): Promise<void> {
    await this.rpc.call('initialize', {}, 45000);
  }

  public async openBinary(data: Uint8Array, filename: string): Promise<BinaryMetadata> {
    return this.rpc.call<BinaryMetadata>('openBinary', { data, filename }, 45000);
  }

  public async analyze(): Promise<AnalysisResult> {
    const res = await this.rpc.call<AnalysisResult>(
      'analyze',
      { minStringLength: this.minStringLength },
      60000
    );
    this.lastAnalysis = res;
    return res;
  }

  public async listFunctions(): Promise<FunctionInfo[]> {
    if (!this.lastAnalysis) await this.analyze();
    return this.lastAnalysis?.functions || [];
  }

  public async getStrings(): Promise<StringInfo[]> {
    if (!this.lastAnalysis) await this.analyze();
    return this.lastAnalysis?.strings || [];
  }

  public async disassemble(address: string): Promise<string> {
    const lines = await this.getDisassemblyLines(address);
    return lines
      .map((l) => `${l.address.padEnd(12)} ${l.bytes.padEnd(18)} ${l.disasm}`)
      .join('\n');
  }

  public async getDisassemblyLines(address: string): Promise<DisassemblyLine[]> {
    return this.rpc.call<DisassemblyLine[]>('getDisassemblyLines', { address }, 20000);
  }

  public async getCfg(address: string): Promise<CfgData> {
    return this.rpc.call<CfgData>('getCfg', { address }, 20000);
  }

  public async decompile(address: string): Promise<DecompilationResult> {
    return this.rpc.call<DecompilationResult>('decompile', { address }, 30000);
  }

  public async getImports(): Promise<ImportInfo[]> {
    if (!this.lastAnalysis) await this.analyze();
    return this.lastAnalysis?.imports || [];
  }

  public async getExports(): Promise<ExportInfo[]> {
    if (!this.lastAnalysis) await this.analyze();
    return this.lastAnalysis?.exports || [];
  }

  public async getSections(): Promise<SectionInfo[]> {
    if (!this.lastAnalysis) await this.analyze();
    return this.lastAnalysis?.sections || [];
  }

  public async executeRawCommand(command: string): Promise<string> {
    return this.rpc.call<string>('executeRawCommand', { command }, 15000);
  }

  public async syncSymbols(symbols: Array<{ address: string; name: string }>): Promise<void> {
    await this.rpc.call('syncSymbols', { symbols }, 15000);
  }

  public async close(): Promise<void> {
    this.lastAnalysis = null;
    await this.rpc.call('close', {}, 5000).catch(() => {});
  }

  public cancelAndRestart(): void {
    this.lastAnalysis = null;
    this.rpc.terminate();
  }
}

export class GhidraWasmEngine implements DecompilerEngine {
  public readonly id = 'ghidra-wasm';
  public readonly name = 'Ghidra C++ Sleigh Decompiler';
  public readonly version = '11.2 / 0.0.4';
  public readonly supportedArchitectures = [
    'x86',
    'x86_64',
    'arm',
    'aarch64',
    'mips',
    'ppc',
    'riscv',
    'sparc',
    'm68k',
    'z80',
    '6502',
    'avr',
    'ebpf',
    'superh4',
    'xtensa',
    'loongarch',
  ];
  public readonly supportedFormats = [
    'ELF32',
    'ELF64',
    'PE32',
    'PE32+',
    'Mach-O',
    'Raw Binary / Firmware',
  ];
  public readonly capabilities = {
    hasCLikeDecompiler: true,
    supportsCfg: false,
    supportsCallGraph: false,
    supportsFunctionNaming: true,
    supportsStrings: false,
    supportsImports: false,
    supportsExports: false,
    supportsHexView: false,
    supportedArchitectures: [
      'x86',
      'x86_64',
      'arm',
      'aarch64',
      'mips',
      'ppc',
      'riscv',
      'sparc',
      'm68k',
    ],
  };

  private rpc: WorkerRpcClient;
  private sharedAnalysis: AnalysisResult | null = null;

  constructor(onLog?: LogCallback) {
    this.rpc = new WorkerRpcClient(
      () =>
        new Worker(new URL('../workers/ghidra.worker.ts', import.meta.url), {
          type: 'module',
        }),
      onLog
    );
  }

  public setSharedAnalysis(analysis: AnalysisResult): void {
    this.sharedAnalysis = analysis;
  }

  public async initialize(): Promise<void> {
    await this.rpc.call('initialize', {}, 45000);
  }

  public async openBinary(data: Uint8Array, filename: string): Promise<BinaryMetadata> {
    const sections = this.sharedAnalysis?.sections || [];
    const symbols =
      this.sharedAnalysis?.functions.map((f) => ({
        address: f.address,
        name: f.customName || f.name,
      })) || [];
    return this.rpc.call<BinaryMetadata>(
      'openBinary',
      { data, filename, sections, symbols },
      45000
    );
  }

  public async syncContext(
    sections: SectionInfo[],
    symbols: Array<{ address: string; name: string }>
  ): Promise<void> {
    await this.rpc.call('syncContext', { sections, symbols }, 15000);
  }

  public async analyze(): Promise<AnalysisResult> {
    if (this.sharedAnalysis) return this.sharedAnalysis;
    throw new Error('Ghidra engine relies on primary binary analysis context');
  }

  public async listFunctions(): Promise<FunctionInfo[]> {
    return this.sharedAnalysis?.functions || [];
  }

  public async getStrings(): Promise<StringInfo[]> {
    return this.sharedAnalysis?.strings || [];
  }

  public async disassemble(address: string): Promise<string> {
    return `// Disassembly @ ${address} provided by Rizin core`;
  }

  public async decompile(address: string): Promise<DecompilationResult> {
    return this.rpc.call<DecompilationResult>('decompile', { address }, 45000);
  }

  public async getImports(): Promise<ImportInfo[]> {
    return this.sharedAnalysis?.imports || [];
  }

  public async getExports(): Promise<ExportInfo[]> {
    return this.sharedAnalysis?.exports || [];
  }

  public async getSections(): Promise<SectionInfo[]> {
    return this.sharedAnalysis?.sections || [];
  }

  public async syncSymbols(symbols: Array<{ address: string; name: string }>): Promise<void> {
    await this.rpc.call(
      'syncContext',
      {
        sections: this.sharedAnalysis?.sections || [],
        symbols,
      },
      15000
    );
  }

  public async close(): Promise<void> {
    await this.rpc.call('close', {}, 5000).catch(() => {});
  }

  public cancelAndRestart(): void {
    this.rpc.terminate();
  }
}
