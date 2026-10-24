import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { calculateEntropy, computeSha256Hex, inspectBinaryHeaders } from '../src/analysis/metadata';
import { classifyFunction, generateIdaStyleFunctionName, applyCustomNamesToCode } from '../src/analysis/function-naming';
import { extractBinaryStrings, classifyStringHeuristics } from '../src/analysis/string-analysis';
import { generateMarkdownReport, serializeProjectBundle } from '../src/analysis/report-export';
import type { AnalysisResult, BinaryMetadata, FunctionInfo, SavedProject, SectionInfo } from '../src/types';

describe('10-Point QA Verification Suite — Easy Decompiler', () => {

  it('QA Step 1: Detects binary formats and architectures accurately', () => {

    const peBuf = new Uint8Array(128);
    peBuf[0] = 0x4D;
    peBuf[1] = 0x5A;
    const view = new DataView(peBuf.buffer);
    view.setUint32(0x3C, 0x40, true);
    peBuf[0x40] = 0x50;
    peBuf[0x41] = 0x45;
    view.setUint16(0x44, 0x014c, true);
    view.setUint16(0x58, 0x010b, true);
    const peMeta = inspectBinaryHeaders(peBuf, 'test.exe', 'deadbeef');
    expect(peMeta.format).toContain('PE32');
    expect(peMeta.size).toBe(128);

    const elfBuf = new Uint8Array(64);
    elfBuf.set([0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00]);
    const elfMeta = inspectBinaryHeaders(elfBuf, 'test.elf', 'beefcafe');
    expect(elfMeta.format).toBe('ELF64');
    expect(elfMeta.bits).toBe(64);
  });

  it('QA Step 2: Computes Shannon entropy accurately for crypto/packed detection', () => {
    const zeroBuf = new Uint8Array(1024).fill(0);
    const zeroEntropy = calculateEntropy(zeroBuf);
    expect(zeroEntropy).toBe(0);

    const randBuf = new Uint8Array(1024);
    for (let i = 0; i < 1024; i++) randBuf[i] = i % 256;
    const randEntropy = calculateEntropy(randBuf);
    expect(randEntropy).toBeGreaterThan(7.9);
  });

  it('QA Step 3: Computes SHA-256 hexadecimal hash correctly', async () => {
    const testData = new TextEncoder().encode('EasyDecompiler-QA-2026');
    const hash = await computeSha256Hex(testData);
    expect(hash).toHaveLength(64);
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('QA Step 4: Correctly reads and parses authentic gfwlivesetup.exe sample', () => {
    const samplePath = path.resolve(__dirname, '../public/samples/gfwlivesetup.exe');
    expect(fs.existsSync(samplePath)).toBe(true);

    const gfwlBytes = new Uint8Array(fs.readFileSync(samplePath));
    expect(gfwlBytes.length).toBe(642712);

    const meta = inspectBinaryHeaders(gfwlBytes, 'gfwlivesetup.exe', 'sha256-mock');
    expect(meta.format).toContain('PE32');
    expect(meta.architecture).toContain('x86');
    expect(meta.bits).toBe(32);
    expect(meta.entropy).toBeGreaterThan(6.0);
    expect(meta.size).toBe(642712);
  });

  it('QA Step 5: Classifies function names into security & reverse engineering categories', () => {
    const exportsSet = new Set<number>([0x401000]);
    const importsSet = new Set<number>([0x408000]);

    const resMain = classifyFunction('main', 0x401000, 100, 5, [], ['_start'], 0x401000, exportsSet, importsSet);
    expect(resMain.category).toBe('entry');

    const resImp = classifyFunction('sym.imp.CreateFileW', 0x408000, 16, 1, [], ['main'], 0x401000, exportsSet, importsSet);
    expect(resImp.category).toBe('imported');

    const resThunk = classifyFunction('j_sub_401080', 0x401020, 12, 1, ['0x401080'], ['main'], 0x401000, exportsSet, importsSet);
    expect(resThunk.isThunk).toBe(true);
  });

  it('QA Step 6: Generates standardized sub_* IDA auto-names for stripped binaries', () => {
    const res1 = generateIdaStyleFunctionName('fcn.00401080', 0x401080, { isEntry: false, isImported: false, isThunk: false });
    expect(res1.autoName).toBe('sub_401080');
    expect(res1.isUnnamedOrGeneric).toBe(true);

    const res2 = generateIdaStyleFunctionName('entry0', 0x401000, { isEntry: true, isImported: false, isThunk: false });
    expect(res2.autoName).toBe('_start');
  });

  it('QA Step 7: Extracts ASCII/UTF strings and classifies URLs, registry keys and file paths', () => {
    const rawContent = 'https://login.live.com/auth\0AES-256-CBC\0C:\\Windows\\System32\\kernel32.dll\0';
    const rawBytes = new TextEncoder().encode(rawContent);
    const sections: SectionInfo[] = [
      { name: '.rdata', virtualAddress: '0x409000', virtualAddressNum: 0x409000, size: rawBytes.length, virtualSize: rawBytes.length, permissions: 'r--', entropy: 4.5, fileOffset: '0x0', fileOffsetNum: 0 },
    ];
    const strings = extractBinaryStrings(rawBytes, sections, 4);

    expect(strings.length).toBeGreaterThanOrEqual(3);
    const urlStr = strings.find((s) => s.value.includes('http'));
    expect(urlStr).toBeDefined();
    expect(urlStr?.categories).toContain('URL');

    const cryptoStr = strings.find((s) => s.value.includes('AES'));
    expect(cryptoStr).toBeDefined();
    expect(cryptoStr?.categories).toContain('CryptoIndicator');

    const fileStr = strings.find((s) => s.value.includes('kernel32.dll'));
    expect(fileStr).toBeDefined();
    expect(fileStr?.categories).toContain('DLL/Library');
  });

  it('QA Step 8: Propagates user custom symbol renames across decompiled C output', () => {
    const originalCode = `
int sub_401080(char *key) {
    if (sub_401040(key) == 0x1337) {
        return 1;
    }
    return 0;
}`;
    const fns: FunctionInfo[] = [
      {
        address: '0x401080',
        virtualAddress: 0x401080,
        fileOffset: 0x1080,
        name: 'sub_401080',
        originalName: 'sub_401080',
        autoName: 'sub_401080',
        size: 64,
        basicBlocksCount: 3,
        signature: 'int sub_401080(char *key)',
        callingConvention: 'cdecl',
        callers: [],
        callees: ['0x401040'],
        xrefs: [],
        category: 'standard',
        entropy: 5.5,
        complexityScore: 4,
        isExported: false,
        isImported: false,
        isThunk: false,
        isRecursive: false,
      },
      {
        address: '0x401040',
        virtualAddress: 0x401040,
        fileOffset: 0x1040,
        name: 'sub_401040',
        originalName: 'sub_401040',
        autoName: 'sub_401040',
        size: 32,
        basicBlocksCount: 1,
        signature: 'int sub_401040(char *key)',
        callingConvention: 'cdecl',
        callers: ['0x401080'],
        callees: [],
        xrefs: [],
        category: 'standard',
        entropy: 5.0,
        complexityScore: 2,
        isExported: false,
        isImported: false,
        isThunk: false,
        isRecursive: false,
      },
    ];
    const customNames = {
      '0x401080': 'validate_license',
      '0x401040': 'compute_hash',
    };
    const renamed = applyCustomNamesToCode(originalCode, fns, customNames, {});
    expect(renamed).toContain('validate_license');
    expect(renamed).toContain('compute_hash');
    expect(renamed).not.toContain('sub_401080');
    expect(renamed).not.toContain('sub_401040');
  });

  it('QA Step 9: Serializes complete binary analysis report in clean Markdown', () => {
    const meta: BinaryMetadata = {
      filename: 'gfwlivesetup.exe',
      sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      size: 642712,
      format: 'PE32',
      architecture: 'x86 (Intel 80386)',
      bits: 32,
      endianness: 'little',
      entryPoint: '0x00405000',
      baseAddress: '0x00400000',
      entropy: 6.45,
      sectionsCount: 5,
      isValid: true,
      compiler: 'Microsoft Visual C++',
      os: 'Windows',
      abi: 'PE',
      machine: 'i386',
      subsystem: 'GUI',
      hasSymbols: false,
      isStripped: true,
      isPackedOrProtected: false,
      packerDetails: '',
      libraries: ['KERNEL32.dll'],
    };

    const mockAnalysis: AnalysisResult = {
      metadata: meta,
      sections: [{ name: '.text', virtualAddress: '0x00401000', virtualAddressNum: 0x401000, size: 204800, virtualSize: 204800, permissions: 'r-x', entropy: 6.2, fileOffset: '0x400', fileOffsetNum: 1024 }],
      imports: [{ library: 'KERNEL32.dll', functionName: 'CreateFileW', address: '0x00408000', ordinal: 0, isBound: false }],
      exports: [],
      symbols: [],
      relocations: [],
      functions: [{
        address: '0x00401000',
        virtualAddress: 0x401000,
        fileOffset: 1024,
        name: 'main',
        originalName: 'main',
        autoName: 'main',
        size: 120,
        basicBlocksCount: 5,
        signature: 'int main()',
        callingConvention: 'cdecl',
        callers: [],
        callees: [],
        xrefs: [],
        category: 'entry',
        entropy: 5.5,
        complexityScore: 3,
        isExported: true,
        isImported: false,
        isThunk: false,
        isRecursive: false,
      }],
      strings: [{ address: '0x00409000', value: 'https://spet01.dev', length: 18, type: 'ascii', encoding: 'ASCII', categories: ['url'], section: '.rdata', functions: [] }],
      callGraph: { nodes: [{ id: '0x00401000', label: 'main', address: '0x00401000', name: 'main', category: 'entry', depth: 0 }], edges: [] },
    };

    const report = generateMarkdownReport(mockAnalysis, null, null);
    expect(report).toContain('# Binary Reverse Engineering Report');
    expect(report).toContain('gfwlivesetup.exe');
    expect(report).toContain('PE32');
    expect(report).toContain('KERNEL32.dll');
  });

  it('QA Step 10: Bundles and serializes local-first project bundle without external dependencies', () => {
    const project: SavedProject = {
      id: 'proj-1',
      name: 'GFWL Analysis',
      filename: 'gfwlivesetup.exe',
      sha256: 'deadbeef1234',
      size: 642712,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      customNames: { '0x401000': 'custom_entry' },
      fnComments: { '0x401000': 'Entry point initial stub' },
      engineChoice: 'rizin-jsdec',
      tags: ['gfwl', 'pe32'],
    };
    const bundleJson = serializeProjectBundle(project);
    expect(bundleJson).toContain('GFWL Analysis');
    expect(bundleJson).toContain('gfwlivesetup.exe');
    const parsed = JSON.parse(bundleJson);
    expect(parsed.customNames['0x401000']).toBe('custom_entry');
    expect(parsed.fnComments['0x401000']).toBe('Entry point initial stub');
  });
});
