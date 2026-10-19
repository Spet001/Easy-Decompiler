import type { BinaryMetadata, SectionInfo } from '../types';

export function calculateEntropy(data: Uint8Array): number {
  if (!data || data.length === 0) return 0;
  const counts = new Uint32Array(256);
  for (let i = 0; i < data.length; i++) {
    counts[data[i]]++;
  }
  let entropy = 0;
  const len = data.length;
  for (let i = 0; i < 256; i++) {
    const c = counts[i];
    if (c > 0) {
      const p = c / len;
      entropy -= p * Math.log2(p);
    }
  }
  return Math.round(entropy * 100) / 100;
}

export async function computeSha256Hex(data: Uint8Array): Promise<string> {
  if (typeof crypto !== 'undefined' && crypto.subtle) {
    try {
      const copy = new Uint8Array(data.byteLength);
      copy.set(data);
      const digest = await crypto.subtle.digest('SHA-256', copy.buffer);
      const bytes = new Uint8Array(digest);
      return Array.from(bytes)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
    } catch {
      // Fallback below
    }
  }
  // Pure JS fallback hash if crypto.subtle unavailable
  let h1 = 0xdeadbeef ^ data.length;
  let h2 = 0x41c6ce57 ^ data.length;
  for (let i = 0; i < data.length; i++) {
    const ch = data[i];
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  return (h1 >>> 0).toString(16).padStart(8, '0') + (h2 >>> 0).toString(16).padStart(8, '0').repeat(7);
}

export function inspectBinaryHeaders(
  data: Uint8Array,
  filename: string,
  sha256: string,
  rizinInfo?: Record<string, unknown> | null,
  sections?: SectionInfo[]
): BinaryMetadata {
  const entropy = calculateEntropy(data);
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);

  let format = 'Raw Binary / Firmware';
  let architecture = 'x86';
  let bits: 16 | 32 | 64 = 64;
  let endianness: 'little' | 'big' = 'little';
  let entryPoint = '0x0';
  let baseAddress = '0x0';
  let compiler = 'Unknown / Generic Toolchain';
  let os = 'Bare Metal / Unknown';
  let abi = 'System V / Default';
  let machine = 'Generic';
  let subsystem = 'Console / Native';
  let hasSymbols = false;
  let isStripped = true;
  let isPackedOrProtected = entropy >= 7.15;
  let packerDetails = entropy >= 7.15 ? `High Shannon entropy (${entropy.toFixed(2)} bits/byte) suggests packing or compressed payload` : 'None detected (normal section entropy)';
  const libraries: string[] = [];

  // 1. Check ELF Magic: 0x7F 'E' 'L' 'F'
  if (data.length >= 64 && data[0] === 0x7f && data[1] === 0x45 && data[2] === 0x4c && data[3] === 0x46) {
    const is64 = data[4] === 2;
    const isLE = data[5] !== 2;
    bits = is64 ? 64 : 32;
    endianness = isLE ? 'little' : 'big';
    format = is64 ? 'ELF64' : 'ELF32';
    os = data[7] === 3 ? 'Linux' : data[7] === 9 ? 'FreeBSD' : 'UNIX - System V';
    abi = is64 ? 'System V ABI' : 'ELF32 ABI';

    const e_type = dv.getUint16(16, isLE);
    const e_machine = dv.getUint16(18, isLE);
    const e_entry = is64 ? dv.getBigUint64(24, isLE) : BigInt(dv.getUint32(24, isLE));
    entryPoint = `0x${e_entry.toString(16)}`;
    baseAddress = e_type === 3 ? '0x0' : is64 ? '0x400000' : '0x8048000';

    switch (e_machine) {
      case 0x3e:
        architecture = 'x86';
        machine = 'AMD x86-64';
        break;
      case 0x03:
        architecture = 'x86';
        machine = 'Intel 80386';
        break;
      case 0xb7:
        architecture = 'arm';
        machine = 'ARM AArch64';
        abi = 'AAPCS64';
        break;
      case 0x28:
        architecture = 'arm';
        machine = 'ARM32';
        abi = 'EABI';
        break;
      case 0x08:
        architecture = 'mips';
        machine = 'MIPS R3000';
        break;
      case 0xf3:
        architecture = 'riscv';
        machine = `RISC-V ${bits}`;
        break;
      case 0x14:
      case 0x15:
        architecture = 'ppc';
        machine = `PowerPC ${bits}`;
        break;
      default:
        architecture = 'x86';
        machine = `ELF Machine 0x${e_machine.toString(16)}`;
    }

    // Check if `.symtab` string is present in binary
    const asciiText = new TextDecoder('latin1').decode(data.subarray(0, Math.min(data.length, 65536)));
    hasSymbols = asciiText.includes('.symtab');
    isStripped = !hasSymbols;
    if (asciiText.includes('GCC:')) {
      const m = asciiText.match(/GCC:\s*\([^)]+\)\s*[0-9.]+/);
      compiler = m ? m[0] : 'GCC (GNU Compiler Collection)';
    } else if (asciiText.includes('clang version')) {
      compiler = 'LLVM / Clang';
    } else {
      compiler = 'GCC / GNU ld (ELF)';
    }
    if (asciiText.includes('UPX!')) {
      isPackedOrProtected = true;
      packerDetails = 'UPX Packer signature (UPX!) detected';
    }
  }
  // 2. Check PE/COFF Magic: 'M' 'Z'
  else if (data.length >= 0x80 && data[0] === 0x4d && data[1] === 0x5a) {
    const peOff = dv.getUint32(0x3c, true);
    if (peOff + 24 <= data.length && data[peOff] === 0x50 && data[peOff + 1] === 0x45) {
      const machineCode = dv.getUint16(peOff + 4, true);
      const numSyms = dv.getUint32(peOff + 16, true);
      const optOff = peOff + 24;
      const optMagic = optOff + 2 <= data.length ? dv.getUint16(optOff, true) : 0x10b;
      const isPe64 = optMagic === 0x20b;

      bits = isPe64 ? 64 : 32;
      endianness = 'little';
      format = isPe64 ? 'PE32+ (64-bit Windows)' : 'PE32 (32-bit Windows)';
      os = 'Windows (NT)';
      abi = isPe64 ? 'Microsoft x64 (fastcall)' : 'stdcall / cdecl';

      switch (machineCode) {
        case 0x8664:
          architecture = 'x86';
          machine = 'AMD64 (x86-64)';
          break;
        case 0x014c:
          architecture = 'x86';
          machine = 'Intel i386';
          break;
        case 0xaa64:
          architecture = 'arm';
          machine = 'ARM64 (Windows)';
          break;
        case 0x01c0:
        case 0x01c2:
        case 0x01c4:
          architecture = 'arm';
          machine = 'ARMv7 Thumb';
          break;
        default:
          architecture = 'x86';
          machine = `PE Machine 0x${machineCode.toString(16)}`;
      }

      if (optOff + 68 <= data.length) {
        const linkerMajor = data[optOff + 2];
        const linkerMinor = data[optOff + 3];
        const epRva = dv.getUint32(optOff + 16, true);
        const imgBase = isPe64 ? dv.getBigUint64(optOff + 24, true) : BigInt(dv.getUint32(optOff + 28, true));
        baseAddress = `0x${imgBase.toString(16)}`;
        entryPoint = `0x${(imgBase + BigInt(epRva)).toString(16)}`;
        compiler = `MSVC / Linker v${linkerMajor}.${linkerMinor}`;
      }
      hasSymbols = numSyms > 0;
      isStripped = numSyms === 0;
      const asciiText = new TextDecoder('latin1').decode(data.subarray(0, Math.min(data.length, 65536)));
      if (asciiText.includes('UPX0') || asciiText.includes('VMProtect') || asciiText.includes('Themida')) {
        isPackedOrProtected = true;
        packerDetails = 'Known PE packer section signature (UPX/VMProtect/Themida) detected';
      }
    }
  }
  // 3. Check Mach-O Magic
  else if (data.length >= 32) {
    const m = ((data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3]) >>> 0;
    if (m === 0xfeedfacf || m === 0xcffaedfe || m === 0xfeedface || m === 0xcefaedfe) {
      const is64 = m === 0xfeedfacf || m === 0xcffaedfe;
      const isLE = m === 0xcffaedfe || m === 0xcefaedfe;
      bits = is64 ? 64 : 32;
      endianness = isLE ? 'little' : 'big';
      format = is64 ? 'Mach-O 64-bit' : 'Mach-O 32-bit';
      os = 'macOS / iOS (Darwin)';
      compiler = 'Apple Clang / ld64';
      const cputype = dv.getUint32(4, isLE);
      if ((cputype & 0xff) === 12) {
        architecture = 'arm';
        machine = is64 ? 'Apple Silicon ARM64' : 'ARM32';
        abi = 'Darwin ARM64 ABI';
      } else {
        architecture = 'x86';
        machine = is64 ? 'x86-64' : 'i386';
        abi = 'SysV Darwin ABI';
      }
      baseAddress = is64 ? '0x100000000' : '0x1000';
      entryPoint = baseAddress;
      hasSymbols = true;
      isStripped = false;
    } else if (data[0] === 0x00 && data[1] === 0x61 && data[2] === 0x73 && data[3] === 0x6d) {
      format = 'WebAssembly (WASM 1.0)';
      architecture = 'wasm';
      bits = 32;
      endianness = 'little';
      os = 'WASI / Browser WebAssembly VM';
      abi = 'WASM Stack Machine';
      compiler = 'LLVM wasm-ld / Emscripten';
      machine = 'wasm32';
      baseAddress = '0x0';
      entryPoint = '0x0';
      hasSymbols = true;
      isStripped = false;
    }
  }

  // Merge Rizin info if available
  if (rizinInfo && typeof rizinInfo === 'object') {
    const overview = (rizinInfo.overview ?? rizinInfo) as Record<string, any>;
    const bin = overview?.bin ?? (rizinInfo.binaryInfo as Record<string, any>) ?? {};
    const core = overview?.core ?? {};

    if (bin.arch) architecture = String(bin.arch);
    if (bin.bits === 16 || bin.bits === 32 || bin.bits === 64) bits = bin.bits;
    if (bin.endian) endianness = String(bin.endian).toLowerCase().includes('big') ? 'big' : 'little';
    if (bin.class || core.format) format = String(bin.class || core.format);
    if (bin.os) os = String(bin.os);
    if (bin.machine) machine = String(bin.machine);
    if (bin.subsys) subsystem = String(bin.subsys);
    if (bin.compiler) compiler = String(bin.compiler);
    if (typeof bin.stripped === 'boolean') {
      isStripped = bin.stripped;
      hasSymbols = !bin.stripped;
    }
    if (typeof bin.baddr === 'number' && bin.baddr >= 0) {
      baseAddress = `0x${bin.baddr.toString(16)}`;
    }
    const entries = rizinInfo.entries as Array<{ vaddr?: number }> | undefined;
    if (Array.isArray(entries) && entries[0]?.vaddr !== undefined) {
      entryPoint = `0x${Number(entries[0].vaddr).toString(16)}`;
    }
    const libs = rizinInfo.libraries as string[] | undefined;
    if (Array.isArray(libs)) {
      libraries.push(...libs.map(String));
    }
  }

  if (sections && sections.some((s) => s.entropy >= 7.25)) {
    const highSec = sections.find((s) => s.entropy >= 7.25)!;
    isPackedOrProtected = true;
    packerDetails = `Section ${highSec.name} exhibits elevated entropy (${highSec.entropy.toFixed(2)} bits/byte)`;
  }

  return {
    filename,
    size: data.byteLength,
    sha256,
    format,
    architecture,
    bits,
    endianness,
    entryPoint,
    baseAddress,
    compiler,
    os,
    abi,
    machine,
    subsystem,
    hasSymbols,
    isStripped,
    isPackedOrProtected,
    packerDetails,
    entropy,
    libraries,
  };
}
