import type { SectionInfo, StringHeuristicCategory, StringInfo } from '../types';

export function classifyStringHeuristics(value: string): {
  categories: StringHeuristicCategory[];
  heuristicNote?: string;
} {
  const categories: StringHeuristicCategory[] = [];
  let heuristicNote: string | undefined;
  const trimmed = value.trim();

  if (/^https?:\/\/[^\s/$.?#].[^\s]*$/i.test(trimmed) || /https?:\/\/[a-z0-9.-]+/i.test(trimmed)) {
    categories.push('URL');
  }
  if (/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/.test(trimmed)) {
    categories.push('Email');
  }
  if (
    /^(\/[a-zA-Z0-9._-]+){2,}/.test(trimmed) ||
    /^[a-zA-Z]:\\[\\\S|*\S]?.*$/.test(trimmed) ||
    /\.(json|xml|conf|ini|cfg|pem|key|db|sqlite|log)$/i.test(trimmed)
  ) {
    categories.push('FilePath');
  }
  if (
    /\b(sh\s+-c|cmd\.exe|powershell|chmod\s+\+x|\/bin\/sh|\/bin\/bash|uname\s+-a|whoami|curl\s+|wget\s+)\b/i.test(
      trimmed
    )
  ) {
    categories.push('ShellCommand');
  }
  if (/\.(dll|so|dylib)(\.[0-9]+)*$/i.test(trimmed) || /^(KERNEL32|USER32|ADVAPI32|NTDLL|WS2_32|libc|libcrypto)/i.test(trimmed)) {
    categories.push('DLL/Library');
  }
  if (
    /^(CreateFile|VirtualAlloc|WriteFile|LoadLibrary|GetProcAddress|RegOpenKey|socket|connect|execve|ptrace|dlopen|dlsym|dcgettext|printf|malloc|free)/i.test(
      trimmed
    )
  ) {
    categories.push('API/Symbol');
  }
  if (/\b(error|failed|invalid|exception|denied|fatal|corrupt|overflow|unauthorized)\b/i.test(trimmed)) {
    categories.push('ErrorMessage');
  }
  if (
    /\b(AES|RSA|SHA256|SHA384|SHA512|ChaCha20|HMAC|EVP_|BEGIN\s+PUBLIC\s+KEY|BEGIN\s+PRIVATE\s+KEY|cipher|decrypt|encrypt)\b/i.test(
      trimmed
    )
  ) {
    categories.push('CryptoIndicator');
  }
  if (/\b(DEBUG|ASSERT|TRACE|VERBOSE|stack\s+frame|gdb|lldb|pdb)\b/i.test(trimmed)) {
    categories.push('DebugIndicator');
  }
  if (/\b(ELF|PE32|MZ|PNG|JFIF|ZIP|PDF-|SQLite\s+format)\b/.test(trimmed)) {
    categories.push('FileFormat');
  }

  if (
    /(AIza[0-9A-Za-z-_]{20,}|ghp_[0-9A-Za-z]{20,}|eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+|[0-9a-fA-F]{32,64})/.test(
      trimmed
    )
  ) {
    categories.push('HeuristicTokenOrKey');
    heuristicNote =
      'Heuristic pattern match only (high-entropy identifier or token-like format). Not a confirmed secret.';
  }

  if (categories.length === 0) {
    categories.push('General');
  }

  return { categories, heuristicNote };
}

export function extractBinaryStrings(
  data: Uint8Array,
  sections: SectionInfo[],
  minLen = 4,
  rizinStrings?: Array<Record<string, any>>
): StringInfo[] {
  const results: StringInfo[] = [];
  const seenKeys = new Set<string>();

  const findSectionName = (paddr: number, vaddr: number): string => {
    for (const sec of sections) {
      if (vaddr >= sec.virtualAddressNum && vaddr < sec.virtualAddressNum + Math.max(sec.size, sec.virtualSize)) {
        return sec.name;
      }
      if (paddr >= sec.fileOffsetNum && paddr < sec.fileOffsetNum + sec.size) {
        return sec.name;
      }
    }
    return '.rodata / raw';
  };

  if (Array.isArray(rizinStrings) && rizinStrings.length > 0) {
    for (const item of rizinStrings) {
      const val = String(item.string ?? '');
      if (val.length < minLen) continue;
      const vaddr = Number(item.vaddr ?? item.paddr ?? 0);
      const paddr = Number(item.paddr ?? item.vaddr ?? 0);
      const key = `${vaddr}:${val}`;
      if (seenKeys.has(key)) continue;
      seenKeys.add(key);

      const rawType = String(item.type ?? 'ascii').toLowerCase();
      const encoding: StringInfo['encoding'] = rawType.includes('utf16be')
        ? 'UTF-16BE'
        : rawType.includes('utf16') || rawType.includes('wide')
          ? 'UTF-16LE'
          : rawType.includes('utf8')
            ? 'UTF-8'
            : 'ASCII';

      const { categories, heuristicNote } = classifyStringHeuristics(val);
      results.push({
        address: `0x${vaddr.toString(16)}`,
        virtualAddress: vaddr,
        fileOffset: paddr,
        section: item.section ? String(item.section) : findSectionName(paddr, vaddr),
        encoding,
        length: val.length,
        value: val,
        xrefs: [],
        functions: [],
        categories,
        heuristicNote,
      });
    }
  }

  const mapOffsetToVaddr = (paddr: number): number => {
    for (const sec of sections) {
      if (paddr >= sec.fileOffsetNum && paddr < sec.fileOffsetNum + sec.size) {
        return sec.virtualAddressNum + (paddr - sec.fileOffsetNum);
      }
    }
    return paddr;
  };

  let start = -1;
  const maxScan = Math.min(data.length, 2 * 1024 * 1024);
  for (let i = 0; i < maxScan; i++) {
    const b = data[i];
    const isPrintable = (b >= 0x20 && b <= 0x7e) || b === 0x09 || b === 0x0a;
    if (isPrintable) {
      if (start < 0) start = i;
    } else {
      if (start >= 0 && i - start >= minLen) {
        const val = new TextDecoder('utf-8', { fatal: false }).decode(data.subarray(start, i)).trim();
        if (val.length >= minLen) {
          const vaddr = mapOffsetToVaddr(start);
          const key = `${vaddr}:${val}`;
          if (!seenKeys.has(key)) {
            seenKeys.add(key);
            const { categories, heuristicNote } = classifyStringHeuristics(val);
            results.push({
              address: `0x${vaddr.toString(16)}`,
              virtualAddress: vaddr,
              fileOffset: start,
              section: findSectionName(start, vaddr),
              encoding: 'ASCII',
              length: val.length,
              value: val,
              xrefs: [],
              functions: [],
              categories,
              heuristicNote,
            });
          }
        }
      }
      start = -1;
    }
  }

  let wStart = -1;
  let wChars: number[] = [];
  for (let i = 0; i + 1 < Math.min(data.length, 512 * 1024); i += 2) {
    const lo = data[i];
    const hi = data[i + 1];
    if (hi === 0 && lo >= 0x20 && lo <= 0x7e) {
      if (wStart < 0) wStart = i;
      wChars.push(lo);
    } else {
      if (wStart >= 0 && wChars.length >= minLen) {
        const val = String.fromCharCode(...wChars).trim();
        if (val.length >= minLen) {
          const vaddr = mapOffsetToVaddr(wStart);
          const key = `${vaddr}:${val}`;
          if (!seenKeys.has(key)) {
            seenKeys.add(key);
            const { categories, heuristicNote } = classifyStringHeuristics(val);
            results.push({
              address: `0x${vaddr.toString(16)}`,
              virtualAddress: vaddr,
              fileOffset: wStart,
              section: findSectionName(wStart, vaddr),
              encoding: 'UTF-16LE',
              length: val.length,
              value: val,
              xrefs: [],
              functions: [],
              categories,
              heuristicNote,
            });
          }
        }
      }
      wStart = -1;
      wChars = [];
    }
  }

  return results.sort((a, b) => a.virtualAddress - b.virtualAddress);
}
