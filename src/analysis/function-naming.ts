import type { FunctionCategory, FunctionInfo } from '../types';

export function generateIdaStyleFunctionName(
  rawName: string,
  virtualAddress: number,
  bits: 16 | 32 | 64,
  options: {
    isThunk?: boolean;
    isImported?: boolean;
    isExported?: boolean;
    isEntry?: boolean;
    padFull64?: boolean;
  } = {}
): { autoName: string; isUnnamedOrGeneric: boolean } {
  const cleanRaw = (rawName || '').trim();
  const hexAddr = Math.max(0, Math.floor(virtualAddress)).toString(16).toLowerCase();
  const formattedHex = options.padFull64 && bits === 64 ? hexAddr.padStart(16, '0') : hexAddr;

  const isGenericRizinName =
    !cleanRaw ||
    /^fcn\.[0-9a-fA-F]+$/.test(cleanRaw) ||
    /^sub\.[0-9a-fA-F]+$/.test(cleanRaw) ||
    /^loc\.[0-9a-fA-F]+$/.test(cleanRaw) ||
    /^func_0x[0-9a-fA-F]+$/.test(cleanRaw) ||
    /^unk\.[0-9a-fA-F]+$/.test(cleanRaw);

  if (options.isEntry || cleanRaw === 'entry0' || cleanRaw === '_start' || cleanRaw === 'entry') {
    if (cleanRaw === 'entry0') {
      return { autoName: '_start', isUnnamedOrGeneric: false };
    }
    return { autoName: cleanRaw || '_start', isUnnamedOrGeneric: false };
  }

  if (options.isImported || cleanRaw.startsWith('sym.imp.') || cleanRaw.startsWith('loc.imp.')) {
    const strippedImp = cleanRaw
      .replace(/^(sym\.imp\.|loc\.imp\.|imp\.)/, '')
      .replace(/^[^_]+\.dll_/i, '');
    return {
      autoName: strippedImp ? `imp_${strippedImp}` : `imp_sub_${formattedHex}`,
      isUnnamedOrGeneric: false,
    };
  }

  if (isGenericRizinName) {
    if (options.isThunk) {
      return { autoName: `j_sub_${formattedHex}`, isUnnamedOrGeneric: true };
    }
    return { autoName: `sub_${formattedHex}`, isUnnamedOrGeneric: true };
  }

  if (cleanRaw === 'main' || cleanRaw === 'sym.main' || cleanRaw === '_main') {
    return { autoName: 'main', isUnnamedOrGeneric: false };
  }
  if (/dllmain/i.test(cleanRaw)) {
    return { autoName: 'DllMain', isUnnamedOrGeneric: false };
  }
  if (cleanRaw.startsWith('sym.')) {
    const baseSym = cleanRaw.slice(4).replace(/^[^_]+\.(exe|dll|so)_/i, '');
    if (options.isThunk) {
      return { autoName: `thunk_${baseSym}`, isUnnamedOrGeneric: false };
    }
    return { autoName: baseSym, isUnnamedOrGeneric: false };
  }

  return { autoName: cleanRaw, isUnnamedOrGeneric: false };
}

export function classifyFunction(
  rawName: string,
  virtualAddress: number,
  size: number,
  basicBlocksCount: number,
  callees: string[],
  callers: string[],
  entryPointAddr: number,
  exportAddrs: Set<number>,
  importAddrs: Set<number>
): {
  category: FunctionCategory;
  isRecursive: boolean;
  isThunk: boolean;
  isWrapper: boolean;
  isExported: boolean;
  isImported: boolean;
  isUnreferenced: boolean;
} {
  const addrHex = `0x${virtualAddress.toString(16)}`;
  const isEntry =
    virtualAddress === entryPointAddr ||
    rawName === 'entry0' ||
    rawName === '_start' ||
    rawName === 'entry';
  const isImported =
    importAddrs.has(virtualAddress) ||
    rawName.startsWith('sym.imp.') ||
    rawName.startsWith('loc.imp.') ||
    rawName.startsWith('imp_');
  const isExported =
    exportAddrs.has(virtualAddress) ||
    rawName === 'main' ||
    rawName === 'sym.main' ||
    rawName.includes('.exe_') ||
    rawName.includes('.dll_');
  const isRecursive = callees.includes(addrHex) || callees.includes(rawName);
  const isThunk =
    !isImported &&
    ((size > 0 && size <= 16 && basicBlocksCount <= 1 && callees.length === 1) ||
      rawName.startsWith('j_') ||
      rawName.startsWith('thunk_'));
  const isWrapper =
    !isThunk && !isImported && basicBlocksCount === 1 && callees.length === 1 && size <= 48;
  const isUnreferenced = !isEntry && !isExported && callers.length === 0;

  let category: FunctionCategory = 'standard';
  if (isEntry) category = 'entry';
  else if (isImported) category = 'imported';
  else if (rawName.includes('plt') || rawName.includes('got')) category = 'plt_got';
  else if (rawName.includes('init') || rawName.includes('ctor') || rawName.includes('GLOBAL__sub_I'))
    category = 'constructor';
  else if (rawName.includes('fini') || rawName.includes('dtor')) category = 'destructor';
  else if (isThunk) category = 'thunk';
  else if (isExported) category = 'exported';
  else if (isRecursive) category = 'recursive';
  else if (isWrapper) category = 'wrapper';
  else if (
    rawName.includes('register_tm_clones') ||
    rawName.includes('deregister_tm_clones') ||
    rawName.includes('frame_dummy')
  )
    category = 'compiler_stub';
  else if (isUnreferenced) category = 'unreferenced';

  return {
    category,
    isRecursive,
    isThunk,
    isWrapper,
    isExported,
    isImported,
    isUnreferenced,
  };
}

export function applyCustomNamesToCode(
  code: string,
  functions: FunctionInfo[],
  customNames: Record<string, string>,
  comments: Record<string, string>
): string {
  if (!code) return code;
  let updated = code;

  for (const fn of functions) {
    const activeName = customNames[fn.address] || fn.customName || fn.name;
    const hexNoPrefix = fn.virtualAddress.toString(16);
    const candidates = new Set<string>([
      fn.originalName,
      fn.originalName.replace(/\./g, '_'),
      fn.autoName,
      `fcn_${hexNoPrefix}`,
      `fcn_${hexNoPrefix.padStart(8, '0')}`,
      `func_0x${hexNoPrefix}`,
      `func_0x${hexNoPrefix.padStart(8, '0')}`,
      `sym_${fn.originalName.replace(/^sym\./, '').replace(/\./g, '_')}`,
    ]);

    for (const cand of candidates) {
      if (!cand || cand === activeName || cand.length < 3) continue;
      const escaped = cand.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const re = new RegExp(`\\b${escaped}\\b`, 'g');
      updated = updated.replace(re, activeName);
    }
  }

  const fnMatch = functions.find((f) => {
    const activeName = customNames[f.address] || f.customName || f.name;
    return updated.includes(`${activeName}(`) || updated.includes(`${activeName} (`);
  });
  if (fnMatch) {
    const userComment = comments[fnMatch.address] || fnMatch.comment;
    if (userComment && !updated.includes(userComment)) {
      updated = `/* [User Annotation @ ${fnMatch.address}]: ${userComment} */\n` + updated;
    }
  }

  return updated;
}
