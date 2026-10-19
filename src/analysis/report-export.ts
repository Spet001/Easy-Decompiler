import type {
  AnalysisResult,
  CallGraphData,
  CfgData,
  DecompilationResult,
  FunctionInfo,
  SavedProject,
  StringInfo,
} from '../types';

export function downloadLocalBlob(content: string | Uint8Array, filename: string, mimeType = 'text/plain;charset=utf-8'): void {
  const blobPart: BlobPart =
    typeof content === 'string'
      ? content
      : new Uint8Array(content.buffer.slice(content.byteOffset, content.byteOffset + content.byteLength)) as unknown as BlobPart;
  const blob = new Blob([blobPart], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function formatStringsExport(strings: StringInfo[], format: 'txt' | 'json' | 'csv'): string {
  if (format === 'json') {
    return JSON.stringify(strings, null, 2);
  }
  if (format === 'csv') {
    const header = 'Address,FileOffset,Section,Encoding,Length,Categories,References,Value';
    const rows = strings.map((s) =>
      [
        s.address,
        `0x${s.fileOffset.toString(16)}`,
        `"${s.section.replace(/"/g, '""')}"`,
        s.encoding,
        s.length,
        `"${s.categories.join(';')}"`,
        `"${s.functions.join(';')}"`,
        `"${s.value.replace(/"/g, '""')}"`,
      ].join(',')
    );
    return [header, ...rows].join('\n');
  }
  return strings
    .map((s) => `${s.address.padEnd(14)} [${s.encoding.padEnd(8)}] (${s.section.padEnd(10)}) ${s.value}`)
    .join('\n');
}

export function formatFunctionsExport(functions: FunctionInfo[], format: 'json' | 'csv' | 'names'): string {
  if (format === 'names') {
    return JSON.stringify(
      functions.map((f) => ({
        address: f.address,
        name: f.customName || f.name,
        originalName: f.originalName,
        autoName: f.autoName,
        comment: f.comment || '',
      })),
      null,
      2
    );
  }
  if (format === 'csv') {
    const header = 'Address,Name,OriginalName,AutoName,Size,BasicBlocks,Category,Callers,Callees,Signature';
    const rows = functions.map((f) =>
      [
        f.address,
        `"${(f.customName || f.name).replace(/"/g, '""')}"`,
        `"${f.originalName.replace(/"/g, '""')}"`,
        `"${f.autoName.replace(/"/g, '""')}"`,
        f.size,
        f.basicBlocksCount,
        f.category,
        f.callersCount,
        f.calleesCount,
        `"${f.signature.replace(/"/g, '""')}"`,
      ].join(',')
    );
    return [header, ...rows].join('\n');
  }
  return JSON.stringify(functions, null, 2);
}

export function generateMarkdownReport(
  analysis: AnalysisResult,
  decompA: DecompilationResult | null,
  decompB: DecompilationResult | null
): string {
  const m = analysis.metadata;
  return `# Binary Reverse Engineering Report — ${m.filename}
Generated locally by **Spet's Easy Decompiler** (100% Client-Side WebAssembly)

## 1. Binary Metadata
| Property | Value |
| :--- | :--- |
| **Filename** | \`${m.filename}\` |
| **Size** | ${m.size.toLocaleString()} bytes |
| **SHA-256** | \`${m.sha256}\` |
| **Format** | ${m.format} |
| **Architecture** | ${m.architecture} (${m.bits}-bit, ${m.endianness}-endian) |
| **Entry Point** | \`${m.entryPoint}\` |
| **Base Address** | \`${m.baseAddress}\` |
| **OS / ABI** | ${m.os} / ${m.abi} |
| **Compiler / Toolchain** | ${m.compiler} |
| **Symbols / Stripped** | Symbols: ${m.hasSymbols ? 'Yes' : 'No'} · Stripped: ${m.isStripped ? 'Yes' : 'No'} |
| **Entropy / Packing** | ${m.entropy.toFixed(2)} bits/byte (${m.packerDetails}) |

## 2. Sections (${analysis.sections.length})
| Name | VAddr | File Offset | Size | Permissions | Entropy |
| :--- | :--- | :--- | ---: | :--- | ---: |
${analysis.sections
  .map(
    (s) =>
      `| \`${s.name}\` | \`${s.virtualAddress}\` | \`${s.fileOffset}\` | ${s.size} | \`${s.permissions}\` | ${s.entropy.toFixed(2)} |`
  )
  .join('\n')}

## 3. Discovered Functions (${analysis.functions.length})
| Address | Active Name | Original Name | Size | Blocks | Category |
| :--- | :--- | :--- | ---: | ---: | :--- |
${analysis.functions
  .map(
    (f) =>
      `| \`${f.address}\` | \`${f.customName || f.name}\` | \`${f.originalName}\` | ${f.size} B | ${f.basicBlocksCount} | ${f.category} |`
  )
  .join('\n')}

## 4. Imports (${analysis.imports.length}) & Exports (${analysis.exports.length})
### Imports
${
  analysis.imports.length > 0
    ? analysis.imports.map((imp) => `- \`${imp.address}\` **${imp.name}** (${imp.library})`).join('\n')
    : '_No imports indexed_'
}

### Exports
${
  analysis.exports.length > 0
    ? analysis.exports.map((exp) => `- \`${exp.address}\` **${exp.name}** (${exp.size} B)`).join('\n')
    : '_No exports indexed_'
}

## 5. Dual Decompiler C-like Output Comparison
### Decompiler A: ${decompA ? `${decompA.engineName} (${decompA.engineVersion}) — ${decompA.durationMs} ms` : 'Not executed'}
\`\`\`c
${decompA?.code || '// Not generated'}
\`\`\`

### Decompiler B: ${decompB ? `${decompB.engineName} (${decompB.engineVersion}) — ${decompB.durationMs} ms` : 'Not executed'}
\`\`\`c
${decompB?.code || '// Not generated'}
\`\`\`

## 6. Extracted Strings (${analysis.strings.length})
${analysis.strings
  .slice(0, 100)
  .map((s) => `- \`${s.address}\` [${s.encoding}] (${s.categories.join(', ')}): \`${s.value}\``)
  .join('\n')}
`;
}

export function generateCfgSvg(cfg: CfgData): string {
  const width = 880;
  const blockHeight = 140;
  const gapY = 48;
  const height = Math.max(320, cfg.blocks.length * (blockHeight + gapY) + 80);

  const blockNodes = cfg.blocks.map((b, i) => {
    const x = i % 2 === 0 ? 80 : 460;
    const y = 40 + i * (blockHeight + gapY);
    return { ...b, x, y, w: 340, h: blockHeight };
  });

  const nodeMap = new Map(blockNodes.map((n) => [n.address, n]));
  const edgesSvg = cfg.edges
    .map((e) => {
      const from = nodeMap.get(e.from);
      const to = nodeMap.get(e.to);
      if (!from || !to) return '';
      const color = e.type === 'true' ? '#10B981' : e.type === 'false' ? '#EF4444' : '#00E5FF';
      const x1 = from.x + from.w / 2;
      const y1 = from.y + from.h;
      const x2 = to.x + to.w / 2;
      const y2 = to.y;
      return `<path d="M ${x1} ${y1} C ${x1} ${(y1 + y2) / 2}, ${x2} ${(y1 + y2) / 2}, ${x2} ${y2}" fill="none" stroke="${color}" stroke-width="2" />`;
    })
    .join('\n');

  const rectsSvg = blockNodes
    .map((n) => {
      const lines = n.instructions
        .slice(0, 5)
        .map(
          (ins, idx) =>
            `<text x="${n.x + 12}" y="${n.y + 44 + idx * 18}" fill="#E2E8F0" font-family="monospace" font-size="11">${ins.address}  ${ins.disasm
              .replace(/&/g, '&amp;')
              .replace(/</g, '&lt;')
              .replace(/>/g, '&gt;')}</text>`
        )
        .join('\n');
      return `<g>
        <rect x="${n.x}" y="${n.y}" width="${n.w}" height="${n.h}" rx="6" fill="#0B0F17" stroke="#00E5FF" stroke-opacity="0.5" stroke-width="1.5" />
        <text x="${n.x + 12}" y="${n.y + 22}" fill="#00E5FF" font-family="monospace" font-weight="bold" font-size="12">${n.label} (${n.address})</text>
        ${lines}
      </g>`;
    })
    .join('\n');

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" width="${width}" height="${height}" style="background:#05070B">
    ${edgesSvg}
    ${rectsSvg}
  </svg>`;
}

export function generateCallGraphSvg(cg: CallGraphData): string {
  const width = 900;
  const height = Math.max(360, cg.nodes.length * 70 + 80);
  const positioned = cg.nodes.map((n, i) => ({
    ...n,
    x: 100 + (n.depth % 3) * 260,
    y: 50 + i * 64,
    w: 210,
    h: 42,
  }));
  const map = new Map(positioned.map((n) => [n.address, n]));
  const edges = cg.edges
    .map((e) => {
      const a = map.get(e.from);
      const b = map.get(e.to);
      if (!a || !b) return '';
      return `<line x1="${a.x + a.w}" y1="${a.y + a.h / 2}" x2="${b.x}" y2="${b.y + b.h / 2}" stroke="#00E5FF" stroke-width="1.5" stroke-opacity="0.7" />`;
    })
    .join('\n');
  const nodes = positioned
    .map(
      (n) => `<g>
      <rect x="${n.x}" y="${n.y}" width="${n.w}" height="${n.h}" rx="5" fill="#0B0F17" stroke="#8B5CF6" stroke-width="1.5" />
      <text x="${n.x + 10}" y="${n.y + 18}" fill="#E2E8F0" font-family="monospace" font-size="11" font-weight="bold">${n.name}</text>
      <text x="${n.x + 10}" y="${n.y + 34}" fill="#94A3B8" font-family="monospace" font-size="10">${n.address} · ${n.category}</text>
    </g>`
    )
    .join('\n');
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" width="${width}" height="${height}" style="background:#05070B">${edges}${nodes}</svg>`;
}

export function serializeProjectBundle(project: SavedProject): string {
  return JSON.stringify(project, null, 2);
}
