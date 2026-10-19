import React, { useMemo, useState } from 'react';
import { Search, ArrowRight } from 'lucide-react';
import type { SectionInfo } from '../types';

interface HexViewerPaneProps {
  data: Uint8Array | null;
  sections: SectionInfo[];
  fontClass: string;
}

export const HexViewerPane: React.FC<HexViewerPaneProps> = ({ data, sections, fontClass }) => {
  const [pageOffset, setPageOffset] = useState(0);
  const [jumpInput, setJumpInput] = useState('');
  const [searchHex, setSearchHex] = useState('');
  const [highlightOffset, setHighlightOffset] = useState<number | null>(null);

  const bytesPerRow = 16;
  const rowsPerPage = 36;
  const pageBytes = bytesPerRow * rowsPerPage;

  const rows = useMemo(() => {
    if (!data) return [];
    const start = Math.max(0, Math.min(pageOffset, Math.max(0, data.length - 16)));
    const end = Math.min(data.length, start + pageBytes);
    const out: Array<{
      offset: number;
      hex: string[];
      ascii: string;
    }> = [];

    for (let off = start; off < end; off += bytesPerRow) {
      const slice = data.subarray(off, Math.min(data.length, off + bytesPerRow));
      const hex: string[] = [];
      let ascii = '';
      for (let i = 0; i < slice.length; i++) {
        const b = slice[i];
        hex.push(b.toString(16).padStart(2, '0'));
        ascii += b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : '.';
      }
      out.push({ offset: off, hex, ascii });
    }
    return out;
  }, [data, pageOffset, pageBytes]);

  if (!data) {
    return (
      <div className="flex h-full items-center justify-center text-xs text-slate-400">
        Open a binary file to inspect raw hex bytes.
      </div>
    );
  }

  const handleJump = (e: React.FormEvent) => {
    e.preventDefault();
    const clean = jumpInput.trim().replace(/^0x/i, '');
    const parsed = parseInt(clean, 16);
    if (!Number.isNaN(parsed)) {
      // Check if user entered a virtual address inside a section
      let fileOff = parsed;
      for (const sec of sections) {
        if (
          parsed >= sec.virtualAddressNum &&
          parsed < sec.virtualAddressNum + Math.max(sec.size, sec.virtualSize)
        ) {
          fileOff = sec.fileOffsetNum + (parsed - sec.virtualAddressNum);
          break;
        }
      }
      const clamped = Math.max(0, Math.min(data.length - 16, Math.floor(fileOff / 16) * 16));
      setPageOffset(clamped);
      setHighlightOffset(fileOff);
    }
  };

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    const q = searchHex.trim();
    if (!q) return;

    // Search either hex byte sequence ("7f 45 4c 46") or ASCII substring
    const isHexPattern = /^[0-9a-fA-F\s]+$/.test(q) && q.replace(/\s+/g, '').length % 2 === 0;
    let needle: Uint8Array;
    if (isHexPattern) {
      const cleanHex = q.replace(/\s+/g, '');
      const arr = new Uint8Array(cleanHex.length / 2);
      for (let i = 0; i < arr.length; i++) {
        arr[i] = parseInt(cleanHex.slice(i * 2, i * 2 + 2), 16);
      }
      needle = arr;
    } else {
      needle = new TextEncoder().encode(q);
    }

    for (let i = 0; i <= data.length - needle.length; i++) {
      let match = true;
      for (let j = 0; j < needle.length; j++) {
        if (data[i + j] !== needle[j]) {
          match = false;
          break;
        }
      }
      if (match) {
        setPageOffset(Math.floor(i / 16) * 16);
        setHighlightOffset(i);
        break;
      }
    }
  };

  return (
    <div className="flex h-full flex-col overflow-hidden bg-[#05070B]">
      {/* Controls */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/10 bg-[#0B0F17] px-3 py-2 text-xs">
        <div className="flex items-center gap-2">
          <form onSubmit={handleJump} className="flex items-center gap-1">
            <input
              type="text"
              value={jumpInput}
              onChange={(e) => setJumpInput(e.target.value)}
              placeholder="Jump offset/vaddr (e.g. 0x1000)"
              className="w-48 rounded border border-white/10 bg-[#05070B] px-2 py-1 text-xs text-slate-200 focus:border-[#00E5FF] focus:outline-none"
            />
            <button
              type="submit"
              className="inline-flex items-center gap-1 rounded border border-[#00E5FF]/30 bg-[#00E5FF]/10 px-2 py-1 text-[#00E5FF] hover:bg-[#00E5FF]/20"
            >
              Go <ArrowRight className="h-3 w-3" />
            </button>
          </form>

          <form onSubmit={handleSearch} className="flex items-center gap-1">
            <div className="relative">
              <Search className="pointer-events-none absolute left-2 top-1.5 h-3.5 w-3.5 text-slate-500" />
              <input
                type="text"
                value={searchHex}
                onChange={(e) => setSearchHex(e.target.value)}
                placeholder="Find hex (7f 45) or ASCII..."
                className="w-48 rounded border border-white/10 bg-[#05070B] pl-7 pr-2 py-1 text-xs text-slate-200 focus:border-[#00E5FF] focus:outline-none"
              />
            </div>
          </form>
        </div>

        {/* Section Quick Jump */}
        <div className="flex items-center gap-1.5">
          {sections.slice(0, 5).map((s) => (
            <button
              key={s.name}
              type="button"
              onClick={() => {
                setPageOffset(Math.floor(s.fileOffsetNum / 16) * 16);
                setHighlightOffset(s.fileOffsetNum);
              }}
              className="rounded border border-white/10 bg-white/5 px-2 py-0.5 font-mono-jetbrains text-[11px] text-slate-300 hover:border-[#00E5FF]/40 hover:text-[#00E5FF]"
            >
              {s.name}
            </button>
          ))}
          <div className="ml-2 flex items-center gap-1">
            <button
              type="button"
              onClick={() => setPageOffset((p) => Math.max(0, p - pageBytes))}
              className="rounded border border-white/10 bg-white/5 px-2 py-0.5 text-slate-300 hover:text-white"
            >
              Prev
            </button>
            <button
              type="button"
              onClick={() =>
                setPageOffset((p) => Math.min(Math.max(0, data.length - pageBytes), p + pageBytes))
              }
              className="rounded border border-white/10 bg-white/5 px-2 py-0.5 text-slate-300 hover:text-white"
            >
              Next
            </button>
          </div>
        </div>
      </div>

      {/* Hex Table */}
      <div className={`flex-1 overflow-auto p-3 text-xs leading-5 ${fontClass}`}>
        <div className="mb-1 flex border-b border-white/10 pb-1 text-[11px] font-semibold text-slate-500">
          <span className="w-24">OFFSET</span>
          <span className="w-[390px]">00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F</span>
          <span>ASCII</span>
        </div>
        {rows.map((row) => {
          const isHighlightedRow =
            highlightOffset !== null &&
            highlightOffset >= row.offset &&
            highlightOffset < row.offset + 16;
          return (
            <div
              key={row.offset}
              className={`flex items-center rounded px-1 py-0.5 ${
                isHighlightedRow ? 'bg-[#00E5FF]/15' : 'hover:bg-white/[0.03]'
              }`}
            >
              <span className="w-24 select-all text-[#00E5FF]">
                0x{row.offset.toString(16).padStart(8, '0')}
              </span>
              <span className="w-[390px] text-slate-200">
                {row.hex.map((h, i) => (
                  <React.Fragment key={i}>
                    <span
                      className={
                        h === '00'
                          ? 'text-slate-600'
                          : h === 'ff'
                            ? 'text-amber-400'
                            : 'text-slate-200'
                      }
                    >
                      {h}
                    </span>
                    {i === 7 ? '  ' : ' '}
                  </React.Fragment>
                ))}
              </span>
              <span className="tracking-wider text-emerald-400/90">{row.ascii}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
};
