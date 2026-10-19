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
      <div className="flex h-full items-center justify-center text-xs text-slate-400 font-mono">
        Open a binary file to inspect raw hex bytes.
      </div>
    );
  }

  const handleJump = (e: React.FormEvent) => {
    e.preventDefault();
    const clean = jumpInput.trim().replace(/^0x/i, '');
    const parsed = parseInt(clean, 16);
    if (!Number.isNaN(parsed)) {
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
    <div className="flex h-full flex-col overflow-hidden bg-[#06090f]">
      {/* Controls */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#182232] bg-[#0c121d] px-2.5 py-1 text-xs shrink-0 select-none">
        <div className="flex items-center gap-2">
          <form onSubmit={handleJump} className="flex items-center gap-1">
            <input
              type="text"
              value={jumpInput}
              onChange={(e) => setJumpInput(e.target.value)}
              placeholder="Jump 0x offset/vaddr"
              className="w-44 bg-[#06090f] border border-[#182232] px-2 py-0.5 text-[11px] font-mono text-slate-200 placeholder:text-slate-600 focus:border-[#38bdf8] focus:outline-none"
            />
            <button
              type="submit"
              className="inline-flex items-center gap-1 border border-[#182232] bg-[#111a29] px-2 py-0.5 text-[10px] font-mono text-[#38bdf8] hover:border-[#38bdf8]"
            >
              Go <ArrowRight className="h-2.5 w-2.5" />
            </button>
          </form>

          <form onSubmit={handleSearch} className="flex items-center gap-1">
            <div className="relative">
              <Search className="pointer-events-none absolute left-2 top-1.5 h-3 w-3 text-slate-600" />
              <input
                type="text"
                value={searchHex}
                onChange={(e) => setSearchHex(e.target.value)}
                placeholder="Find hex or ASCII..."
                className="w-44 bg-[#06090f] border border-[#182232] pl-6 pr-2 py-0.5 text-[11px] font-mono text-slate-200 placeholder:text-slate-600 focus:border-[#38bdf8] focus:outline-none"
              />
            </div>
          </form>
        </div>

        {/* Section Quick Jump */}
        <div className="flex items-center gap-1">
          {sections.slice(0, 5).map((s) => (
            <button
              key={s.name}
              type="button"
              onClick={() => {
                setPageOffset(Math.floor(s.fileOffsetNum / 16) * 16);
                setHighlightOffset(s.fileOffsetNum);
              }}
              className="border border-[#182232] bg-[#090d14] px-1.5 py-0.5 font-mono text-[10px] text-slate-300 hover:border-[#38bdf8] hover:text-[#38bdf8]"
            >
              {s.name}
            </button>
          ))}
          <div className="ml-1 flex items-center gap-1">
            <button
              type="button"
              onClick={() => setPageOffset((p) => Math.max(0, p - pageBytes))}
              className="border border-[#182232] bg-[#090d14] px-1.5 py-0.5 text-[10px] font-mono text-slate-300 hover:text-white"
            >
              Prev
            </button>
            <button
              type="button"
              onClick={() =>
                setPageOffset((p) => Math.min(Math.max(0, data.length - pageBytes), p + pageBytes))
              }
              className="border border-[#182232] bg-[#090d14] px-1.5 py-0.5 text-[10px] font-mono text-slate-300 hover:text-white"
            >
              Next
            </button>
          </div>
        </div>
      </div>

      {/* Hex Table */}
      <div className={`flex-1 overflow-auto p-2 text-xs leading-5 ${fontClass}`}>
        <div className="mb-1 flex border-b border-[#182232] pb-1 text-[11px] font-semibold text-[#64748b]">
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
              className={`flex items-center px-1 py-0.2 ${
                isHighlightedRow ? 'bg-[#38bdf8]/15' : 'hover:bg-white/[0.03]'
              }`}
            >
              <span className="w-24 select-all text-[#38bdf8]">
                0x{row.offset.toString(16).padStart(8, '0')}
              </span>
              <span className="w-[390px] text-slate-300">
                {row.hex.map((h, i) => (
                  <React.Fragment key={i}>
                    <span
                      className={
                        h === '00'
                          ? 'text-[#475569]'
                          : h === 'ff'
                            ? 'text-[#f59e0b]'
                            : 'text-[#e2e8f0]'
                      }
                    >
                      {h}
                    </span>
                    {i === 7 ? '  ' : ' '}
                  </React.Fragment>
                ))}
              </span>
              <span className="tracking-wider text-[#34d399]">{row.ascii}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
};
