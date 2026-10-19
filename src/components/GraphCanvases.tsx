import React, { useMemo, useState } from 'react';
import { ZoomIn, ZoomOut, RotateCcw, Download } from 'lucide-react';
import type { CallGraphData, CfgData } from '../types';
import { downloadLocalBlob, generateCallGraphSvg, generateCfgSvg } from '../analysis/report-export';

interface CfgCanvasViewProps {
  cfg: CfgData | null;
  onSelectAddress?: (addr: string) => void;
}

export const CfgCanvasView: React.FC<CfgCanvasViewProps> = ({ cfg, onSelectAddress }) => {
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [dragging, setDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
  const [selectedBlock, setSelectedBlock] = useState<string | null>(null);

  const layout = useMemo(() => {
    if (!cfg || cfg.blocks.length === 0) return { nodes: [], edges: [], width: 900, height: 500 };

    const blockW = 360;
    const gapY = 56;
    let currentY = 36;

    const nodes = cfg.blocks.map((b, idx) => {
      const insCount = Math.min(b.instructions.length, 10);
      const blockH = Math.max(92, 42 + insCount * 18);
      const colOffset = cfg.blocks.length === 1 ? 260 : idx % 2 === 0 ? 70 : 470;
      const node = {
        ...b,
        x: colOffset,
        y: currentY,
        w: blockW,
        h: blockH,
      };
      currentY += blockH + gapY;
      return node;
    });

    const map = new Map(nodes.map((n) => [n.address, n]));
    const edges = cfg.edges
      .map((e) => {
        const from = map.get(e.from);
        const to = map.get(e.to);
        if (!from || !to) return null;
        return { ...e, fromNode: from, toNode: to };
      })
      .filter(Boolean) as Array<{
      from: string;
      to: string;
      type: 'true' | 'false' | 'unconditional' | 'loop';
      fromNode: (typeof nodes)[0];
      toNode: (typeof nodes)[0];
    }>;

    return {
      nodes,
      edges,
      width: 920,
      height: Math.max(480, currentY + 60),
    };
  }, [cfg]);

  if (!cfg || cfg.blocks.length === 0) {
    return (
      <div className="flex h-full items-center justify-center text-xs text-slate-400">
        Select a function to inspect its Control Flow Graph (CFG).
      </div>
    );
  }

  return (
    <div className="relative flex h-full w-full flex-col overflow-hidden bg-[#05070B]">
      {/* Toolbar */}
      <div className="z-10 flex items-center justify-between border-b border-white/10 bg-[#0B0F17]/90 px-3 py-1.5 text-xs">
        <div className="flex items-center gap-3">
          <span className="font-mono-jetbrains font-semibold text-[#00E5FF]">
            CFG: {cfg.functionName} ({cfg.functionAddress})
          </span>
          <span className="text-slate-400">
            {cfg.blocks.length} basic blocks · {cfg.edges.length} edges
          </span>
          <div className="hidden items-center gap-2 sm:flex">
            <span className="inline-flex items-center gap-1 text-[11px] text-emerald-400">
              <span className="h-2 w-2 rounded-full bg-emerald-400" /> True Branch
            </span>
            <span className="inline-flex items-center gap-1 text-[11px] text-rose-400">
              <span className="h-2 w-2 rounded-full bg-rose-400" /> False Branch
            </span>
            <span className="inline-flex items-center gap-1 text-[11px] text-[#00E5FF]">
              <span className="h-2 w-2 rounded-full bg-[#00E5FF]" /> Unconditional
            </span>
          </div>
        </div>
        <div className="flex items-center gap-1">
          <button
            type="button"
            onClick={() => setZoom((z) => Math.min(2.2, +(z + 0.15).toFixed(2)))}
            className="rounded border border-white/10 bg-white/5 p-1 text-slate-300 hover:border-[#00E5FF]/50 hover:text-white"
            title="Zoom In"
          >
            <ZoomIn className="h-3.5 w-3.5" />
          </button>
          <button
            type="button"
            onClick={() => setZoom((z) => Math.max(0.4, +(z - 0.15).toFixed(2)))}
            className="rounded border border-white/10 bg-white/5 p-1 text-slate-300 hover:border-[#00E5FF]/50 hover:text-white"
            title="Zoom Out"
          >
            <ZoomOut className="h-3.5 w-3.5" />
          </button>
          <button
            type="button"
            onClick={() => {
              setZoom(1);
              setPan({ x: 0, y: 0 });
            }}
            className="rounded border border-white/10 bg-white/5 p-1 text-slate-300 hover:border-[#00E5FF]/50 hover:text-white"
            title="Reset View"
          >
            <RotateCcw className="h-3.5 w-3.5" />
          </button>
          <button
            type="button"
            onClick={() => {
              const svg = generateCfgSvg(cfg);
              downloadLocalBlob(svg, `${cfg.functionName}-cfg.svg`, 'image/svg+xml');
            }}
            className="ml-1 inline-flex items-center gap-1 rounded border border-[#00E5FF]/30 bg-[#00E5FF]/10 px-2 py-1 text-[11px] font-medium text-[#00E5FF] hover:bg-[#00E5FF]/20"
          >
            <Download className="h-3 w-3" /> SVG
          </button>
        </div>
      </div>

      {/* Interactive SVG Canvas */}
      <div
        className="relative flex-1 cursor-grab overflow-auto active:cursor-grabbing"
        onMouseDown={(e) => {
          setDragging(true);
          setDragStart({ x: e.clientX - pan.x, y: e.clientY - pan.y });
        }}
        onMouseMove={(e) => {
          if (!dragging) return;
          setPan({ x: e.clientX - dragStart.x, y: e.clientY - dragStart.y });
        }}
        onMouseUp={() => setDragging(false)}
        onMouseLeave={() => setDragging(false)}
      >
        <svg
          width={layout.width * zoom}
          height={layout.height * zoom}
          viewBox={`0 0 ${layout.width} ${layout.height}`}
          style={{
            transform: `translate(${pan.x}px, ${pan.y}px)`,
            transition: dragging ? 'none' : 'transform 120ms ease-out',
          }}
          className="select-none"
        >
          <defs>
            <marker
              id="arrow-true"
              viewBox="0 0 10 10"
              refX="6"
              refY="5"
              markerWidth="6"
              markerHeight="6"
              orient="auto-start-reverse"
            >
              <path d="M 0 0 L 10 5 L 0 10 z" fill="#10B981" />
            </marker>
            <marker
              id="arrow-false"
              viewBox="0 0 10 10"
              refX="6"
              refY="5"
              markerWidth="6"
              markerHeight="6"
              orient="auto-start-reverse"
            >
              <path d="M 0 0 L 10 5 L 0 10 z" fill="#EF4444" />
            </marker>
            <marker
              id="arrow-uncond"
              viewBox="0 0 10 10"
              refX="6"
              refY="5"
              markerWidth="6"
              markerHeight="6"
              orient="auto-start-reverse"
            >
              <path d="M 0 0 L 10 5 L 0 10 z" fill="#00E5FF" />
            </marker>
          </defs>

          {/* Edges */}
          {layout.edges.map((e, i) => {
            const x1 = e.fromNode.x + e.fromNode.w / 2;
            const y1 = e.fromNode.y + e.fromNode.h;
            const x2 = e.toNode.x + e.toNode.w / 2;
            const y2 = e.toNode.y;
            const stroke =
              e.type === 'true' ? '#10B981' : e.type === 'false' ? '#EF4444' : '#00E5FF';
            const marker =
              e.type === 'true'
                ? 'url(#arrow-true)'
                : e.type === 'false'
                  ? 'url(#arrow-false)'
                  : 'url(#arrow-uncond)';
            const midY = (y1 + y2) / 2;
            return (
              <path
                key={`${e.from}-${e.to}-${i}`}
                d={`M ${x1} ${y1} C ${x1} ${midY}, ${x2} ${midY}, ${x2} ${y2}`}
                fill="none"
                stroke={stroke}
                strokeWidth={2}
                strokeDasharray={e.type === 'loop' ? '5,4' : undefined}
                markerEnd={marker}
              />
            );
          })}

          {/* Blocks */}
          {layout.nodes.map((node) => {
            const isSelected = selectedBlock === node.address;
            const borderColor = node.isEntry
              ? '#00E5FF'
              : node.isExit
                ? '#8B5CF6'
                : isSelected
                  ? '#F59E0B'
                  : '#334155';
            return (
              <g
                key={node.address}
                onClick={(ev) => {
                  ev.stopPropagation();
                  setSelectedBlock(node.address);
                  onSelectAddress?.(node.address);
                }}
                className="cursor-pointer"
              >
                <rect
                  x={node.x}
                  y={node.y}
                  width={node.w}
                  height={node.h}
                  rx={6}
                  fill="#0B0F17"
                  stroke={borderColor}
                  strokeWidth={isSelected ? 2.2 : 1.4}
                />
                <rect
                  x={node.x}
                  y={node.y}
                  width={node.w}
                  height={26}
                  rx={6}
                  fill={node.isEntry ? 'rgba(0, 229, 255, 0.14)' : 'rgba(139, 92, 246, 0.12)'}
                />
                <text
                  x={node.x + 10}
                  y={node.y + 17}
                  fill={node.isEntry ? '#00E5FF' : '#E2E8F0'}
                  fontFamily="JetBrains Mono, monospace"
                  fontSize="11.5"
                  fontWeight="bold"
                >
                  {node.label} @ {node.address} ({node.size}B)
                </text>
                {node.instructions.slice(0, 10).map((ins, idx) => (
                  <text
                    key={`${ins.address}-${idx}`}
                    x={node.x + 10}
                    y={node.y + 42 + idx * 17}
                    fill="#CBD5E1"
                    fontFamily="JetBrains Mono, monospace"
                    fontSize="11"
                  >
                    <tspan fill="#64748B">{ins.address.padEnd(10)}</tspan>{' '}
                    <tspan fill="#E2E8F0">{ins.disasm.slice(0, 38)}</tspan>
                  </text>
                ))}
              </g>
            );
          })}
        </svg>
      </div>
    </div>
  );
};

interface CallGraphCanvasViewProps {
  callGraph: CallGraphData | null;
  selectedAddress?: string;
  onSelectFunction: (address: string) => void;
}

export const CallGraphCanvasView: React.FC<CallGraphCanvasViewProps> = ({
  callGraph,
  selectedAddress,
  onSelectFunction,
}) => {
  const [zoom, setZoom] = useState(1);

  if (!callGraph || callGraph.nodes.length === 0) {
    return (
      <div className="flex h-full items-center justify-center text-xs text-slate-400">
        No call graph nodes available.
      </div>
    );
  }

  const nodes = callGraph.nodes.map((n, idx) => {
    const col = idx % 3;
    const row = Math.floor(idx / 3);
    return {
      ...n,
      x: 50 + col * 280,
      y: 44 + row * 86,
      w: 230,
      h: 50,
    };
  });

  const nodeMap = new Map(nodes.map((n) => [n.address, n]));
  const height = Math.max(420, Math.ceil(nodes.length / 3) * 95 + 80);

  return (
    <div className="flex h-full w-full flex-col overflow-hidden bg-[#05070B]">
      <div className="flex items-center justify-between border-b border-white/10 bg-[#0B0F17]/90 px-3 py-1.5 text-xs">
        <div className="flex items-center gap-3">
          <span className="font-mono-jetbrains font-semibold text-[#8B5CF6]">
            Interactive Call Graph
          </span>
          <span className="text-slate-400">
            {callGraph.nodes.length} functions · {callGraph.edges.length} call edges
          </span>
        </div>
        <div className="flex items-center gap-1">
          <button
            type="button"
            onClick={() => setZoom((z) => Math.min(2, +(z + 0.15).toFixed(2)))}
            className="rounded border border-white/10 bg-white/5 p-1 text-slate-300 hover:text-white"
          >
            <ZoomIn className="h-3.5 w-3.5" />
          </button>
          <button
            type="button"
            onClick={() => setZoom((z) => Math.max(0.5, +(z - 0.15).toFixed(2)))}
            className="rounded border border-white/10 bg-white/5 p-1 text-slate-300 hover:text-white"
          >
            <ZoomOut className="h-3.5 w-3.5" />
          </button>
          <button
            type="button"
            onClick={() => {
              const svg = generateCallGraphSvg(callGraph);
              downloadLocalBlob(svg, 'callgraph.svg', 'image/svg+xml');
            }}
            className="ml-1 inline-flex items-center gap-1 rounded border border-[#8B5CF6]/40 bg-[#8B5CF6]/15 px-2 py-1 text-[11px] font-medium text-[#C4B5FD] hover:bg-[#8B5CF6]/25"
          >
            <Download className="h-3 w-3" /> SVG
          </button>
        </div>
      </div>

      <div className="flex-1 overflow-auto p-2">
        <svg
          width={920 * zoom}
          height={height * zoom}
          viewBox={`0 0 920 ${height}`}
          className="select-none"
        >
          {callGraph.edges.map((e, idx) => {
            const a = nodeMap.get(e.from);
            const b = nodeMap.get(e.to);
            if (!a || !b) return null;
            return (
              <path
                key={`${e.from}-${e.to}-${idx}`}
                d={`M ${a.x + a.w / 2} ${a.y + a.h} C ${a.x + a.w / 2} ${(a.y + b.y) / 2}, ${
                  b.x + b.w / 2
                } ${(a.y + b.y) / 2}, ${b.x + b.w / 2} ${b.y}`}
                fill="none"
                stroke="#00E5FF"
                strokeOpacity={0.65}
                strokeWidth={1.8}
              />
            );
          })}

          {nodes.map((n) => {
            const active = selectedAddress?.toLowerCase() === n.address.toLowerCase();
            return (
              <g
                key={n.address}
                onClick={() => onSelectFunction(n.address)}
                className="cursor-pointer"
              >
                <rect
                  x={n.x}
                  y={n.y}
                  width={n.w}
                  height={n.h}
                  rx={6}
                  fill={active ? 'rgba(0, 229, 255, 0.14)' : '#0B0F17'}
                  stroke={active ? '#00E5FF' : '#8B5CF6'}
                  strokeWidth={active ? 2.2 : 1.4}
                />
                <text
                  x={n.x + 12}
                  y={n.y + 21}
                  fill={active ? '#00E5FF' : '#E2E8F0'}
                  fontFamily="JetBrains Mono, monospace"
                  fontSize="12"
                  fontWeight="bold"
                >
                  {n.name.slice(0, 24)}
                </text>
                <text
                  x={n.x + 12}
                  y={n.y + 38}
                  fill="#94A3B8"
                  fontFamily="JetBrains Mono, monospace"
                  fontSize="10.5"
                >
                  {n.address} · {n.category}
                </text>
              </g>
            );
          })}
        </svg>
      </div>
    </div>
  );
};
