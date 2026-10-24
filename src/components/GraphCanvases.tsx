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
      <div className="flex h-full items-center justify-center text-xs text-slate-400 font-mono">
        Select a function to inspect its Control Flow Graph (CFG).
      </div>
    );
  }

  return (
    <div className="relative flex h-full w-full flex-col overflow-hidden bg-[#06090f]">

      <div className="z-10 flex items-center justify-between border-b border-[#182232] bg-[#0c121d] px-2.5 py-1 text-xs shrink-0 select-none">
        <div className="flex items-center gap-3">
          <span className="font-mono font-semibold text-[#38bdf8]">
            CFG: {cfg.functionName} ({cfg.functionAddress})
          </span>
          <span className="text-[#64748b] font-mono text-[11px]">
            {cfg.blocks.length} basic blocks · {cfg.edges.length} edges
          </span>
          <div className="hidden items-center gap-2 sm:flex">
            <span className="inline-flex items-center gap-1 text-[10px] font-mono text-[#34d399]">
              <span className="h-1.5 w-1.5 bg-[#34d399]" /> True Branch
            </span>
            <span className="inline-flex items-center gap-1 text-[10px] font-mono text-[#f87171]">
              <span className="h-1.5 w-1.5 bg-[#f87171]" /> False Branch
            </span>
            <span className="inline-flex items-center gap-1 text-[10px] font-mono text-[#38bdf8]">
              <span className="h-1.5 w-1.5 bg-[#38bdf8]" /> Unconditional
            </span>
          </div>
        </div>
        <div className="flex items-center gap-1">
          <button
            type="button"
            onClick={() => setZoom((z) => Math.min(2.2, +(z + 0.15).toFixed(2)))}
            className="border border-[#182232] bg-[#090d14] p-1 text-slate-300 hover:border-[#38bdf8] hover:text-white"
            title="Zoom In"
          >
            <ZoomIn className="h-3 w-3" />
          </button>
          <button
            type="button"
            onClick={() => setZoom((z) => Math.max(0.4, +(z - 0.15).toFixed(2)))}
            className="border border-[#182232] bg-[#090d14] p-1 text-slate-300 hover:border-[#38bdf8] hover:text-white"
            title="Zoom Out"
          >
            <ZoomOut className="h-3 w-3" />
          </button>
          <button
            type="button"
            onClick={() => {
              setZoom(1);
              setPan({ x: 0, y: 0 });
            }}
            className="border border-[#182232] bg-[#090d14] p-1 text-slate-300 hover:border-[#38bdf8] hover:text-white"
            title="Reset View"
          >
            <RotateCcw className="h-3 w-3" />
          </button>
          <button
            type="button"
            onClick={() => {
              const svg = generateCfgSvg(cfg);
              downloadLocalBlob(svg, `${cfg.functionName}-cfg.svg`, 'image/svg+xml');
            }}
            className="ml-1 inline-flex items-center gap-1 border border-[#182232] bg-[#111a29] px-2 py-0.5 text-[10px] font-mono text-[#38bdf8] hover:border-[#38bdf8]"
          >
            <Download className="h-2.5 w-2.5" /> SVG
          </button>
        </div>
      </div>

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
              <path d="M 0 0 L 10 5 L 0 10 z" fill="#34d399" />
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
              <path d="M 0 0 L 10 5 L 0 10 z" fill="#f87171" />
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
              <path d="M 0 0 L 10 5 L 0 10 z" fill="#38bdf8" />
            </marker>
          </defs>

          {layout.edges.map((e, i) => {
            const x1 = e.fromNode.x + e.fromNode.w / 2;
            const y1 = e.fromNode.y + e.fromNode.h;
            const x2 = e.toNode.x + e.toNode.w / 2;
            const y2 = e.toNode.y;
            const stroke =
              e.type === 'true' ? '#34d399' : e.type === 'false' ? '#f87171' : '#38bdf8';
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
                strokeWidth={1.6}
                strokeDasharray={e.type === 'loop' ? '5,4' : undefined}
                markerEnd={marker}
              />
            );
          })}

          {layout.nodes.map((node) => {
            const isSelected = selectedBlock === node.address;
            const borderColor = node.isEntry
              ? '#38bdf8'
              : node.isExit
                ? '#c084fc'
                : isSelected
                  ? '#f59e0b'
                  : '#182232';
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
                  rx={0}
                  fill="#090d14"
                  stroke={borderColor}
                  strokeWidth={isSelected ? 2 : 1}
                />
                <rect
                  x={node.x}
                  y={node.y}
                  width={node.w}
                  height={24}
                  rx={0}
                  fill={node.isEntry ? 'rgba(56, 189, 248, 0.15)' : 'rgba(192, 132, 252, 0.12)'}
                  stroke={borderColor}
                  strokeWidth={1}
                />
                <text
                  x={node.x + 8}
                  y={node.y + 16}
                  fill={node.isEntry ? '#38bdf8' : '#e2e8f0'}
                  fontFamily="'JetBrains Mono', monospace"
                  fontSize="11"
                  fontWeight="bold"
                >
                  {node.label} @ {node.address} ({node.size}B)
                </text>
                {node.instructions.slice(0, 10).map((ins, idx) => (
                  <text
                    key={`${ins.address}-${idx}`}
                    x={node.x + 8}
                    y={node.y + 39 + idx * 17}
                    fill="#cbd5e1"
                    fontFamily="'JetBrains Mono', monospace"
                    fontSize="11"
                  >
                    <tspan fill="#64748b">{ins.address.padEnd(10)}</tspan>{' '}
                    <tspan fill="#e2e8f0">{ins.disasm.slice(0, 38)}</tspan>
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
      <div className="flex h-full items-center justify-center text-xs text-slate-400 font-mono">
        No call graph nodes available.
      </div>
    );
  }

  const nodes = callGraph.nodes.map((n, idx) => {
    const col = idx % 3;
    const row = Math.floor(idx / 3);
    return {
      ...n,
      x: 40 + col * 280,
      y: 40 + row * 80,
      w: 240,
      h: 46,
    };
  });

  const nodeMap = new Map(nodes.map((n) => [n.address, n]));
  const height = Math.max(420, Math.ceil(nodes.length / 3) * 85 + 60);

  return (
    <div className="flex h-full w-full flex-col overflow-hidden bg-[#06090f]">
      <div className="flex items-center justify-between border-b border-[#182232] bg-[#0c121d] px-2.5 py-1 text-xs shrink-0 select-none">
        <div className="flex items-center gap-3">
          <span className="font-mono font-semibold text-[#c084fc]">
            Interactive Call Graph
          </span>
          <span className="text-[#64748b] font-mono text-[11px]">
            {callGraph.nodes.length} functions · {callGraph.edges.length} call edges
          </span>
        </div>
        <div className="flex items-center gap-1">
          <button
            type="button"
            onClick={() => setZoom((z) => Math.min(2, +(z + 0.15).toFixed(2)))}
            className="border border-[#182232] bg-[#090d14] p-1 text-slate-300 hover:text-white"
          >
            <ZoomIn className="h-3 w-3" />
          </button>
          <button
            type="button"
            onClick={() => setZoom((z) => Math.max(0.5, +(z - 0.15).toFixed(2)))}
            className="border border-[#182232] bg-[#090d14] p-1 text-slate-300 hover:text-white"
          >
            <ZoomOut className="h-3 w-3" />
          </button>
          <button
            type="button"
            onClick={() => {
              const svg = generateCallGraphSvg(callGraph);
              downloadLocalBlob(svg, 'callgraph.svg', 'image/svg+xml');
            }}
            className="ml-1 inline-flex items-center gap-1 border border-[#182232] bg-[#111a29] px-2 py-0.5 text-[10px] font-mono text-[#c084fc] hover:border-[#c084fc]"
          >
            <Download className="h-2.5 w-2.5" /> SVG
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
                stroke="#38bdf8"
                strokeOpacity={0.65}
                strokeWidth={1.5}
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
                  rx={0}
                  fill={active ? '#111a29' : '#090d14'}
                  stroke={active ? '#38bdf8' : '#182232'}
                  strokeWidth={active ? 2 : 1}
                />
                <text
                  x={n.x + 10}
                  y={n.y + 18}
                  fill={active ? '#38bdf8' : '#e2e8f0'}
                  fontFamily="'JetBrains Mono', monospace"
                  fontSize="11.5"
                  fontWeight="bold"
                >
                  {n.name.slice(0, 24)}
                </text>
                <text
                  x={n.x + 10}
                  y={n.y + 35}
                  fill="#64748b"
                  fontFamily="'JetBrains Mono', monospace"
                  fontSize="10"
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
