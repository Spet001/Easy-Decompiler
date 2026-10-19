import React from 'react';
import {
  X,
  RotateCcw,
  ShieldCheck,
  Cpu,
  Sliders,
  Keyboard,
  Lock,
} from 'lucide-react';
import type { AppSettings } from '../types';
import { DEFAULT_SETTINGS } from '../storage/local-db';

interface SettingsModalProps {
  open: boolean;
  settings: AppSettings;
  onUpdate: (next: AppSettings) => void;
  onClose: () => void;
}

export const SettingsModal: React.FC<SettingsModalProps> = ({
  open,
  settings,
  onUpdate,
  onClose,
}) => {
  if (!open) return null;

  const toggle = (key: keyof AppSettings) => {
    onUpdate({
      ...settings,
      [key]: !settings[key],
    });
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-sm">
      <div className="flex max-h-[88vh] w-full max-w-2xl flex-col overflow-hidden rounded-lg border border-white/15 bg-[#0B0F17] shadow-2xl">
        <div className="flex items-center justify-between border-b border-white/10 px-5 py-3.5">
          <div className="flex items-center gap-2">
            <Sliders className="h-4 w-4 text-[#00E5FF]" />
            <h2 className="font-ui text-sm font-semibold text-white">
              Preferences & Analysis Settings
            </h2>
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => onUpdate({ ...DEFAULT_SETTINGS })}
              className="inline-flex items-center gap-1 rounded border border-white/10 bg-white/5 px-2.5 py-1 text-xs text-slate-300 hover:border-white/25 hover:text-white"
            >
              <RotateCcw className="h-3 w-3" /> Reset to Defaults
            </button>
            <button
              type="button"
              onClick={onClose}
              className="rounded p-1 text-slate-400 hover:bg-white/10 hover:text-white"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>

        <div className="grid flex-1 grid-cols-1 gap-5 overflow-y-auto p-5 text-xs md:grid-cols-2">
          {/* Appearance & Fonts */}
          <div className="space-y-3 rounded-md border border-white/10 bg-[#05070B]/70 p-3.5">
            <h3 className="font-semibold uppercase tracking-wider text-[#00E5FF]">
              Appearance & Typography
            </h3>

            <div className="flex items-center justify-between">
              <span className="text-slate-300">Color Theme</span>
              <select
                value={settings.theme}
                onChange={(e) =>
                  onUpdate({ ...settings, theme: e.target.value as 'dark' | 'light' })
                }
                className="rounded border border-white/15 bg-[#0B0F17] px-2 py-1 text-slate-200"
              >
                <option value="dark">Obsidian Forensics (Dark)</option>
                <option value="light">Clean Daylight (Light)</option>
              </select>
            </div>

            <div className="flex items-center justify-between">
              <span className="text-slate-300">Monospace Code Font</span>
              <select
                value={settings.monospaceCodeFont}
                onChange={(e) =>
                  onUpdate({
                    ...settings,
                    monospaceCodeFont: e.target.value as AppSettings['monospaceCodeFont'],
                  })
                }
                className="rounded border border-white/15 bg-[#0B0F17] px-2 py-1 text-slate-200"
              >
                <option value="JetBrains Mono">JetBrains Mono</option>
                <option value="IBM Plex Mono">IBM Plex Mono</option>
                <option value="System Mono">System Mono</option>
              </select>
            </div>

            {(
              [
                ['enhancedFonts', 'Enhanced Font Ligatures & Rendering'],
                ['compactLayout', 'Compact High-Density Workspace'],
                ['showBackgroundStars', 'Subtle Background Starfield Canvas'],
                ['animations', 'Smooth UI Transitions'],
                ['reducedMotion', 'Reduced Motion Mode'],
              ] as Array<[keyof AppSettings, string]>
            ).map(([k, label]) => (
              <label key={k} className="flex cursor-pointer items-center justify-between py-0.5">
                <span className="text-slate-300">{label}</span>
                <input
                  type="checkbox"
                  checked={Boolean(settings[k])}
                  onChange={() => toggle(k)}
                  className="h-3.5 w-3.5 accent-[#00E5FF]"
                />
              </label>
            ))}
          </div>

          {/* Disassembly & Decompiler Display */}
          <div className="space-y-3 rounded-md border border-white/10 bg-[#05070B]/70 p-3.5">
            <h3 className="font-semibold uppercase tracking-wider text-[#8B5CF6]">
              Disassembly & Analysis Engine
            </h3>

            {(
              [
                ['showAddresses', 'Show Virtual Addresses'],
                ['showBytes', 'Show Instruction Opcode Bytes'],
                ['showComments', 'Show Inline Cross-Ref & User Comments'],
                ['showFunctionSignatures', 'Show Inferred Function Signatures'],
                ['showAnalysisDetails', 'Show Deep Binary Metadata & Entropy'],
                ['autoAnalyzeOnOpen', 'Auto-Analyze Binary on File Open'],
                ['autoNameFunctions', 'IDA-Style Auto Function Naming (sub_*)'],
                ['autoSaveProject', 'Auto-Save Project State to IndexedDB'],
              ] as Array<[keyof AppSettings, string]>
            ).map(([k, label]) => (
              <label key={k} className="flex cursor-pointer items-center justify-between py-0.5">
                <span className="text-slate-300">{label}</span>
                <input
                  type="checkbox"
                  checked={Boolean(settings[k])}
                  onChange={() => toggle(k)}
                  className="h-3.5 w-3.5 accent-[#8B5CF6]"
                />
              </label>
            ))}

            <div className="flex items-center justify-between pt-1">
              <span className="text-slate-300">Minimum String Length</span>
              <input
                type="number"
                min={2}
                max={32}
                value={settings.minStringLength}
                onChange={(e) =>
                  onUpdate({
                    ...settings,
                    minStringLength: Math.max(2, parseInt(e.target.value, 10) || 4),
                  })
                }
                className="w-16 rounded border border-white/15 bg-[#0B0F17] px-2 py-1 text-right text-slate-200"
              />
            </div>

            <div className="flex items-center justify-between">
              <span className="text-slate-300">Worker Timeout (seconds)</span>
              <input
                type="number"
                min={10}
                max={180}
                value={settings.analysisTimeoutSec}
                onChange={(e) =>
                  onUpdate({
                    ...settings,
                    analysisTimeoutSec: Math.max(10, parseInt(e.target.value, 10) || 45),
                  })
                }
                className="w-16 rounded border border-white/15 bg-[#0B0F17] px-2 py-1 text-right text-slate-200"
              />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export const ShortcutsModal: React.FC<{ open: boolean; onClose: () => void }> = ({
  open,
  onClose,
}) => {
  if (!open) return null;
  const shortcuts = [
    ['Ctrl/Cmd + O', 'Open local binary file (.exe, .dll, .elf, .so, .wasm, .bin)'],
    ['Ctrl/Cmd + K', 'Focus Function / Symbol / String search filter'],
    ['N', 'Rename currently selected function (syncs across both decompilers)'],
    [';', 'Add or edit analyst annotation comment on active function'],
    ['1 / 2 / 3 / 4', 'Switch primary center view (Decompiler / Disassembly / CFG / Hex)'],
    ['D', 'Toggle Dual C-Like Decompiler Side-by-Side Comparison'],
    ['G', 'Jump to virtual address or function symbol'],
    ['Ctrl/Cmd + S', 'Save current reverse engineering project to IndexedDB'],
    ['Esc', 'Close active modal or clear search filter'],
  ];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-sm">
      <div className="w-full max-w-lg overflow-hidden rounded-lg border border-white/15 bg-[#0B0F17] shadow-2xl">
        <div className="flex items-center justify-between border-b border-white/10 px-5 py-3.5">
          <div className="flex items-center gap-2">
            <Keyboard className="h-4 w-4 text-[#00E5FF]" />
            <h2 className="font-ui text-sm font-semibold text-white">Keyboard Shortcuts</h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded p-1 text-slate-400 hover:bg-white/10 hover:text-white"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="divide-y divide-white/5 p-4 text-xs">
          {shortcuts.map(([key, desc]) => (
            <div key={key} className="flex items-center justify-between py-2">
              <span className="text-slate-300">{desc}</span>
              <kbd className="rounded border border-white/15 bg-[#05070B] px-2 py-0.5 font-mono-jetbrains text-[11px] text-[#00E5FF]">
                {key}
              </kbd>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export const AboutArchitectureModal: React.FC<{
  open: boolean;
  tab: 'engines' | 'security' | 'about';
  onClose: () => void;
}> = ({ open, tab, onClose }) => {
  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-sm">
      <div className="max-h-[85vh] w-full max-w-2xl overflow-y-auto rounded-lg border border-white/15 bg-[#0B0F17] p-5 text-xs text-slate-300 shadow-2xl">
        <div className="mb-4 flex items-center justify-between border-b border-white/10 pb-3">
          <div className="flex items-center gap-2">
            {tab === 'security' ? (
              <Lock className="h-4 w-4 text-emerald-400" />
            ) : (
              <Cpu className="h-4 w-4 text-[#00E5FF]" />
            )}
            <h2 className="font-ui text-sm font-semibold text-white">
              {tab === 'security'
                ? '100% Local-First Privacy & Sandbox Model'
                : tab === 'engines'
                    ? 'Dual WebAssembly Decompiler Architecture'
                    : "About Spet's Easy Decompiler"}
            </h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded p-1 text-slate-400 hover:bg-white/10 hover:text-white"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="space-y-4 leading-relaxed">
          <div className="rounded border border-[#38bdf8]/30 bg-[#38bdf8]/5 p-3.5">
            <h3 className="mb-1 font-semibold text-[#38bdf8]">
              Engine A: Rizin v0.9.1 WASM + jsdec v0.9.0
            </h3>
            <p className="text-zinc-300">
              Compiled from native C (`librz`) to WebAssembly via Emscripten (`rzwasi`), paired with
              the official `jsdec` AST control-flow structuring engine running inside an isolated Web
              Worker. Performs full binary header parsing (ELF, PE/COFF, Mach-O, WASM), recursive
              traversal disassembly (`aaa`), basic-block Control Flow Graph recovery (`agf`), cross-reference
              indexing, and C-like pseudocode synthesis.
            </p>
          </div>

          <div className="rounded border border-[#818cf8]/30 bg-[#818cf8]/5 p-3.5">
            <h3 className="mb-1 font-semibold text-[#a5b4fc]">
              Engine B: Ghidra C++ Sleigh Decompiler WASM (v11.2 / 0.0.4)
            </h3>
            <p className="text-zinc-300">
              Compiled directly from the NSA Ghidra C++ decompiler core (`libdecomp` + `WasmSleigh`)
              into WebAssembly. Ingests compiled `.sla`, `.pspec`, and `.cspec` processor specifications
              and virtual memory bytechunks in a dedicated Web Worker to perform full P-Code lifting,
              SSA data-flow simplification, type propagation, and structured C decompilation.
            </p>
          </div>

          <div className="rounded border border-emerald-500/30 bg-emerald-500/5 p-3.5">
            <h3 className="mb-1 flex items-center gap-1.5 font-semibold text-emerald-400">
              <ShieldCheck className="h-4 w-4" /> Zero-Telemetry Client-Side Execution Guarantee
            </h3>
            <p className="text-zinc-300">
              Every byte of your binary stays strictly inside your browser&apos;s sandboxed Web Worker
              heap and IndexedDB storage. No binary uploads, external API calls, or remote telemetry
              ever occur. Once loaded, the Progressive Web App (PWA) service worker caches all WASM
              engines and Sleigh specifications for complete offline operation.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
