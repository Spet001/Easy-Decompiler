import React, { useEffect, useState } from 'react';
import { Download } from 'lucide-react';

interface BeforeInstallPromptEvent extends Event {
  prompt: () => Promise<void>;
  userChoice: Promise<{ outcome: 'accepted' | 'dismissed'; platform: string }>;
}

export const PwaInstallButton: React.FC = () => {
  const [deferredPrompt, setDeferredPrompt] = useState<BeforeInstallPromptEvent | null>(null);
  const [isStandalone, setIsStandalone] = useState(false);

  useEffect(() => {
    const standalone =
      window.matchMedia('(display-mode: standalone)').matches ||
      (window.navigator as any).standalone === true;
    setIsStandalone(standalone);

    const handler = (e: Event) => {
      e.preventDefault();
      setDeferredPrompt(e as BeforeInstallPromptEvent);
    };

    window.addEventListener('beforeinstallprompt', handler);
    return () => window.removeEventListener('beforeinstallprompt', handler);
  }, []);

  if (isStandalone) return null;

  const isIos =
    /iPad|iPhone|iPod/.test(navigator.userAgent) && !(window as any).MSStream;

  if (!deferredPrompt && !isIos) return null;

  const handleInstallClick = async () => {
    if (deferredPrompt) {
      await deferredPrompt.prompt();
      const choice = await deferredPrompt.userChoice;
      if (choice.outcome === 'accepted') {
        setDeferredPrompt(null);
      }
    }
  };

  return (
    <button
      type="button"
      onClick={handleInstallClick}
      className="inline-flex h-[20px] items-center gap-1 border border-[#26354d] bg-[#111a29] px-2 text-[10px] font-mono text-slate-200 hover:border-[#38bdf8]"
      title="Install Offline-Ready Decompiler PWA"
    >
      <Download className="h-2.5 w-2.5 text-[#38bdf8]" />
      <span>Install PWA</span>
    </button>
  );
};
