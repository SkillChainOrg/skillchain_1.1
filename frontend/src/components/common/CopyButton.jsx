import React, { useState } from 'react';
import { Copy, Check } from 'lucide-react';
import { useToast } from '../../context/ToastContext';

export const CopyButton = ({ text, label = "Copy" }) => {
  const [copied, setCopied] = useState(false);
  const { addToast } = useToast();

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      addToast(`${label} copied to clipboard`, 'success');
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      addToast('Failed to copy', 'error');
    }
  };

  return (
    <button 
      onClick={handleCopy}
      className="p-1.5 hover:bg-sandstone/30 rounded-md transition-colors text-warm-gray hover:text-deep-ink"
      title="Copy to clipboard"
    >
      {copied ? <Check size={16} className="text-forest" /> : <Copy size={16} />}
    </button>
  );
};