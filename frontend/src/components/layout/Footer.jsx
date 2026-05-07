import React from 'react';
import { Heart } from 'lucide-react';
import { MotifDivider } from '../common/MotifDivider';

export const Footer = () => (
  <footer className="bg-parchment dark:bg-black/20 border-t border-sandstone/30 mt-20">
    <div className="max-w-7xl mx-auto px-4 py-12 sm:px-6 lg:px-8">
      <MotifDivider className="mb-8" />
      <div className="flex flex-col md:flex-row justify-between items-center gap-4">
        <div className="text-center md:text-left">
          <h3 className="font-serif text-lg font-bold text-deep-ink dark:text-ivory">SkillChain</h3>
          <p className="text-sm text-warm-gray mt-1">Preserving heritage through verifiable trust.</p>
        </div>
        <div className="flex items-center gap-1 text-sm text-warm-gray">
          <span>Made with</span>
          <Heart size={14} className="text-terracotta fill-terracotta" />
          <span>for Indian artisans</span>
        </div>
      </div>
      <div className="mt-8 text-center text-xs text-warm-gray/60">
        Anchored on Algorand • Stored on IPFS • Verified on SkillChain
      </div>
    </div>
  </footer>
);