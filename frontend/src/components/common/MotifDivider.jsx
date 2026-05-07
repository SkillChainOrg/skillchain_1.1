import React from 'react';

export const MotifDivider = ({ className = "" }) => (
  <div className={`flex items-center justify-center gap-4 my-8 ${className}`}>
    <div className="h-px w-16 bg-gradient-to-r from-transparent to-saffron/60" />
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" className="text-saffron animate-spin-slow">
      <path d="M12 2L14.5 9.5L22 12L14.5 14.5L12 22L9.5 14.5L2 12L9.5 9.5L12 2Z" fill="currentColor" opacity="0.6"/>
    </svg>
    <div className="h-px w-16 bg-gradient-to-l from-transparent to-saffron/60" />
  </div>
);