import React from 'react';
import { motion } from 'framer-motion';

export const StatusBadge = ({ status, text }) => {
  const variants = {
    verified: 'bg-forest/10 text-forest border-forest/20',
    pending: 'bg-saffron/10 text-amber-700 border-saffron/20',
    rejected: 'bg-terracotta/10 text-terracotta border-terracotta/20',
    default: 'bg-sandstone/30 text-warm-gray border-sandstone'
  };

  return (
    <motion.span 
      initial={{ scale: 0.8 }}
      animate={{ scale: 1 }}
      className={`inline-flex items-center px-3 py-1 rounded-full text-xs font-semibold border ${variants[status] || variants.default}`}
    >
      {text || status}
    </motion.span>
  );
};