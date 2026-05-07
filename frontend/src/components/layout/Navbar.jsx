import React, { useState, useEffect } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Menu, X, Sun, Moon, Fingerprint } from 'lucide-react';

const navLinks = [
  { path: '/', label: 'Home' },
  { path: '/institution', label: 'Institution' },
  { path: '/artisan', label: 'Artisan' },
  { path: '/verify', label: 'Verify' },
  { path: '/admin', label: 'Admin' },
  { path: '/digilocker', label: 'DigiLocker' },
];

export const Navbar = () => {
  const [isOpen, setIsOpen] = useState(false);
  const [darkMode, setDarkMode] = useState(false);
  const location = useLocation();

  useEffect(() => {
    if (darkMode) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  }, [darkMode]);

  return (
    <nav className="sticky top-0 z-40 backdrop-blur-md bg-ivory/80 dark:bg-indigo-deep/80 border-b border-sandstone/20">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between items-center h-16">
          <Link to="/" className="flex items-center gap-2 group">
            <Fingerprint className="text-terracotta group-hover:text-saffron transition-colors" size={28} />
            <span className="font-serif text-xl font-bold text-deep-ink dark:text-ivory">SkillChain</span>
          </Link>

          <div className="hidden md:flex items-center gap-8">
            {navLinks.map((link) => (
              <Link
                key={link.path}
                to={link.path}
                className={`text-sm font-medium transition-colors relative ${
                  location.pathname === link.path 
                    ? 'text-terracotta' 
                    : 'text-warm-gray hover:text-deep-ink dark:hover:text-ivory'
                }`}
              >
                {link.label}
                {location.pathname === link.path && (
                  <motion.div layoutId="underline" className="absolute -bottom-5 left-0 right-0 h-0.5 bg-terracotta" />
                )}
              </Link>
            ))}
            <button 
              onClick={() => setDarkMode(!darkMode)}
              className="p-2 rounded-lg hover:bg-sandstone/20 transition-colors"
            >
              {darkMode ? <Sun size={20} /> : <Moon size={20} />}
            </button>
          </div>

          <button className="md:hidden p-2" onClick={() => setIsOpen(!isOpen)}>
            {isOpen ? <X size={24} /> : <Menu size={24} />}
          </button>
        </div>
      </div>

      {isOpen && (
        <motion.div 
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          className="md:hidden bg-ivory dark:bg-indigo-deep border-b border-sandstone/20"
        >
          <div className="px-4 pt-2 pb-4 space-y-1">
            {navLinks.map((link) => (
              <Link
                key={link.path}
                to={link.path}
                onClick={() => setIsOpen(false)}
                className={`block px-3 py-2 rounded-md text-base font-medium ${
                  location.pathname === link.path
                    ? 'bg-terracotta/10 text-terracotta'
                    : 'text-warm-gray hover:bg-sandstone/20'
                }`}
              >
                {link.label}
              </Link>
            ))}
          </div>
        </motion.div>
      )}
    </nav>
  );
};