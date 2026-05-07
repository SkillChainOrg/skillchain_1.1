import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Shield, CheckCircle, XCircle, KeyRound } from 'lucide-react';
import { StatusBadge } from '../components/common/StatusBadge';
import { useToast } from '../context/ToastContext';
import * as api from '../api/api';

export const AdminPanel = () => {
  const [adminKey, setAdminKey] = useState(localStorage.getItem('admin_key') || '');
  const [artisans, setArtisans] = useState([]);
  const [loading, setLoading] = useState(false);
  const { addToast } = useToast();

  const saveKey = (key) => {
    localStorage.setItem('admin_key', key);
    setAdminKey(key);
  };

  const loadPending = async () => {
    if (!adminKey) return addToast('Please enter admin key', 'error');
    setLoading(true);
    try {
      const { data } = await api.getPendingArtisans();
      setArtisans(data);
    } catch (err) {
      addToast('Failed to load pending artisans', 'error');
    } finally {
      setLoading(false);
    }
  };

  const handleApprove = async (id) => {
    try {
      await api.approveArtisan(id);
      setArtisans(prev => prev.filter(a => a.id !== id));
      addToast('Artisan approved successfully', 'success');
    } catch (err) {
      addToast('Approval failed', 'error');
    }
  };

  const handleReject = async (id) => {
    try {
      await api.rejectArtisan(id);
      setArtisans(prev => prev.filter(a => a.id !== id));
      addToast('Artisan rejected', 'success');
    } catch (err) {
      addToast('Rejection failed', 'error');
    }
  };

  return (
    <div className="max-w-6xl mx-auto px-4 py-8">
      <div className="mb-8">
        <h1 className="text-3xl font-serif font-bold mb-2 flex items-center gap-2">
          <Shield className="text-terracotta" /> Moderation Panel
        </h1>
        <p className="text-warm-gray">Review and approve artisan registrations.</p>
      </div>

      <div className="heritage-card mb-8 max-w-md">
        <label className="block text-sm font-medium mb-2 flex items-center gap-2">
          <KeyRound size={16} /> Admin Key
        </label>
        <div className="flex gap-2">
          <input 
            type="password" 
            value={adminKey}
            onChange={(e) => saveKey(e.target.value)}
            className="text-field flex-1"
            placeholder="Enter admin authentication key"
          />
          <button onClick={loadPending} className="btn-primary">Load</button>
        </div>
      </div>

      <div className="heritage-card overflow-hidden p-0">
        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead className="bg-parchment/50 dark:bg-white/5 text-sm uppercase text-warm-gray">
              <tr>
                <th className="px-6 py-4 font-medium">Name</th>
                <th className="px-6 py-4 font-medium">Craft</th>
                <th className="px-6 py-4 font-medium">Location</th>
                <th className="px-6 py-4 font-medium">Status</th>
                <th className="px-6 py-4 font-medium text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-sandstone/20">
              <AnimatePresence>
                {artisans.map((artisan) => (
                  <motion.tr 
                    key={artisan.id}
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    exit={{ opacity: 0, x: -100 }}
                    className="hover:bg-parchment/20 dark:hover:bg-white/5 transition-colors"
                  >
                    <td className="px-6 py-4 font-medium">{artisan.name}</td>
                    <td className="px-6 py-4 text-warm-gray">{artisan.craft_type}</td>
                    <td className="px-6 py-4 text-warm-gray">{artisan.location}</td>
                    <td className="px-6 py-4"><StatusBadge status="pending" text="Pending" /></td>
                    <td className="px-6 py-4 text-right">
                      <div className="flex justify-end gap-2">
                        <button 
                          onClick={() => handleApprove(artisan.id)}
                          className="p-2 rounded-lg bg-forest/10 text-forest hover:bg-forest hover:text-white transition-colors"
                          title="Approve"
                        >
                          <CheckCircle size={18} />
                        </button>
                        <button 
                          onClick={() => handleReject(artisan.id)}
                          className="p-2 rounded-lg bg-terracotta/10 text-terracotta hover:bg-terracotta hover:text-white transition-colors"
                          title="Reject"
                        >
                          <XCircle size={18} />
                        </button>
                      </div>
                    </td>
                  </motion.tr>
                ))}
              </AnimatePresence>
              
              {artisans.length === 0 && !loading && (
                <tr>
                  <td colSpan={5} className="px-6 py-12 text-center text-warm-gray">
                    {adminKey ? 'No pending artisans found.' : 'Enter admin key and click Load.'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};