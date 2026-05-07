import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Wallet, Upload, FileText, Package, RefreshCw } from 'lucide-react';
import { FileUpload } from '../components/common/FileUpload';
import { CopyButton } from '../components/common/CopyButton';
import { useToast } from '../context/ToastContext';
import * as api from '../api/api';

export const InstitutionDashboard = () => {
  const [apiKey, setApiKey] = useState(localStorage.getItem('institution_api_key') || '');
  const [wallet, setWallet] = useState(null);
  const [activeTab, setActiveTab] = useState('issue');
  const [loading, setLoading] = useState(false);
  const { addToast } = useToast();

  const [issueForm, setIssueForm] = useState({ doc_type: '', cert_number: '', issued_to_name: '' });
  const [issueFile, setIssueFile] = useState(null);
  const [batchFiles, setBatchFiles] = useState([]);
  const [batchStatus, setBatchStatus] = useState(null);

  useEffect(() => {
    if (apiKey) loadWallet();
  }, [apiKey]);

  const saveApiKey = (key) => {
    localStorage.setItem('institution_api_key', key);
    setApiKey(key);
  };

  const loadWallet = async () => {
    try {
      const { data } = await api.getWallet();
      setWallet(data);
    } catch (err) {
      addToast('Failed to load wallet', 'error');
    }
  };

  const handleIssue = async (e) => {
    e.preventDefault();
    if (!issueFile) return addToast('Please select a certificate file', 'error');
    
    setLoading(true);
    const formData = new FormData();
    formData.append('certificate', issueFile);
    formData.append('doc_type', issueForm.doc_type);
    formData.append('cert_number', issueForm.cert_number);
    formData.append('issued_to_name', issueForm.issued_to_name);

    try {
      await api.issueCertificate(formData);
      addToast('Certificate issued successfully!', 'success');
      setIssueForm({ doc_type: '', cert_number: '', issued_to_name: '' });
      setIssueFile(null);
    } catch (err) {
      addToast(err.response?.data?.message || 'Issuance failed', 'error');
    } finally {
      setLoading(false);
    }
  };

  const handleBatch = async () => {
    if (!batchFiles.length) return addToast('Please select files', 'error');
    
    setLoading(true);
    const formData = new FormData();
    batchFiles.forEach(file => formData.append('files[]', file));

    try {
      const { data } = await api.issueBatch(formData);
      addToast(`Batch issued: ${data.batch_id}`, 'success');
      setBatchStatus(data);
    } catch (err) {
      addToast('Batch issuance failed', 'error');
    } finally {
      setLoading(false);
    }
  };

  const checkBatchStatus = async () => {
    if (!batchStatus?.batch_id) return;
    try {
      const { data } = await api.getBatchStatus(batchStatus.batch_id);
      setBatchStatus(prev => ({ ...prev, ...data }));
      addToast('Status updated', 'success');
    } catch (err) {
      addToast('Failed to check status', 'error');
    }
  };

  return (
    <div className="max-w-7xl mx-auto px-4 py-8">
      <div className="mb-8">
        <h1 className="text-3xl font-serif font-bold mb-2">Institution Portal</h1>
        <p className="text-warm-gray">Issue and manage verifiable credentials</p>
      </div>

      {/* API Key & Wallet */}
      <div className="grid md:grid-cols-2 gap-6 mb-8">
        <div className="heritage-card">
          <label className="block text-sm font-medium mb-2">Institution API Key</label>
          <div className="flex gap-2">
            <input 
              type="password" 
              value={apiKey} 
              onChange={(e) => saveApiKey(e.target.value)}
              placeholder="Enter your API key"
              className="text-field flex-1"
            />
          </div>
        </div>

        {wallet && (
          <motion.div 
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            className="heritage-card bg-gradient-to-br from-terracotta/5 to-saffron/5"
          >
            <div className="flex items-center gap-3 mb-3">
              <Wallet className="text-terracotta" size={20} />
              <span className="font-medium">Wallet Status</span>
            </div>
            <div className="space-y-2 text-sm">
              <div className="flex justify-between">
                <span className="text-warm-gray">Address</span>
                <div className="flex items-center gap-1 font-mono">
                  {wallet.address?.slice(0, 16)}... <CopyButton text={wallet.address} />
                </div>
              </div>
              <div className="flex justify-between">
                <span className="text-warm-gray">Balance</span>
                <span className="font-bold text-terracotta">{wallet.balance} ALGO</span>
              </div>
            </div>
          </motion.div>
        )}
      </div>

      {/* Tabs */}
      <div className="flex gap-2 mb-6 border-b border-sandstone/30 pb-1">
        {[
          { id: 'issue', label: 'Issue Certificate', icon: FileText },
          { id: 'batch', label: 'Batch Upload', icon: Package },
        ].map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`flex items-center gap-2 px-4 py-2.5 rounded-t-lg text-sm font-medium transition-all ${
              activeTab === tab.id 
                ? 'bg-terracotta text-white shadow-md' 
                : 'text-warm-gray hover:text-deep-ink hover:bg-sandstone/20'
            }`}
          >
            <tab.icon size={16} /> {tab.label}
          </button>
        ))}
      </div>

      {/* Issue Form */}
      {activeTab === 'issue' && (
        <motion.div 
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          className="heritage-card max-w-2xl"
        >
          <form onSubmit={handleIssue} className="space-y-5">
            <FileUpload 
              onFileSelect={setIssueFile} 
              accept=".pdf,.jpg,.png"
              label="Upload certificate document"
            />
            
            <div className="grid md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium mb-1.5">Document Type</label>
                <input 
                  className="text-field"
                  placeholder="e.g., Diploma, Certificate"
                  value={issueForm.doc_type}
                  onChange={e => setIssueForm({...issueForm, doc_type: e.target.value})}
                  required
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1.5">Certificate Number</label>
                <input 
                  className="text-field"
                  placeholder="Unique certificate ID"
                  value={issueForm.cert_number}
                  onChange={e => setIssueForm({...issueForm, cert_number: e.target.value})}
                  required
                />
              </div>
            </div>
            
            <div>
              <label className="block text-sm font-medium mb-1.5">Issued To</label>
              <input 
                className="text-field"
                placeholder="Recipient full name"
                value={issueForm.issued_to_name}
                onChange={e => setIssueForm({...issueForm, issued_to_name: e.target.value})}
                required
              />
            </div>

            <button 
              type="submit" 
              disabled={loading}
              className="btn-primary w-full justify-center disabled:opacity-50"
            >
              {loading ? <RefreshCw className="animate-spin" size={18} /> : <Upload size={18} />}
              Issue Certificate
            </button>
          </form>
        </motion.div>
      )}

      {/* Batch Upload */}
      {activeTab === 'batch' && (
        <motion.div 
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          className="heritage-card max-w-2xl"
        >
          <FileUpload 
            multiple
            onFileSelect={(files) => setBatchFiles(files)}
            accept=".pdf,.zip"
            label="Drop multiple certificates or a ZIP file"
          />
          
          <button 
            onClick={handleBatch}
            disabled={loading || !batchFiles.length}
            className="btn-primary w-full justify-center mt-6 disabled:opacity-50"
          >
            {loading ? <RefreshCw className="animate-spin" size={18} /> : <Package size={18} />}
            Process Batch
          </button>

          {batchStatus && (
            <div className="mt-6 p-4 bg-sandstone/20 rounded-lg">
              <div className="flex justify-between items-start mb-2">
                <span className="font-medium">Batch ID: {batchStatus.batch_id}</span>
                <button onClick={checkBatchStatus} className="text-terracotta hover:underline text-sm">
                  Check Status
                </button>
              </div>
              {batchStatus.status && (
                <div className="text-sm text-warm-gray">
                  Status: <span className="font-medium text-deep-ink">{batchStatus.status}</span>
                </div>
              )}
            </div>
          )}
        </motion.div>
      )}
    </div>
  );
};