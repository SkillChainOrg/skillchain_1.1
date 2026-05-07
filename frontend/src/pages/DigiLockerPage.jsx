import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Fingerprint, ArrowRight, CheckCircle, Shield, UserCheck } from 'lucide-react';
import { useToast } from '../context/ToastContext';
import * as api from '../api/api';

const steps = [
  { id: 'start', label: 'Start', icon: Fingerprint },
  { id: 'consent', label: 'Consent', icon: Shield },
  { id: 'verify', label: 'Verified', icon: UserCheck },
];

export const DigiLockerPage = () => {
  const [currentStep, setCurrentStep] = useState(0);
  const [loading, setLoading] = useState(false);
  const [identity, setIdentity] = useState(null);
  const { addToast } = useToast();

  const handleNext = async () => {
    setLoading(true);
    try {
      if (currentStep === 0) {
        await api.startDigiLocker();
      } else if (currentStep === 1) {
        await api.verifyDigiLocker();
      } else if (currentStep === 2) {
        const { data } = await api.bindDigiLocker();
        setIdentity(data);
        addToast('Identity linked successfully!', 'success');
      }
      
      if (currentStep < 2) setCurrentStep(prev => prev + 1);
    } catch (err) {
      addToast('DigiLocker flow error', 'error');
    } finally {
      setLoading(false);
    }
  };

  const CurrentIcon = steps[currentStep].icon;

  return (
    <div className="max-w-2xl mx-auto px-4 py-12">
      <div className="text-center mb-10">
        <h1 className="text-3xl font-serif font-bold mb-2">DigiLocker Integration</h1>
        <p className="text-warm-gray">Link your government-verified identity to your SkillChain profile.</p>
      </div>

      {/* Stepper */}
      <div className="flex items-center justify-between mb-10 relative">
        <div className="absolute top-1/2 left-0 right-0 h-0.5 bg-sandstone/30 -z-10" />
        {steps.map((step, i) => (
          <div key={step.id} className="flex flex-col items-center gap-2 bg-ivory dark:bg-indigo-deep px-2">
            <div className={`
              w-10 h-10 rounded-full flex items-center justify-center transition-all
              ${i <= currentStep ? 'bg-terracotta text-white shadow-lg' : 'bg-sandstone/30 text-warm-gray'}
            `}>
              {i < currentStep ? <CheckCircle size={20} /> : <step.icon size={20} />}
            </div>
            <span className={`text-xs font-medium ${i <= currentStep ? 'text-deep-ink dark:text-ivory' : 'text-warm-gray'}`}>
              {step.label}
            </span>
          </div>
        ))}
      </div>

      <AnimatePresence mode="wait">
        <motion.div
          key={currentStep}
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          exit={{ opacity: 0, x: -20 }}
          className="heritage-card text-center py-10"
        >
          <div className="w-16 h-16 rounded-full bg-terracotta/10 flex items-center justify-center mx-auto mb-5">
            <CurrentIcon className="text-terracotta" size={32} />
          </div>
          
          <h3 className="text-xl font-serif font-bold mb-3">
            {currentStep === 0 && "Start Identity Verification"}
            {currentStep === 1 && "Grant Consent"}
            {currentStep === 2 && "Identity Linked"}
          </h3>
          
          <p className="text-warm-gray max-w-md mx-auto mb-8">
            {currentStep === 0 && "We will redirect you to DigiLocker to fetch your verified demographic details."}
            {currentStep === 1 && "Allow SkillChain to access your name, DOB, and address for identity binding."}
            {currentStep === 2 && "Your DigiLocker identity has been successfully linked to your artisan profile."}
          </p>

          {currentStep < 2 ? (
            <button 
              onClick={handleNext}
              disabled={loading}
              className="btn-primary mx-auto disabled:opacity-50"
            >
              {loading ? 'Processing...' : 'Continue'} <ArrowRight size={16} />
            </button>
          ) : (
            <div className="bg-forest/10 text-forest px-4 py-2 rounded-lg inline-flex items-center gap-2">
              <CheckCircle size={18} /> Verified & Linked
            </div>
          )}

          {identity && (
            <motion.div 
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              className="mt-6 p-4 bg-parchment/50 dark:bg-white/5 rounded-lg text-left space-y-2 text-sm"
            >
              <div className="flex justify-between"><span className="text-warm-gray">Name</span> <span>{identity.name}</span></div>
              <div className="flex justify-between"><span className="text-warm-gray">DOB</span> <span>{identity.dob}</span></div>
              <div className="flex justify-between"><span className="text-warm-gray">Aadhaar</span> <span>XXXX-XXXX-{identity.aadhaar_last}</span></div>
            </motion.div>
          )}
        </motion.div>
      </AnimatePresence>
    </div>
  );
};