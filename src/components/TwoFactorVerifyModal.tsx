import React, { useState } from 'react';
import { X, ShieldCheck } from 'lucide-react';
import { api } from '../services/api';
import { Button } from './Button';

interface TwoFactorVerifyModalProps {
  onClose: () => void;
  onVerify: (token: string) => void;
}

export function TwoFactorVerifyModal({ onClose, onVerify }: TwoFactorVerifyModalProps) {
  const [code, setCode] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [isVerifying, setIsVerifying] = useState(false);
  
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!code) {
      setError('Please enter a verification code');
      return;
    }
    
    try {
      setIsVerifying(true);
      const response = await api.auth.verify2FA(code);
      onVerify(response.sensitiveOpToken);
    } catch (err) {
      console.error('2FA verification failed:', err);
      setError('Invalid verification code');
      setIsVerifying(false);
    }
  };
  
  return (
    <div className="fixed inset-0 flex items-center justify-center z-50 bg-black bg-opacity-50">
      <div className="bg-white rounded-lg shadow-lg w-full max-w-md">
        <div className="flex justify-between items-center p-4 border-b">
          <h2 className="text-xl font-semibold text-gray-800 flex items-center">
            <ShieldCheck className="w-5 h-5 mr-2 text-primary-500" />
            Security Verification
          </h2>
          <button 
            className="text-gray-500 hover:text-gray-700"
            onClick={onClose}
            disabled={isVerifying}
          >
            <X className="w-5 h-5" />
          </button>
        </div>
        
        <form onSubmit={handleSubmit} className="p-4">
          {error && (
            <div className="mb-4 p-3 bg-red-50 text-red-700 rounded-md">
              {error}
            </div>
          )}
          
          <div className="mb-4">
            <label htmlFor="code" className="block mb-2 text-sm font-medium text-gray-700">
              Enter the verification code from your authenticator app
            </label>
            <input
              type="text"
              id="code"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              placeholder="000000"
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-primary-500"
              autoComplete="one-time-code"
              inputMode="numeric"
              pattern="[0-9]*"
              maxLength={6}
            />
          </div>
          
          <div className="flex justify-end space-x-3">
            <Button
              variant="outline"
              onClick={onClose}
              disabled={isVerifying}
            >
              Cancel
            </Button>
            <Button
              variant="primary"
              type="submit"
              isLoading={isVerifying}
            >
              Verify
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
}