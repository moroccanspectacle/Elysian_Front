import React, { useState, useRef, useEffect } from 'react';
import { AlertCircle } from 'lucide-react';
import { useAuth } from './AuthContext';

interface MfaVerificationProps {
  onVerify?: (code: string) => Promise<void>;
  onCancel?: () => void; // Add this prop
  enforced?: boolean;    // Add this prop
}

export function MfaVerification({ onVerify, onCancel, enforced = false }: MfaVerificationProps) {
  const { completeMfaLogin, error } = useAuth();
  const [verificationCode, setVerificationCode] = useState(['', '', '', '', '', '']);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const inputRefs = useRef<(HTMLInputElement | null)[]>([]);

  const handleChange = (index: number, value: string) => {
    // Allow only numbers
    if (value && !/^\d+$/.test(value)) return;
    
    const newVerificationCode = [...verificationCode];
    newVerificationCode[index] = value;
    setVerificationCode(newVerificationCode);
    
    // Move to next input if current input is filled
    if (value && index < 5) {
      inputRefs.current[index + 1]?.focus();
    }
  };

  const handleKeyDown = (index: number, e: React.KeyboardEvent<HTMLInputElement>) => {
    // Move to previous input on backspace if current input is empty
    if (e.key === 'Backspace' && !verificationCode[index] && index > 0) {
      inputRefs.current[index - 1]?.focus();
    }
  };

  const handlePaste = (e: React.ClipboardEvent<HTMLInputElement>) => {
    e.preventDefault();
    const pastedData = e.clipboardData.getData('text').trim();
    
    // If pasted data is a 6-digit number
    if (/^\d{6}$/.test(pastedData)) {
      const digits = pastedData.split('');
      setVerificationCode(digits);
      // Focus last input
      inputRefs.current[5]?.focus();
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const code = verificationCode.join('');
    
    if (code.length !== 6) return;
    
    setIsSubmitting(true);
    try {
      if (onVerify) {
        await onVerify(code);
      } else {
        await completeMfaLogin(code);
      }
    } catch (err) {
      // Error handling...
    } finally {
      setIsSubmitting(false);
    }
  };

  // Automatically submit when all 6 digits are entered
  useEffect(() => {
    if (verificationCode.every(digit => digit !== '')) {
      handleSubmit(new Event('submit') as unknown as React.FormEvent);
    }
  }, [verificationCode]);

  return (
    <div className="max-w-md mx-auto p-6">
      <h2 className="text-xl font-semibold text-center mb-4">Two-Factor Authentication</h2>
      
      {/* Add cancel button if onCancel is provided */}
      {onCancel && (
        <button 
          onClick={onCancel}
          className="absolute top-4 right-4 text-gray-500 hover:text-gray-700"
        >
          Cancel
        </button>
      )}
      
      <p className="text-gray-700 text-center mb-6">
        Enter the verification code from your authentication app
      </p>
      
      {error && (
        <div className="mb-4 p-3 bg-red-100 text-red-700 rounded-md flex items-center">
          <AlertCircle className="w-5 h-5 mr-2" />
          {error}
        </div>
      )}
      
      <form onSubmit={handleSubmit}>
        <div className="grid grid-cols-6 gap-2 mb-6">
          {verificationCode.map((digit, index) => (
            <input
              key={index}
              ref={el => inputRefs.current[index] = el}
              type="text"
              inputMode="numeric"
              maxLength={1}
              value={digit}
              onChange={(e) => handleChange(index, e.target.value)}
              onKeyDown={(e) => handleKeyDown(index, e)}
              onPaste={index === 0 ? handlePaste : undefined}
              className="w-full aspect-square rounded-lg border border-gray-300 text-center text-lg focus:outline-none focus:ring-2 focus:ring-[#217eaa] disabled:bg-gray-100"
              autoFocus={index === 0}
              disabled={isSubmitting}
            />
          ))}
        </div>
        
        <button
          type="submit"
          disabled={verificationCode.some(digit => digit === '') || isSubmitting}
          className="w-full bg-[#217eaa] text-white rounded-lg px-4 py-2 hover:bg-[#1a6389] transition-colors disabled:opacity-70"
        >
          {isSubmitting ? (
            <div className="flex items-center justify-center">
              <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white mr-2"></div>
              Verifying...
            </div>
          ) : (
            'Verify'
          )}
        </button>
      </form>
    </div>
  );
}