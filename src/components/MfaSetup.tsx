import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { AlertCircle, Check } from 'lucide-react';
import { useAuth } from './AuthContext'; // Assuming useAuth is imported from a context

interface MfaSetupProps {
  onComplete: (code: string) => void;  // Change this to accept a code
  onCancel: () => void;
  enforced?: boolean;
}

export function MfaSetup({ onComplete, onCancel, enforced = false }: MfaSetupProps) {
  const [qrCode, setQrCode] = useState<string | null>(null);
  const [secret, setSecret] = useState<string | null>(null);
  const [verificationCode, setVerificationCode] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);
  const { user, tempUserId: contextUserId } = useAuth(); // Get from context too

  useEffect(() => {
    // Generate MFA secret and QR code when component mounts
    const setupMfa = async () => {
      try {
        setIsLoading(true);
        
        // Diagnostic logging
        let tempUserId = sessionStorage.getItem('temp-user-id');
        const mfaToken = sessionStorage.getItem('mfa-setup-token');
        
        console.log("MFA Setup Diagnostics:", {
          tempUserId: tempUserId ? 'present' : 'missing',
          tokenExists: mfaToken ? 'present' : 'missing',
          allSessionStorageKeys: Object.keys(sessionStorage)
        });
        
        console.log("Attempting to set up MFA...");
        
        // Get user ID from session storage or context
         tempUserId = sessionStorage.getItem('temp-user-id');
        
        // Try multiple methods
        let result;
        try {
          // Try the direct method first
          result = await api.mfa.directSetup();
        } catch (directError) {
          console.error("Direct setup failed:", directError);
          
          // Get userId from multiple sources
          const sessionUserId = sessionStorage.getItem('temp-user-id');
          const fallbackUserId = sessionUserId || contextUserId || user?.id;
          
          if (fallbackUserId) {
            console.log("Attempting emergency setup with userId:", fallbackUserId);
            result = await api.mfa.emergencySetup(fallbackUserId);
          } else {
            throw new Error("No user ID available for emergency setup");
          }
        }
        
        console.log("MFA setup result:", result);
        
        if (result.qr) {
          setQrCode(result.qr);
          setSecret(result.secret);
        } else {
          setError('QR code was not returned by the server');
        }
      } catch (err: any) {
        console.error("MFA setup error:", err);
        setError(err.message || 'Failed to set up MFA');
      } finally {
        setIsLoading(false);
      }
    };

    setupMfa();
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!verificationCode.trim()) {
      setError('Please enter the verification code');
      return;
    }
    
    try {
      setIsLoading(true);
      setError(null);
      await api.mfa.verifySetup(verificationCode);
      setSuccess(true);
      setTimeout(() => onComplete(verificationCode), 1500); // Pass the verification code to the parent component
    } catch (err: any) {
      setError(err.message || 'Failed to verify MFA setup');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="p-6">
      <h2 className="text-2xl font-semibold mb-4">
        {enforced ? 'Required: Set Up Two-Factor Authentication' : 'Set Up Two-Factor Authentication'}
      </h2>
      
      {enforced && (
        <div className="mb-4 p-3 bg-blue-100 text-blue-700 rounded-md">
          Your organization requires two-factor authentication. 
          You must set up 2FA to continue using the application.
        </div>
      )}
      
      {error && (
        <div className="mb-4 p-3 bg-red-100 text-red-700 rounded-md flex items-center">
          <AlertCircle className="w-5 h-5 mr-2" />
          {error}
        </div>
      )}
      
      {success && (
        <div className="mb-4 p-3 bg-green-100 text-green-700 rounded-md flex items-center">
          <Check className="w-5 h-5 mr-2" />
          MFA setup successful!
        </div>
      )}
      
      <div className="space-y-6">
        <div>
          <p className="text-gray-700 mb-4">
            Two-factor authentication adds an extra layer of security to your account. When enabled, 
            you'll need to provide both your password and a verification code from your authentication app.
          </p>
          
          <ol className="list-decimal list-inside text-gray-700 space-y-2">
            <li>Download an authenticator app like Google Authenticator or Authy</li>
            <li>Scan the QR code below with your app</li>
            <li>Enter the verification code provided by the app</li>
          </ol>
        </div>
        
        {isLoading && !qrCode ? (
          <div className="flex justify-center">
            <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-[#217eaa]"></div>
          </div>
        ) : qrCode ? (
          <div className="flex flex-col items-center space-y-4">
            <div className="bg-white p-4 rounded-md shadow-sm">
              <img src={qrCode} alt="QR Code for MFA" className="w-48 h-48" />
            </div>
            
            {secret && (
              <div className="text-center">
                <p className="text-sm text-gray-500 mb-1">If you can't scan the QR code, enter this code manually:</p>
                <code className="bg-gray-100 px-2 py-1 rounded text-sm font-mono">{secret}</code>
              </div>
            )}
          </div>
        ) : null}
        
        <form onSubmit={handleSubmit}>
          <div className="mb-4">
            <label htmlFor="verificationCode" className="block text-sm font-medium text-gray-700 mb-1">
              Verification Code
            </label>
            <input
              type="text"
              id="verificationCode"
              value={verificationCode}
              onChange={(e) => setVerificationCode(e.target.value)}
              className="w-full rounded-lg border border-gray-300 px-3 py-2 focus:outline-none focus:ring-2 focus:ring-[#217eaa]"
              placeholder="Enter 6-digit code"
              maxLength={6}
              pattern="[0-9]{6}"
              disabled={isLoading || success}
            />
          </div>
          
          <div className="flex justify-end space-x-3">
            <button
              type="button"
              onClick={onCancel}
              disabled={isLoading || success}
              className="px-4 py-2 text-[#8ca4ac] hover:text-[#217eaa] disabled:opacity-50"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isLoading || success || verificationCode.length !== 6}
              className="bg-[#217eaa] text-white px-4 py-2 rounded-lg hover:bg-[#1a6389] disabled:opacity-50"
            >
              {isLoading ? (
                <div className="flex items-center">
                  <div className="animate-spin rounded-full h-4 w-4 border-t-2 border-b-2 border-white mr-2"></div>
                  Verifying...
                </div>
              ) : success ? (
                <div className="flex items-center">
                  <Check className="w-4 h-4 mr-2" />
                  Verified
                </div>
              ) : (
                'Verify'
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}