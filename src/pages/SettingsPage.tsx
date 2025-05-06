import React, { useState, useEffect } from 'react';
import { Layout } from '../components/Layout';
import { Navigate, useNavigate } from 'react-router-dom';
import { MfaSetup } from '../components/MfaSetup';
import { Shield, AlertCircle, Check, Key } from 'lucide-react';
import { useAuth } from '../components/AuthContext';
import { api } from '../services/api';

export function SettingsPage() {
  const { user, refreshUserData } = useAuth();
  const navigate = useNavigate();
  const [showMfaSetup, setShowMfaSetup] = useState(false);
  const [mfaEnabled, setMfaEnabled] = useState(false);
  const [isMfaEnforced, setIsMfaEnforced] = useState(false); // Add this state
  const [isLoading, setIsLoading] = useState(false);
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [verificationCode, setVerificationCode] = useState('');

  // Fetch user settings on mount
  useEffect(() => {
    const fetchSettings = async () => {
      try {
        const userData = await api.profile.get();
        setMfaEnabled(userData.mfaEnabled || false);
        setIsMfaEnforced(userData.isMfaEnforced || false); // Store enforcement status
      } catch (error) {
        console.error('Error fetching user settings:', error);
      }
    };

    fetchSettings();
  }, [user]);

  const handleDisableMfa = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!verificationCode.trim()) {
      setMessage({ type: 'error', text: 'Please enter a verification code' });
      return;
    }
    
    try {
      setIsLoading(true);
      await api.mfa.disable(verificationCode);
      setMfaEnabled(false);
      setVerificationCode('');
      setMessage({ type: 'success', text: 'Two-factor authentication disabled successfully' });
    } catch (error: any) {
      setMessage({ 
        type: 'error', 
        text: error.message || 'Failed to disable two-factor authentication' 
      });
    } finally {
      setIsLoading(false);
    }
  };
  
  const handleMfaSetupComplete = async () => {
    setShowMfaSetup(false);
    setMessage({ type: 'success', text: 'Two-factor authentication enabled successfully' });
    
    // Refresh user data from server
    await refreshUserData();
    
    // Get updated MFA status
    try {
      const userData = await api.profile.get();
      setMfaEnabled(userData.mfaEnabled || false);
    } catch (error) {
      console.error('Error refreshing user settings:', error);
    }
  };

  return (
    <Layout>
      <div className="max-w-4xl mx-auto px-4 py-8">
        <h1 className="text-3xl font-bold text-gray-900 mb-8">Settings</h1>
        
        {message && (
          <div className={`mb-6 p-4 rounded-lg ${
            message.type === 'success' ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'
          }`}>
            <div className="flex items-center">
              {message.type === 'success' ? (
                <Check className="h-5 w-5 mr-2" />
              ) : (
                <AlertCircle className="h-5 w-5 mr-2" />
              )}
              {message.text}
            </div>
          </div>
        )}

        {/* MFA Card */}
        <div className="bg-white rounded-lg shadow-md p-6 mb-6">
          <div className="flex justify-between items-center mb-4">
            <div className="flex items-center">
              <Shield className="h-6 w-6 text-[#217eaa] mr-3" />
              <h2 className="text-xl font-semibold">Two-Factor Authentication</h2>
            </div>
            <div>
              <span 
                className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                  mfaEnabled ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-800'
                }`}
              >
                {mfaEnabled ? 'Enabled' : 'Disabled'}
              </span>
            </div>
          </div>
          
          <p className="text-gray-600 mb-6">
            Two-factor authentication adds an extra layer of security to your account by requiring a 
            verification code in addition to your password when signing in.
          </p>

          {showMfaSetup ? (
            <MfaSetup 
              onComplete={handleMfaSetupComplete} 
              onCancel={() => setShowMfaSetup(false)} 
            />
          ) : mfaEnabled ? (
            <>
              {isMfaEnforced ? (
                <div className="bg-blue-100 text-blue-800 p-3 rounded-md mb-4">
                  <div className="flex items-center">
                    <Shield className="h-5 w-5 mr-2" />
                    <span>Two-Factor Authentication is enforced by your organization and cannot be disabled.</span>
                  </div>
                </div>
              ) : (
                <form onSubmit={handleDisableMfa}>
                  <div className="mb-4">
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Enter verification code to disable 2FA
                    </label>
                    <input
                      type="text"
                      value={verificationCode}
                      onChange={(e) => setVerificationCode(e.target.value)}
                      className="w-full rounded-lg border border-gray-300 px-3 py-2 focus:outline-none focus:ring-2 focus:ring-[#217eaa]"
                      placeholder="Enter 6-digit code"
                      maxLength={6}
                    />
                  </div>
                  <button
                    type="submit"
                    disabled={isLoading || !verificationCode}
                    className="bg-red-600 text-white px-4 py-2 rounded-lg hover:bg-red-700 disabled:opacity-50 transition-colors"
                  >
                    {isLoading ? 'Processing...' : 'Disable Two-Factor Authentication'}
                  </button>
                </form>
              )}
            </>
          ) : (
            <button
              onClick={() => setShowMfaSetup(true)}
              className="bg-[#217eaa] text-white px-4 py-2 rounded-lg hover:bg-[#1a6389] transition-colors"
            >
              Enable Two-Factor Authentication
            </button>
          )}
        </div>
        
        {/* Password Security */}
        <div className="bg-white rounded-lg shadow-md p-6">
          <div className="flex items-center mb-4">
            <Key className="h-6 w-6 text-[#217eaa] mr-3" />
            <h2 className="text-xl font-semibold">Password Security</h2>
          </div>
          
          <p className="text-gray-600 mb-6">
            It's recommended to use a strong, unique password and change it periodically.
          </p>
          
          <button
            onClick={() => navigate('/profile')}
            className="bg-[#217eaa] text-white px-4 py-2 rounded-lg hover:bg-[#1a6389] transition-colors"
          >
            Change Password
          </button>
        </div>
      </div>
    </Layout>
  );
}