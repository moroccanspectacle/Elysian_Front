import React, { useState, useEffect } from 'react';
import { Link, useParams, useNavigate } from 'react-router-dom';
import { Key, ArrowLeft, AlertCircle, CheckCircle, Loader } from 'lucide-react';
import { api } from '../services/api';
import { validatePassword, getPasswordStrength } from '../utils/passwordValidation';

export function ResetPasswordPage() {
  const { token } = useParams<{ token: string }>();
  const navigate = useNavigate();
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isVerifying, setIsVerifying] = useState(true);
  const [success, setSuccess] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [tokenValid, setTokenValid] = useState(false);
  const [passwordErrors, setPasswordErrors] = useState<string[]>([]);
  const [passwordStrength, setPasswordStrength] = useState({ score: 0, label: 'No Password', color: 'bg-gray-200' });
  
  useEffect(() => {
    const verifyToken = async () => {
      if (!token) {
        setError('Invalid reset link');
        setIsVerifying(false);
        return;
      }
      
      try {
        const response = await api.auth.verifyResetToken(token);
        setTokenValid(true);
      } catch (err: any) {
        setError('This password reset link is invalid or has expired');
      } finally {
        setIsVerifying(false);
      }
    };
    
    verifyToken();
  }, [token]);
  
  useEffect(() => {
    if (password) {
      const { errors } = validatePassword(password);
      setPasswordErrors(errors);
      setPasswordStrength(getPasswordStrength(password));
    } else {
      setPasswordErrors([]);
      setPasswordStrength({ score: 0, label: 'No Password', color: 'bg-gray-200' });
    }
  }, [password]);
  
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!password) {
      setError('Password is required');
      return;
    }
    
    if (password !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }
    
    const { valid, errors } = validatePassword(password);
    if (!valid) {
      setError(errors[0]);
      return;
    }
    
    setIsSubmitting(true);
    setError(null);
    
    try {
      await api.auth.resetPassword(token!, password);
      setSuccess(true);
      
      // Redirect to login after 3 seconds
      setTimeout(() => {
        navigate('/login');
      }, 3000);
    } catch (err: any) {
      setError(err.message || 'Failed to reset password');
    } finally {
      setIsSubmitting(false);
    }
  };
  
  if (isVerifying) {
    return (
      <div className="min-h-screen bg-[#eeeeee] flex items-center justify-center p-4">
        <div className="bg-white rounded-xl shadow-lg w-full max-w-md p-8 text-center">
          <Loader className="w-8 h-8 text-[#217eaa] animate-spin mx-auto mb-4" />
          <p className="text-gray-600">Verifying your reset link...</p>
        </div>
      </div>
    );
  }
  
  return (
    <div className="min-h-screen bg-[#eeeeee] flex items-center justify-center p-4">
      <div className="bg-white rounded-xl shadow-lg w-full max-w-md p-8">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-[#f2f2f3] mb-4">
            <Key className="w-8 h-8 text-[#217eaa]" />
          </div>
          <h1 className="text-2xl font-bold text-gray-900">Reset Your Password</h1>
        </div>
        
        {success ? (
          <div className="space-y-6">
            <div className="bg-green-50 p-4 rounded-lg flex items-start">
              <CheckCircle className="w-5 h-5 text-green-500 mt-0.5 mr-3 flex-shrink-0" />
              <p className="text-green-700">
                Your password has been reset successfully! You'll be redirected to the login page in a moment.
              </p>
            </div>
            
            <div className="text-center">
              <Link to="/login" className="text-[#217eaa] hover:text-[#7d9cb7] inline-flex items-center">
                <ArrowLeft className="w-4 h-4 mr-1" />
                Back to login
              </Link>
            </div>
          </div>
        ) : (
          <>
            {!tokenValid ? (
              <div className="space-y-6">
                <div className="bg-red-50 p-4 rounded-lg flex items-start">
                  <AlertCircle className="w-5 h-5 text-red-500 mt-0.5 mr-3 flex-shrink-0" />
                  <p className="text-red-700">{error}</p>
                </div>
                
                <div className="text-center">
                  <Link to="/forgot-password" className="text-[#217eaa] hover:text-[#7d9cb7]">
                    Request a new password reset link
                  </Link>
                </div>
              </div>
            ) : (
              <form onSubmit={handleSubmit} className="space-y-6">
                {error && (
                  <div className="bg-red-50 p-4 rounded-lg flex items-start">
                    <AlertCircle className="w-5 h-5 text-red-500 mt-0.5 mr-3 flex-shrink-0" />
                    <p className="text-red-700">{error}</p>
                  </div>
                )}
                
                <div>
                  <p className="text-gray-600 mb-4">
                    Enter your new password below.
                  </p>
                  
                  <div className="space-y-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">New Password</label>
                      <input
                        type="password"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        className={`w-full rounded-lg border ${
                          passwordErrors.length > 0 ? 'border-red-500' : 'border-[#8ca4ac]'
                        } px-3 py-2 focus:outline-none focus:ring-2 focus:ring-[#217eaa]`}
                        placeholder="••••••••"
                        required
                      />
                      
                      {password && (
                        <div className="mt-2">
                          <div className="flex items-center justify-between mb-1">
                            <span className="text-xs text-gray-500">Password strength:</span>
                            <span className="text-xs font-medium" style={{ color: passwordStrength.color.replace('bg-', 'text-') }}>
                              {passwordStrength.label}
                            </span>
                          </div>
                          <div className="h-1.5 w-full bg-gray-200 rounded-full overflow-hidden">
                            <div 
                              className={`h-full ${passwordStrength.color}`} 
                              style={{ width: `${(passwordStrength.score / 5) * 100}%` }}
                            ></div>
                          </div>
                          
                          {passwordErrors.length > 0 && (
                            <div className="mt-2 space-y-1">
                              {passwordErrors.map((error, index) => (
                                <p key={index} className="text-xs text-red-500">{error}</p>
                              ))}
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                    
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">Confirm New Password</label>
                      <input
                        type="password"
                        value={confirmPassword}
                        onChange={(e) => setConfirmPassword(e.target.value)}
                        className="w-full rounded-lg border border-[#8ca4ac] px-3 py-2 focus:outline-none focus:ring-2 focus:ring-[#217eaa]"
                        placeholder="••••••••"
                        required
                      />
                    </div>
                  </div>
                </div>
                
                <button 
                  type="submit"
                  disabled={isSubmitting}
                  className="w-full bg-[#217eaa] text-white rounded-lg px-4 py-2 hover:bg-[#7d9cb7] transition-colors disabled:opacity-70"
                >
                  {isSubmitting ? 'Processing...' : 'Reset Password'}
                </button>
                
                <div className="text-center text-sm text-[#8ca4ac]">
                  <Link to="/login" className="text-[#217eaa] hover:text-[#7d9cb7] inline-flex items-center">
                    <ArrowLeft className="w-4 h-4 mr-1" />
                    Back to login
                  </Link>
                </div>
              </form>
            )}
          </>
        )}
      </div>
    </div>
  );
}