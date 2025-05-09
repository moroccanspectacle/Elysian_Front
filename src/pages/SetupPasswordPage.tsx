import React, { useState, useEffect } from 'react';
import { Link, useParams, useNavigate } from 'react-router-dom';
import { Key, ArrowLeft, AlertCircle, CheckCircle, Loader } from 'lucide-react';
import { api } from '../services/api';
import { validatePassword, getPasswordStrength } from '../utils/passwordValidation';

export function SetupPasswordPage() {
  const { token } = useParams<{ token: string }>();
  const navigate = useNavigate();
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isVerifying, setIsVerifying] = useState(true);
  const [success, setSuccess] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [tokenValid, setTokenValid] = useState(false);
  const [userData, setUserData] = useState<{ username: string, email: string } | null>(null);
  const [passwordErrors, setPasswordErrors] = useState<string[]>([]);
  const [passwordStrength, setPasswordStrength] = useState({ score: 0, label: 'No Password', color: 'bg-gray-200' });
  
  useEffect(() => {
    const verifyToken = async () => {
      if (!token) {
        console.error('Setup Password: Token is missing');
        setError('Invalid setup link');
        setIsVerifying(false);
        return;
      }
      
      console.log('Setup Password: Verifying token', token.substring(0, 5) + '...');
      
      try {
        const response = await api.auth.verifySetupToken(token);
        console.log('Setup Password: Token verified successfully', response);
        setTokenValid(true);
        setUserData(response.user);
      } catch (err: any) {
        console.error('Setup Password: Token verification failed', err);
        setError('This setup link is invalid or has expired');
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
      await api.auth.setupPassword(token!, password);
      setSuccess(true);
      
      // Redirect to login after 3 seconds
      setTimeout(() => {
        navigate('/login');
      }, 3000);
    } catch (err: any) {
      setError(err.message || 'Failed to set up your password');
    } finally {
      setIsSubmitting(false);
    }
  };
  
  if (isVerifying) {
    return (
      <div className="min-h-screen bg-[#eeeeee] flex items-center justify-center p-4">
        <div className="bg-white rounded-xl shadow-lg w-full max-w-md p-8 text-center">
          <Loader className="w-8 h-8 text-primary-600 animate-spin mx-auto mb-4" />
          <p className="text-gray-600">Verifying your setup link...</p>
        </div>
      </div>
    );
  }
  
  return (
    <div className="min-h-screen bg-[#eeeeee] flex items-center justify-center p-4">
      <div className="bg-white rounded-xl shadow-lg w-full max-w-md p-8">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-[#f2f2f3] mb-4">
            <Key className="w-8 h-8 text-primary-600" />
          </div>
          <h1 className="text-2xl font-bold text-gray-900">Set Up Your Password</h1>
        </div>
        
        {success ? (
          <div className="space-y-6">
            <div className="bg-green-50 p-4 rounded-lg flex items-start">
              <CheckCircle className="w-5 h-5 text-green-500 mt-0.5 mr-3 flex-shrink-0" />
              <p className="text-green-700">
                Your password has been set successfully! You'll be redirected to the login page in a moment.
              </p>
            </div>
            
            <div className="text-center">
              <Link to="/login" className="text-primary-600 hover:text-primary-700 inline-flex items-center">
                <ArrowLeft className="w-4 h-4 mr-1" />
                Go to login
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
                  <Link to="/login" className="text-primary-600 hover:text-primary-700 inline-flex items-center">
                    <ArrowLeft className="w-4 h-4 mr-1" />
                    Back to login
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
                
                {userData && (
                  <div className="bg-blue-50 p-4 rounded-lg">
                    <p className="text-blue-700">
                      Setting up account for <strong>{userData.username}</strong> ({userData.email})
                    </p>
                  </div>
                )}
                
                <div>
                  <p className="text-gray-600 mb-4">
                    Please create a secure password for your account.
                  </p>
                  
                  <div className="space-y-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">Password</label>
                      <input
                        type="password"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        className={`w-full rounded-lg border ${
                          passwordErrors.length > 0 ? 'border-red-500' : 'border-gray-300'
                        } px-3 py-2 focus:outline-none focus:ring-2 focus:ring-primary-600`}
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
                      <label className="block text-sm font-medium text-gray-700 mb-1">Confirm Password</label>
                      <input
                        type="password"
                        value={confirmPassword}
                        onChange={(e) => setConfirmPassword(e.target.value)}
                        className="w-full rounded-lg border border-gray-300 px-3 py-2 focus:outline-none focus:ring-2 focus:ring-primary-600"
                        placeholder="••••••••"
                        required
                      />
                    </div>
                  </div>
                </div>
                
                <button 
                  type="submit"
                  disabled={isSubmitting}
                  className="w-full bg-primary-600 text-white rounded-lg px-4 py-2 hover:bg-primary-700 transition-colors disabled:opacity-70"
                >
                  {isSubmitting ? 'Setting up...' : 'Create Password'}
                </button>
              </form>
            )}
          </>
        )}
      </div>
    </div>
  );
}