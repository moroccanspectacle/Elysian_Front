import React, { useState, useEffect } from 'react';
import { Lock } from 'lucide-react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../components/AuthContext';
import { MfaVerification } from './MfaVerification';
import { MfaSetup } from './MfaSetup';
import { validatePassword, getPasswordStrength } from '../utils/passwordValidation';

interface AuthFormProps {
  mode: 'login' | 'register';
}

export function AuthForm({ mode }: AuthFormProps) {
  const navigate = useNavigate();
  const { login, register, error: authError, mfaRequired, mfaSetupRequired, completeMfaLogin } = useAuth();
  
  console.log("AuthForm render, mfaRequired:", mfaRequired, "mfaSetupRequired:", mfaSetupRequired);

  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: ''
  });
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [passwordErrors, setPasswordErrors] = useState<string[]>([]);
  const [passwordStrength, setPasswordStrength] = useState({ score: 0, label: 'No Password', color: 'bg-gray-200' });
  const [rememberMe, setRememberMe] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const mfaToken = sessionStorage.getItem('mfa-setup-token');
    console.log('Available MFA token in AuthForm:', mfaToken ? 'present' : 'missing');
    
    // Also list all session storage items for debugging
    const allKeys = [];
    for (let i = 0; i < sessionStorage.length; i++) {
      allKeys.push(sessionStorage.key(i));
    }
    console.log('All sessionStorage keys:', allKeys);
  }, []);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    
    setFormData({
      ...formData,
      [name]: value
    });
    
    // Validate password on change
    if (name === 'password') {
      const { errors } = validatePassword(value);
      setPasswordErrors(errors);
      setPasswordStrength(getPasswordStrength(value));
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    // For registration, validate password before submitting
    if (mode === 'register') {
      const { valid, errors } = validatePassword(formData.password);
      if (!valid) {
        setPasswordErrors(errors);
        return;
      }
    }
    
    setIsSubmitting(true);
    
    try {
      if (mode === 'login') {
        const result = await login(formData.email, formData.password, rememberMe);
        // If MFA is required, the MfaVerification component will be shown
        // and this component will not redirect
        if (!result?.mfaRequired) {
          navigate('/dashboard');
        }
      } else {
        await register(formData.username, formData.email, formData.password);
        navigate('/dashboard');
      }
    } catch (error) {
      // Errors are handled in the Auth context
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleMfaVerify = async (code: string) => {
    try {
      await completeMfaLogin(code);
      navigate('/dashboard');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to verify');
    }
  };

  // If MFA is required during login, show the MFA verification component
  if (mfaRequired) {
    return <MfaVerification onVerify={handleMfaVerify} />;
  }

  if (mfaSetupRequired) {
    console.log("Rendering MFA setup screen");
    
    // Force the URL to match what we're showing to avoid navigation issues
    if (window.location.pathname !== '/mfa-setup') {
      window.history.replaceState(null, '', '/mfa-setup');
    }
    
    return <MfaSetup 
      onComplete={async (code) => {
        try {
          await completeMfaLogin(code);
          
          // Clear all MFA setup flags
          sessionStorage.removeItem('mfa-setup-in-progress');
          localStorage.removeItem('mfa-setup-block');
          
          navigate('/dashboard');
        } catch (err) {
          setError(err instanceof Error ? err.message : 'Failed to verify');
        }
      }}
      onCancel={() => {
        const { logout } = useAuth();
        
        // Clear all MFA setup flags
        sessionStorage.removeItem('mfa-setup-in-progress');
        localStorage.removeItem('mfa-setup-block');
        
        logout();
      }}
      enforced={true}
    />;
  }

  return (
    <div className="min-h-screen bg-[#eeeeee] flex items-center justify-center p-4">
      <div className="bg-white rounded-xl shadow-lg w-full max-w-md p-8">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-[#f2f2f3] mb-4">
            <Lock className="w-8 h-8 text-[#217eaa]" />
          </div>
          <h1 className="text-2xl font-bold text-gray-900">Elysian Vault</h1>
          <p className="text-[#8ca4ac] mt-2">Secure document sharing made simple</p>
        </div>

        {/* Use authError from the context here */}
        {authError && (
          <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4">
            {authError}
          </div>
        )}

        <form className="space-y-4" onSubmit={handleSubmit}>
          {mode === 'register' && (
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Username</label>
              <input
                name="username"
                type="text"
                value={formData.username}
                onChange={handleChange}
                className="w-full rounded-lg border border-[#8ca4ac] px-3 py-2 focus:outline-none focus:ring-2 focus:ring-[#217eaa]"
                placeholder="johndoe"
                required
              />
            </div>
          )}

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Email</label>
            <input
              name="email"
              type="email"
              value={formData.email}
              onChange={handleChange}
              className="w-full rounded-lg border border-[#8ca4ac] px-3 py-2 focus:outline-none focus:ring-2 focus:ring-[#217eaa]"
              placeholder="you@example.com"
              required
            />
          </div>

          <div>
            <div className="flex justify-between items-center mb-1">
              <label className="block text-sm font-medium text-gray-700">Password</label>
              {mode === 'login' && (
                <Link to="/forgot-password" className="text-sm text-[#217eaa] hover:text-[#7d9cb7]">
                  Forgot password?
                </Link>
              )}
            </div>
            <input
              name="password"
              type="password"
              value={formData.password}
              onChange={handleChange}
              className={`w-full rounded-lg border ${
                passwordErrors.length > 0 && mode === 'register' ? 'border-red-500' : 'border-[#8ca4ac]'
              } px-3 py-2 focus:outline-none focus:ring-2 focus:ring-[#217eaa]`}
              placeholder="••••••••"
              required
            />
            
            {/* Password strength indicator (for register mode) */}
            {mode === 'register' && formData.password && (
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
                
                {/* Password requirements */}
                <div className="mt-2 space-y-1">
                  {passwordErrors.map((error, index) => (
                    <p key={index} className="text-xs text-red-500">{error}</p>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Remember Me Checkbox */}
          {mode === 'login' && (
            <div className="flex items-center justify-between">
              <div className="flex items-center">
                <input
                  id="remember-me"
                  name="remember-me"
                  type="checkbox"
                  checked={rememberMe}
                  onChange={(e) => setRememberMe(e.target.checked)}
                  className="h-4 w-4 text-[#217eaa] focus:ring-[#1a6389] border-gray-300 rounded"
                />
                <label htmlFor="remember-me" className="ml-2 block text-sm text-gray-900">
                  Remember me
                </label>
              </div>
            </div>
          )}

          <div>
            <button 
              type="submit"
              disabled={isSubmitting}
              className="w-full bg-[#217eaa] text-white rounded-lg px-4 py-2 hover:bg-[#7d9cb7] transition-colors disabled:opacity-70"
            >
              {isSubmitting 
                ? 'Processing...' 
                : mode === 'login' ? 'Sign In' : 'Create Account'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}