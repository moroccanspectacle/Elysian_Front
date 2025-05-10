import React, { createContext, useState, useEffect, useContext } from 'react';
import { useNavigate, useLocation } from 'react-router-dom'; // Add useLocation
import { api } from '../services/api';
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:3000/api';

interface AuthContextType {
  user: any | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (email: string, password: string, rememberMe?: boolean) => Promise<{ mfaRequired: boolean }>;
  completeMfaLogin: (mfaToken: string) => Promise<void>; // Renamed token to mfaToken
  register: (username: string, email: string, password: string) => Promise<void>;
  logout: () => void;
  error: string | null;
  updateUser: (userData: Partial<{
    username: string;
    email: string;
    profileImage: string | null;
  }>) => void;
  mfaRequired: boolean;
  mfaSetupRequired: boolean;
  tempUserId: string | null;
  refreshUserData: () => Promise<void>;
  resetMfaSetupState: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<any | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [mfaRequired, setMfaRequired] = useState(false);
  const [tempUserId, setTempUserId] = useState<string | null>(null);
  const [rememberMeOption, setRememberMeOption] = useState(false);
  const [mfaSetupRequired, setMfaSetupRequired] = useState(false);
  const [blockRedirects, setBlockRedirects] = useState(false);
  const navigate = useNavigate();
  const location = useLocation(); // Get current location for redirect logic

  const checkLoggedIn = async () => {
    const currentPath = window.location.pathname;
    if (currentPath.startsWith('/setup-password/') || currentPath.startsWith('/reset-password/')) {
      console.log('Setup/reset page detected, skipping auth check');
      setIsLoading(false);
      return;
    }

    const mfaSetupInProgress = sessionStorage.getItem('mfa-setup-in-progress') === 'true';
    const localStorageBlock = localStorage.getItem('mfa-setup-block') === 'true';

    if (mfaSetupInProgress || localStorageBlock || blockRedirects || mfaSetupRequired) {
      return;
    }

    const token = localStorage.getItem('auth-token');
    if (token) {
      setIsLoading(true);
      try {
        const response = await fetch(`${API_BASE_URL}/user/verify`, {
          headers: {
            'auth-token': token
          }
        });

        if (response.ok) {
          const userData = await response.json();
          setUser(userData);

          if (userData.needsMfaSetup) {
            setMfaSetupRequired(true);
            setIsLoading(false);
            return;
          }

          if (!mfaSetupRequired) {
            const noRedirectPaths = ['/profile', '/settings', '/admin', '/dashboard', '/teams', '/shared-links', '/vault'];
            const currentPath = window.location.pathname;

            if (currentPath.startsWith('/setup-password') || currentPath.startsWith('/reset-password')) {
              console.log('On password setup/reset page, preventing redirect');
            } else if (!noRedirectPaths.some(path => currentPath.toLowerCase().includes(path.toLowerCase()))) {
              console.log('Redirecting from', currentPath);
              if (userData.role === 'admin' || userData.role === 'super_admin') {
                navigate('/admin');
              } else {
                navigate('/dashboard');
              }
            }
          }
        } else {
          localStorage.removeItem('auth-token');
          setUser(null);
        }
      } catch (error) {
        console.error("Auth verification error:", error);
      } finally {
        setIsLoading(false);
      }
    } else {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    checkLoggedIn();
  }, [navigate]);

  const login = async (email: string, password: string, rememberMe = false) => {
    setError(null);
    setRememberMeOption(rememberMe);
    try {
      const response = await fetch(`${API_BASE_URL}/user/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });

      let data;
      const contentType = response.headers.get('content-type');
      if (contentType && contentType.includes('application/json')) {
        data = await response.json();
      } else {
        const textData = await response.text();
        if (response.ok) {
          data = textData;
        } else {
          try {
            data = JSON.parse(textData);
          } catch (e) {
            throw new Error(textData || `Login failed with status: ${response.status}`);
          }
        }
      }

      if (!response.ok) {
        const errorMessage = typeof data === 'object' && data.error ? data.error : (typeof data === 'string' ? data : 'Login failed');
        throw new Error(errorMessage);
      }

      if (typeof data === 'object' && data.mfaRequired && data.setupRequired) {
        sessionStorage.setItem('temp-user-id', data.userId);
        if (data.setupToken) {
          sessionStorage.setItem('mfa-setup-token', data.setupToken);
        }
        setTempUserId(data.userId);
        setMfaSetupRequired(true);
        setBlockRedirects(true);
        sessionStorage.setItem('mfa-setup-in-progress', 'true');
        localStorage.setItem('mfa-setup-block', 'true');
        return { mfaRequired: true, setupRequired: true };
      }

      if (typeof data === 'object' && data.mfaRequired) {
        setTempUserId(data.userId);
        setMfaRequired(true);
        return { mfaRequired: true };
      }

      sessionStorage.removeItem('mfa-setup-in-progress');
      sessionStorage.removeItem('mfa-setup-token');
      localStorage.removeItem('mfa-setup-block');
      setBlockRedirects(false);
      setMfaSetupRequired(false);

      const token = typeof data === 'object' ? data.token : data;
      localStorage.setItem('auth-token', token);

      const userResponse = await fetch(`${API_BASE_URL}/user/verify`, {
        headers: { 'auth-token': token }
      });

      if (userResponse.ok) {
        const userData = await userResponse.json();
        setUser(userData);

        setTimeout(() => {
          const loginRedirectState = location.state as { from?: string, reason?: string };
          if (loginRedirectState?.reason === 'private_share_access' && loginRedirectState?.from) {
            console.log('[AuthContext] Redirecting back to private share:', loginRedirectState.from);
            navigate(loginRedirectState.from, { replace: true });
          } else {
            if (userData.role === 'admin' || userData.role === 'super_admin') {
              navigate('/admin', { replace: true });
            } else {
              navigate('/dashboard', { replace: true });
            }
          }
        }, 100);
      } else {
        localStorage.removeItem('auth-token');
        throw new Error("Failed to verify user after login.");
      }

      return { mfaRequired: false };
    } catch (err: any) {
      setError(err.message);
      return { mfaRequired: false };
    }
  };

  const completeMfaLogin = async (mfaToken: string) => {
    setError(null);
    try {
      if (!tempUserId) {
        throw new Error('No pending MFA verification');
      }

      const isSetupMode = mfaSetupRequired;

      const response = await fetch(`${API_BASE_URL}/user/login/verify-mfa`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          userId: tempUserId,
          token: mfaToken,
          rememberMe: rememberMeOption,
          isSetupMode
        }),
      });

      if (!response.ok) {
        const errorData = await response.text();
        try {
          const parsedError = JSON.parse(errorData);
          throw new Error(parsedError.error || 'MFA verification failed');
        } catch (e) {
          throw new Error(errorData || 'MFA verification failed');
        }
      }

      const jwtToken = await response.text();
      localStorage.setItem('auth-token', jwtToken);

      const userResponse = await fetch(`${API_BASE_URL}/user/verify`, {
        headers: { 'auth-token': jwtToken }
      });

      if (userResponse.ok) {
        const userData = await userResponse.json();
        setUser(userData);
        setMfaRequired(false);
        setTempUserId(null);
        setMfaSetupRequired(false);
        sessionStorage.removeItem('mfa-setup-in-progress');
        localStorage.removeItem('mfa-setup-block');
        setBlockRedirects(false);

        const loginRedirectState = location.state as { from?: string, reason?: string };
        if (loginRedirectState?.reason === 'private_share_access' && loginRedirectState?.from) {
          console.log('[AuthContext] Redirecting back to private share after MFA:', loginRedirectState.from);
          navigate(loginRedirectState.from, { replace: true });
        } else {
          if (userData.role === 'admin' || userData.role === 'super_admin') {
            navigate('/admin', { replace: true });
          } else {
            navigate('/dashboard', { replace: true });
          }
        }
      } else {
        localStorage.removeItem('auth-token');
        throw new Error("Failed to verify user after MFA.");
      }
    } catch (err: any) {
      setError(err.message);
    }
  };

  const register = async (username: string, email: string, password: string) => {
    setError(null);
    try {
      const response = await fetch(`${API_BASE_URL}/user/register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, email, password }),
      });

      if (!response.ok) {
        const errorData = await response.text();
        throw new Error(errorData || 'Registration failed');
      }

      await login(email, password);
    } catch (err: any) {
      setError(err.message);
    }
  };

  const logout = () => {
    localStorage.removeItem('auth-token');
    setUser(null);
    navigate('/');
  };

  const updateUser = (userData: Partial<{
    username: string;
    email: string;
    profileImage: string | null;
  }>) => {
    if (user) {
      setUser({
        ...user,
        ...userData
      });
    }
  };

  const refreshUserData = async () => {
    try {
      const token = localStorage.getItem('auth-token') || sessionStorage.getItem('auth-token');
      if (!token) return;

      const userResponse = await fetch(`${API_BASE_URL}/profile`, {
        headers: {
          'auth-token': token
        }
      });

      if (userResponse.ok) {
        const userData = await userResponse.json();
        setUser({
          ...user,
          ...userData
        });
      }
    } catch (error) {
      console.error('Error refreshing user data:', error);
    }
  };

  const resetMfaSetupState = () => {
    sessionStorage.removeItem('mfa-setup-in-progress');
    sessionStorage.removeItem('mfa-setup-token');
    sessionStorage.removeItem('temp-user-id');
    localStorage.removeItem('mfa-setup-block');
    setBlockRedirects(false);
    setMfaSetupRequired(false);
    setMfaRequired(false);
    setTempUserId(null);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated: !!user,
        isLoading,
        mfaRequired,
        mfaSetupRequired,
        tempUserId,
        login,
        completeMfaLogin,
        register,
        logout,
        updateUser,
        refreshUserData,
        resetMfaSetupState,
        error
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};