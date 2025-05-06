import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { Mail, ArrowLeft, AlertCircle, CheckCircle } from 'lucide-react';
import { api } from '../services/api';

export function ForgotPasswordPage() {
  const [email, setEmail] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [success, setSuccess] = useState(false);
  const [error, setError] = useState<string | null>(null);
  
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!email) {
      setError('Email is required');
      return;
    }
    
    setIsSubmitting(true);
    setError(null);
    
    try {
      await api.auth.forgotPassword(email);
      setSuccess(true);
    } catch (err: any) {
      setError(err.message || 'Failed to process request');
    } finally {
      setIsSubmitting(false);
    }
  };
  
  return (
    <div className="min-h-screen bg-[#eeeeee] flex items-center justify-center p-4">
      <div className="bg-white rounded-xl shadow-lg w-full max-w-md p-8">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-[#f2f2f3] mb-4">
            <Mail className="w-8 h-8 text-[#217eaa]" />
          </div>
          <h1 className="text-2xl font-bold text-gray-900">Reset Your Password</h1>
        </div>
        
        {success ? (
          <div className="space-y-6">
            <div className="bg-green-50 p-4 rounded-lg flex items-start">
              <CheckCircle className="w-5 h-5 text-green-500 mt-0.5 mr-3 flex-shrink-0" />
              <p className="text-green-700">
                If your email exists in our system, we've sent you instructions to reset your password. Please check your inbox.
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
          <form onSubmit={handleSubmit} className="space-y-6">
            {error && (
              <div className="bg-red-50 p-4 rounded-lg flex items-start">
                <AlertCircle className="w-5 h-5 text-red-500 mt-0.5 mr-3 flex-shrink-0" />
                <p className="text-red-700">{error}</p>
              </div>
            )}
            
            <div>
              <p className="text-gray-600 mb-4">
                Enter your email address and we'll send you instructions to reset your password.
              </p>
              
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Email</label>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full rounded-lg border border-[#8ca4ac] px-3 py-2 focus:outline-none focus:ring-2 focus:ring-[#217eaa]"
                  placeholder="you@example.com"
                  required
                />
              </div>
            </div>
            
            <button 
              type="submit"
              disabled={isSubmitting}
              className="w-full bg-[#217eaa] text-white rounded-lg px-4 py-2 hover:bg-[#7d9cb7] transition-colors disabled:opacity-70"
            >
              {isSubmitting ? 'Processing...' : 'Send Reset Instructions'}
            </button>
            
            <div className="text-center text-sm text-[#8ca4ac]">
              <Link to="/login" className="text-[#217eaa] hover:text-[#7d9cb7] inline-flex items-center">
                <ArrowLeft className="w-4 h-4 mr-1" />
                Back to login
              </Link>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}