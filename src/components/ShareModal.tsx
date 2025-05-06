import React, { useState, useEffect } from 'react';
import { X, Copy, Calendar, Eye, Edit2, Download, Mail } from 'lucide-react';
import { api } from '../services/api';
import { motion, AnimatePresence } from 'framer-motion';

interface ShareModalProps {
  onClose: () => void;
  file: {
    id: string;
    name: string;
  };
}

export function ShareModal({ onClose, file }: ShareModalProps) {
  const [permissions, setPermissions] = useState({
    canView: true,
    canEdit: false,
    canDownload: false,
  });
  const [expirationDays, setExpirationDays] = useState<number | null>(null);
  const [recipientEmail, setRecipientEmail] = useState('');
  const [shareUrl, setShareUrl] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [shareCreated, setShareCreated] = useState(false);

  // Convert expiration days dropdown to actual value
  const handleExpirationChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const value = e.target.value;
    if (value === 'never') {
      setExpirationDays(null);
    } else {
      setExpirationDays(parseInt(value, 10));
    }
  };

  const handlePermissionChange = (permission: keyof typeof permissions) => {
    setPermissions({
      ...permissions,
      [permission]: !permissions[permission],
    });
  };

  const handleCreateShare = async () => {
    try {
      setIsLoading(true);
      setError(null);
      
      const data = {
        fileId: file.id,
        permissions,
        expirationDays: expirationDays === null ? undefined : expirationDays,
        recipientEmail: recipientEmail.trim() || undefined
      };
      
      console.log('Creating share with data:', data);
      
      const result = await api.shares.create(data);
      console.log('Share created:', result);
      
      // Make sure the URL displayed to the user is the frontend URL, not the API URL
      // The backend should return a URL like http://localhost:3000/share/token
      setShareUrl(result.shareUrl);
      setShareCreated(true);
    } catch (err: any) {
      console.error('Share error:', err);
      setError(err.message || 'Failed to create share link');
    } finally {
      setIsLoading(false);
    }
  };

  const handleCopy = () => {
    if (shareUrl) {
      navigator.clipboard.writeText(shareUrl);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-xl shadow-xl w-full max-w-lg transform transition-all">
        <div className="flex justify-between items-center p-6 border-b border-neutral-100">
          <h3 className="text-xl font-medium text-gray-900">Share "{file.name}"</h3>
          <button onClick={onClose} className="text-neutral-500 hover:text-neutral-700">
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="p-6">
          {!shareCreated ? (
            <>
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">Share Permissions</label>
                  <div className="space-y-2">
                    <label 
                      className="flex items-center space-x-3 cursor-pointer"
                      onClick={() => handlePermissionChange('canView')}
                    >
                      <input
                        type="checkbox"
                        checked={permissions.canView}
                        onChange={() => {}}
                        className="w-4 h-4 rounded border-[#8ca4ac] text-[#217eaa] focus:ring-[#217eaa]"
                      />
                      <span className="flex items-center text-gray-700">
                        <Eye className="w-4 h-4 mr-2" />
                        View Only
                      </span>
                    </label>
                    <label 
                      className="flex items-center space-x-3 cursor-pointer"
                      onClick={() => handlePermissionChange('canEdit')}
                    >
                      <input
                        type="checkbox"
                        checked={permissions.canEdit}
                        onChange={() => {}}
                        className="w-4 h-4 rounded border-[#8ca4ac] text-[#217eaa] focus:ring-[#217eaa]"
                      />
                      <span className="flex items-center text-gray-700">
                        <Edit2 className="w-4 h-4 mr-2" />
                        Can Edit
                      </span>
                    </label>
                    <label 
                      className="flex items-center space-x-3 cursor-pointer"
                      onClick={() => handlePermissionChange('canDownload')}
                    >
                      <input
                        type="checkbox"
                        checked={permissions.canDownload}
                        onChange={() => {}}
                        className="w-4 h-4 rounded border-[#8ca4ac] text-[#217eaa] focus:ring-[#217eaa]"
                      />
                      <span className="flex items-center text-gray-700">
                        <Download className="w-4 h-4 mr-2" />
                        Can Download
                      </span>
                    </label>
                  </div>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    <Calendar className="w-4 h-4 inline mr-2" />
                    Link Expiration
                  </label>
                  <select
                    value={expirationDays === null ? 'never' : expirationDays.toString()}
                    onChange={handleExpirationChange}
                    className="w-full rounded-lg border border-[#8ca4ac] px-3 py-2 focus:outline-none focus:ring-2 focus:ring-[#217eaa]"
                  >
                    <option value="never">Never Expires</option>
                    <option value="1">1 day</option>
                    <option value="7">7 days</option>
                    <option value="30">30 days</option>
                    <option value="90">90 days</option>
                  </select>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    <Mail className="w-4 h-4 inline mr-2" />
                    Share with Email (optional)
                  </label>
                  <input
                    type="email"
                    value={recipientEmail}
                    onChange={(e) => setRecipientEmail(e.target.value)}
                    placeholder="Enter recipient email"
                    className="w-full rounded-lg border border-[#8ca4ac] px-3 py-2 focus:outline-none focus:ring-2 focus:ring-[#217eaa]"
                  />
                </div>

                {error && (
                  <div className="text-red-500 text-sm">{error}</div>
                )}
              </div>

              <div className="pt-4 flex justify-end">
                <button
                  onClick={onClose}
                  className="mr-4 px-4 py-2 text-[#8ca4ac] hover:text-[#217eaa]"
                >
                  Cancel
                </button>
                <button
                  onClick={handleCreateShare}
                  disabled={isLoading}
                  className="bg-[#217eaa] text-white px-4 py-2 rounded-lg hover:bg-[#1a6389] disabled:opacity-50 transition-colors"
                >
                  {isLoading ? 'Creating...' : 'Create Share Link'}
                </button>
              </div>
            </>
          ) : (
            <>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Share Link</label>
                <div className="flex">
                  <input
                    type="text"
                    readOnly
                    value={shareUrl || ''}
                    className="flex-1 rounded-l-lg border border-[#8ca4ac] px-3 py-2 bg-[#f2f2f3]"
                  />
                  <button 
                    className={`px-4 rounded-r-lg transition-colors flex items-center justify-center ${
                      copied 
                        ? 'bg-green-500 text-white' 
                        : 'bg-[#217eaa] text-white hover:bg-[#7d9cb7]'
                    }`}
                    onClick={handleCopy}
                  >
                    <Copy className="w-4 h-4" />
                  </button>
                </div>
                {copied && (
                  <p className="text-green-500 text-sm mt-1">Link copied to clipboard!</p>
                )}
              </div>

              <div className="pt-4 flex justify-end">
                <button 
                  className="bg-[#217eaa] text-white px-4 py-2 rounded-lg hover:bg-[#1a6389] transition-colors"
                  onClick={onClose}
                >
                  Done
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}