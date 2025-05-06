import React, { useState, useEffect } from 'react';
import { Layout } from '../components/Layout';
import { api } from '../services/api';
import { Clock, Eye, Download, Edit2, ToggleLeft, ToggleRight, AlertTriangle, ExternalLink, Link } from 'lucide-react';
import { format } from 'date-fns';
import { motion } from 'framer-motion';

interface SharedLink {
  id: number;
  shareToken: string;
  fileId: string;
  fileName: string;
  isActive: boolean;
  expiresAt: string | null;
  permissions: {
    canView: boolean;
    canEdit: boolean;
    canDownload: boolean;
  };
  accessCount: number;
  createdAt: string;
}

export function SharedLinksPage() {
  const [sharedLinks, setSharedLinks] = useState<SharedLink[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  
  useEffect(() => {
    fetchSharedLinks();
  }, []);
  
  const fetchSharedLinks = async () => {
    try {
      setIsLoading(true);
      const response = await api.shares.listMyShares();
      setSharedLinks(response);
      setIsLoading(false);
    } catch (err) {
      console.error('Failed to fetch shared links:', err);
      setError('Failed to load shared links');
      setIsLoading(false);
    }
  };
  
  const toggleShareStatus = async (id: number, currentStatus: boolean) => {
    try {
      await api.shares.updateStatus(id, !currentStatus);
      // Update local state to reflect the change
      setSharedLinks(sharedLinks.map(link => 
        link.id === id ? { ...link, isActive: !currentStatus } : link
      ));
    } catch (err) {
      console.error('Failed to update share status:', err);
      alert('Failed to update share status');
    }
  };

  const copyLinkToClipboard = (shareToken: string) => {
    const shareUrl = `${window.location.origin}/share/${shareToken}`;
    navigator.clipboard.writeText(shareUrl);
    alert('Link copied to clipboard!');
  };
  
  return (
    <Layout>
      <div className="max-w-7xl mx-auto">
        <motion.h1 
          className="text-3xl font-display font-semibold text-gray-900 mb-8"
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
        >
          My Shared Links
        </motion.h1>
        
        {isLoading ? (
          <div className="flex justify-center my-12">
            <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-primary-500"></div>
          </div>
        ) : error ? (
          <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg">
            {error}
          </div>
        ) : sharedLinks.length === 0 ? (
          <div className="text-center py-12 bg-white rounded-lg shadow-sm">
            <Link className="w-16 h-16 text-neutral-300 mx-auto mb-4" />
            <h2 className="text-xl font-medium text-gray-700 mb-2">No shared links yet</h2>
            <p className="text-neutral-500 mb-6">
              When you share files, your links will appear here for easy management.
            </p>
          </div>
        ) : (
          <div className="bg-white rounded-lg shadow-sm overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="bg-neutral-50 border-b border-neutral-200">
                    <th className="px-6 py-3 text-left text-xs font-medium text-neutral-500 uppercase tracking-wider">File</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-neutral-500 uppercase tracking-wider">Created</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-neutral-500 uppercase tracking-wider">Expires</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-neutral-500 uppercase tracking-wider">Permissions</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-neutral-500 uppercase tracking-wider">Views</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-neutral-500 uppercase tracking-wider">Status</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-neutral-500 uppercase tracking-wider">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-neutral-200">
                  {sharedLinks.map((link) => (
                    <tr key={link.id} className="hover:bg-neutral-50">
                      <td className="px-6 py-4 whitespace-nowrap text-sm font-medium truncate max-w-xs">
                        {link.fileName}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-neutral-500">
                        {format(new Date(link.createdAt), 'MMM d, yyyy')}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-neutral-500">
                        {link.expiresAt ? (
                          <span className="flex items-center">
                            <Clock className="w-4 h-4 mr-1 text-orange-500" />
                            {format(new Date(link.expiresAt), 'MMM d, yyyy')}
                          </span>
                        ) : (
                          <span className="text-neutral-400">Never</span>
                        )}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-neutral-500">
                        <div className="flex space-x-2">
                          {link.permissions.canView && (
                            <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-blue-100 text-blue-800">
                              <Eye className="w-3 h-3 mr-1" />
                              View
                            </span>
                          )}
                          {link.permissions.canEdit && (
                            <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-purple-100 text-purple-800">
                              <Edit2 className="w-3 h-3 mr-1" />
                              Edit
                            </span>
                          )}
                          {link.permissions.canDownload && (
                            <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-green-100 text-green-800">
                              <Download className="w-3 h-3 mr-1" />
                              Download
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-neutral-500">
                        {link.accessCount}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        {link.isActive ? (
                          <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                            Active
                          </span>
                        ) : (
                          <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800">
                            Disabled
                          </span>
                        )}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-neutral-500 space-x-2">
                        <button 
                          onClick={() => toggleShareStatus(link.id, link.isActive)}
                          className="inline-flex items-center p-1 rounded text-gray-600 hover:bg-gray-100"
                          title={link.isActive ? "Disable share" : "Enable share"}
                        >
                          {link.isActive ? 
                            <ToggleRight className="w-5 h-5 text-green-600" /> : 
                            <ToggleLeft className="w-5 h-5 text-red-600" />
                          }
                        </button>
                        <button 
                          onClick={() => copyLinkToClipboard(link.shareToken)}
                          className="inline-flex items-center p-1 rounded text-gray-600 hover:bg-gray-100"
                          title="Copy share link"
                        >
                          <ExternalLink className="w-5 h-5 text-blue-600" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </Layout>
  );
}