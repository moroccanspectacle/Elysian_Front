import React, { useState } from 'react';
import { FileText, Download, Share2, Trash2, Shield, AlertTriangle, Eye } from 'lucide-react';
import type { FileItem } from '../types';
import { api } from '../services/api';
import { motion } from 'framer-motion';

interface FileCardProps {
  file: FileItem;
  onShare: () => void;
  onDownload: () => void;
  onDelete: () => void;
  onView: () => void;
  onMoveToVault?: () => void;
}

export function FileCard({ file, onShare, onDownload, onDelete, onView, onMoveToVault }: FileCardProps) {
  const [integrityStatus, setIntegrityStatus] = useState<'unchecked' | 'checking' | 'verified' | 'failed'>('unchecked');
  
  const checkIntegrity = async () => {
    setIntegrityStatus('checking');
    try {
      const result = await api.files.verifyIntegrity(file.id);
      setIntegrityStatus(result.integrityVerified ? 'verified' : 'failed');
    } catch (error) {
      console.error('Integrity check error:', error);
      setIntegrityStatus('failed');
    }
  };

  const getFileTypeColor = (type: string) => {
    switch(type) {
      case 'pdf': return 'from-red-400 to-red-500';
      case 'word': return 'from-blue-400 to-blue-500';
      case 'excel': return 'from-green-400 to-green-500';
      case 'image': return 'from-purple-400 to-purple-500';
      default: return 'from-neutral-400 to-neutral-500';
    }
  };
  
  return (
    <motion.div 
      className="bg-white rounded-xl shadow-sm hover:shadow-md transition-all duration-300 overflow-hidden group"
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, scale: 0.95 }}
      whileHover={{ y: -5 }}
      transition={{ type: "spring", stiffness: 300, damping: 20 }}
    >
      <div className="p-5">
        <div className="flex items-start space-x-4">
          <div className={`w-12 h-12 rounded-lg bg-gradient-to-br ${getFileTypeColor(file.type)} flex items-center justify-center text-white shadow-sm`}>
            <FileText className="w-6 h-6" />
          </div>
          <div className="flex-grow min-w-0">
            <h3 className="font-medium text-gray-900 truncate">{file.name}</h3>
            <div className="flex items-center text-sm text-neutral-500 space-x-2 mt-1">
              <span>{file.size}</span>
              <span className="w-1 h-1 rounded-full bg-neutral-300"></span>
              <span>{file.uploadDate}</span>
            </div>
          </div>
          {integrityStatus !== 'unchecked' && (
            <div>
              {integrityStatus === 'checking' && (
                <div className="animate-spin rounded-full h-4 w-4 border-2 border-primary-500 border-t-transparent" />
              )}
              {integrityStatus === 'verified' && (
                <div title="File integrity verified">
                  <Shield className="w-4 h-4 text-green-500" />
                </div>
              )}
              {integrityStatus === 'failed' && (
                <div title="File integrity check failed">
                  <AlertTriangle className="w-4 h-4 text-red-500" />
                </div>
              )}
            </div>
          )}
        </div>
      </div>
      
      <div className="border-t border-neutral-100 px-5 py-3 bg-neutral-50 flex items-center justify-between">
        <button
          className="p-2 rounded-md text-neutral-500 hover:text-primary-500 hover:bg-primary-50 transition-colors"
          title="Verify Integrity"
          onClick={checkIntegrity}
        >
          <Shield className="w-4 h-4" />
        </button>
        
        <div className="flex space-x-1">
          <button
            className="p-2 rounded-md text-neutral-500 hover:text-primary-500 hover:bg-primary-50 transition-colors"
            title="View"
            onClick={onView}
          >
            <Eye className="w-4 h-4" />
          </button>
          <button
            className="p-2 rounded-md text-neutral-500 hover:text-primary-500 hover:bg-primary-50 transition-colors"
            title="Download"
            onClick={onDownload}
          >
            <Download className="w-4 h-4" />
          </button>
          <button
            className="p-2 rounded-md text-neutral-500 hover:text-primary-500 hover:bg-primary-50 transition-colors"
            title="Share"
            onClick={onShare}
          >
            <Share2 className="w-4 h-4" />
          </button>
          <button
            className="p-2 rounded-md text-neutral-500 hover:text-red-500 hover:bg-red-50 transition-colors"
            title="Delete"
            onClick={onDelete}
          >
            <Trash2 className="w-4 h-4" />
          </button>
          {onMoveToVault && (
            <button
              className="p-2 rounded-md text-neutral-500 hover:text-primary-500 hover:bg-primary-50 transition-colors"
              title="Move to Vault"
              onClick={onMoveToVault}
            >
              <Shield className="w-4 h-4" />
            </button>
          )}
        </div>
      </div>
    </motion.div>
  );
}