import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Layout } from '../components/Layout';
import { api } from '../services/api';
import { LoadingSpinner } from '../components/LoadingSpinner';
import { EmptyState } from '../components/EmptyState';
import { DocumentViewer } from '../components/DocumentViewer';
import { useAuth } from '../components/AuthContext';
import { Shield, Lock, Eye, Download, Trash2, AlertTriangle, Calendar } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { PinEntryModal } from '../components/PinEntryModal';


export interface VaultFile {
  id: string; 
  fileId: string; 
  fileName: string;
  fileSize: number;
  fileType: string;
  uploadDate: string;
  lastAccessed: string | null;
  selfDestruct: boolean;
  destructAfter: string | null;
}

export function VaultPage() {
  const [vaultFiles, setVaultFiles] = useState<VaultFile[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [viewingFile, setViewingFile] = useState<{ // State for DocumentViewer props
    url: string;
    name: string;
    type: string;
    originalFileId: string; // Store original file ID for download/share from viewer
  } | null>(null);
  // const [showMfa, setShowMfa] = useState(false);
  // const [selectedFileId, setSelectedFileId] = useState<string | null>(null);
  // const [actionType, setActionType] = useState<'view' | 'download' | null>(null);

  // Add state for PIN modal
  const [showPinModal, setShowPinModal] = useState(false);
  const [pinActionFile, setPinActionFile] = useState<VaultFile | null>(null); // Store the full file item
  const [pinActionType, setPinActionType] = useState<'view' | 'download' | null>(null);
  const [pinError, setPinError] = useState<string | null>(null);
  // const [viewingFileUrl, setViewingFileUrl] = useState<string | null>(null); // viewingFile state handles this now

  const [permissions, setPermissions] = useState<{
    hasAccess: boolean;
    quota: number;
    usage: number;
    remaining: number;
    unlimited: boolean;
  } | null>(null);

  const navigate = useNavigate();
  const { user } = useAuth(); // Keep user if needed

  useEffect(() => {
    fetchVaultFiles();
    fetchVaultPermissions();
  }, []);

  const fetchVaultFiles = async () => {
    try {
      setIsLoading(true);
      setError(null);
      const files = await api.vault.list();
      setVaultFiles(files);
    } catch (err: any) {
      setError(err.message || 'Failed to load vault files');
      console.error('Error loading vault files:', err);
    } finally {
      setIsLoading(false);
    }
  };

  const fetchVaultPermissions = async () => {
    try {
      const response = await api.vault.getPermissions();
      setPermissions(response);
    } catch (err: any) {
      console.error('Failed to load vault permissions:', err);
    }
  };

  // --- Replace old handleAccessFile ---
  const handleAccessFile = (file: VaultFile, action: 'view' | 'download') => {
    setPinActionFile(file); // Store the whole file object
    setPinActionType(action);
    setPinError(null); // Clear previous errors
    setShowPinModal(true); // Show the PIN modal
  };
  // --- End Replace old handleAccessFile ---

  // --- Add new function to handle PIN submission ---
  const submitVaultAccessWithPin = async (pin: string) => {
    if (!pinActionFile || !pinActionType) return;

    try {
        // Call the access endpoint first to verify PIN and get file details
        // The response contains the original File ID needed for download/view URLs
        const accessResponse = await api.vault.access(pinActionFile.id, pin); // Pass PIN

        // If PIN is valid, proceed with the action
        if (pinActionType === 'view') {
            // Get the temporary signed URL for viewing using the original File ID
            const viewUrl = await api.files.getViewUrl(accessResponse.fileId);
            setViewingFile({ // Set state to open DocumentViewer
                url: viewUrl,
                name: accessResponse.fileName, // Use name from access response
                type: accessResponse.fileType, // Use type from access response
                originalFileId: accessResponse.fileId // Store original ID
            });
        } else if (pinActionType === 'download') {
            // Trigger download using the original File ID
            await api.files.download(accessResponse.fileId);
        }

        setShowPinModal(false); // Close modal on success
        setPinActionFile(null);
        setPinActionType(null);
        fetchVaultFiles(); // Refresh last accessed time in the list

    } catch (error: any) {
        console.error(`Failed to ${pinActionType} vault file:`, error);
         if (error.needsPin) {
             // If backend specifically says PIN is needed/invalid
             // Throw error so modal can display it
             throw new Error(error.message || 'Invalid PIN');
         } else {
             // Throw other errors
             throw new Error(error.message || `Failed to ${pinActionType} file.`);
         }
    }
  };
  // --- End Add new function ---


  const handleRemoveFromVault = async (vaultFileId: string) => {
    if (window.confirm('Remove this file from the vault? The file will not be deleted.')) {
      try {
        await api.vault.remove(vaultFileId);
        // Refresh the list
        fetchVaultFiles();
      } catch (err: any) {
        setError(err.message || 'Failed to remove file from vault');
      }
    }
  };

  const formatDate = (dateString: string | null) => {
    if (!dateString) return 'Never';
    return new Date(dateString).toLocaleString();
  };

  const formatFileSize = (bytes: number) => {
    if (bytes < 1024) return bytes + ' B';
    else if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    else if (bytes < 1073741824) return (bytes / 1048576).toFixed(1) + ' MB';
    else return (bytes / 1073741824).toFixed(1) + ' GB';
  };

  const QuotaDisplay = () => {
    if (!permissions) return null;
    
    const usagePercent = permissions.unlimited ? 0 : 
      Math.min(100, Math.round((permissions.usage / permissions.quota) * 100));
    
    return (
      <div className="bg-white rounded-lg border border-neutral-200 shadow-sm p-4 mb-6">
        <div className="flex justify-between items-center mb-2">
          <h3 className="text-sm font-medium text-neutral-700">Vault Storage</h3>
          <span className="text-xs text-neutral-500">
            {permissions.unlimited ? 'Unlimited Access' : `${usagePercent}% used`}
          </span>
        </div>
        
        {!permissions.unlimited && (
          <>
            <div className="w-full bg-neutral-200 rounded-full h-2.5">
              <div 
                className={`h-2.5 rounded-full ${
                  usagePercent > 90 ? 'bg-red-600' : 
                  usagePercent > 70 ? 'bg-amber-500' : 'bg-primary-600'
                }`}
                style={{ width: `${usagePercent}%` }}
              ></div>
            </div>
            
            <div className="flex justify-between text-xs text-neutral-500 mt-1">
              <span>{formatFileSize(permissions.usage)}</span>
              <span>of {formatFileSize(permissions.quota)}</span>
            </div>
          </>
        )}
      </div>
    );
  };

  return (
    <Layout>
      <div className="p-6">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center">
            <Shield className="w-6 h-6 text-primary-600 mr-2" />
            <h1 className="text-2xl font-bold">Confidential Vault</h1>
          </div>
        </div>
        
        <QuotaDisplay />
        
        {error && (
          <div className="bg-red-50 border border-red-200 text-red-700 p-4 rounded-lg mb-6">
            <div className="flex items-center">
              <AlertTriangle className="w-5 h-5 mr-2" />
              {error}
            </div>
          </div>
        )}
        
        {isLoading ? (
          <div className="flex justify-center items-center h-64">
            <LoadingSpinner />
          </div>
        ) : vaultFiles.length === 0 ? (
          <EmptyState
            icon={Lock}
            title="Your Vault is Empty"
            description="Add your most confidential files to the vault for enhanced security."
          />
        ) : (
          <div className="bg-white rounded-lg border border-neutral-200 shadow-sm overflow-hidden">
            <table className="min-w-full divide-y divide-neutral-200">
              <thead className="bg-neutral-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-neutral-500 uppercase tracking-wider">File Name</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-neutral-500 uppercase tracking-wider">Size</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-neutral-500 uppercase tracking-wider">Last Accessed</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-neutral-500 uppercase tracking-wider">Self-Destruct</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-neutral-500 uppercase tracking-wider">Actions</th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-neutral-200">
                {vaultFiles.map((file) => (
                  <tr key={file.id} className="hover:bg-neutral-50">
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center">
                        <div className="flex-shrink-0 h-10 w-10 bg-neutral-100 rounded-lg flex items-center justify-center">
                          <Lock className="h-5 w-5 text-neutral-500" />
                        </div>
                        <div className="ml-4">
                          <div className="text-sm font-medium text-neutral-900">{file.fileName}</div>
                          <div className="text-xs text-neutral-500">{new Date(file.uploadDate).toLocaleDateString()}</div>
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-neutral-500">
                      {formatFileSize(file.fileSize)}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-neutral-500">
                      {formatDate(file.lastAccessed)}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm">
                      {file.selfDestruct ? (
                        <div className="flex items-center text-amber-600">
                          <Calendar className="w-4 h-4 mr-1" />
                          {formatDate(file.destructAfter)}
                        </div>
                      ) : (
                        <span className="text-neutral-500">No</span>
                      )}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                      <div className="flex space-x-2">
                        {/* --- Update onClick handlers --- */}
                        <button
                          onClick={() => handleAccessFile(file, 'view')} // Pass the whole file object
                          className="text-primary-600 hover:text-primary-900"
                          title="View File"
                        >
                          <Eye className="w-5 h-5" />
                        </button>
                        <button
                          onClick={() => handleAccessFile(file, 'download')} // Pass the whole file object
                          className="text-primary-600 hover:text-primary-900"
                          title="Download File"
                        >
                          <Download className="w-5 h-5" />
                        </button>
                        {/* --- End Update onClick handlers --- */}
                        <button
                          onClick={() => handleRemoveFromVault(file.id)}
                          className="text-red-600 hover:text-red-900"
                          title="Remove from Vault"
                        >
                          <Trash2 className="w-5 h-5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* --- Add PinEntryModal --- */}
      <PinEntryModal
          isOpen={showPinModal && !!pinActionFile}
          onClose={() => {
              setShowPinModal(false);
              setPinActionFile(null);
              setPinActionType(null);
          }}
          onSubmit={submitVaultAccessWithPin}
          title="Enter Vault Access PIN"
          description={`Enter the 6-digit PIN for "${pinActionFile?.fileName || 'this file'}" to ${pinActionType || 'access'} it.`}
          errorMessage={pinError} // Pass pinError state here
      />
      {/* --- End Add PinEntryModal --- */}


      {/* Modify DocumentViewer trigger */}
      {viewingFile && (
          <DocumentViewer
              fileUrl={viewingFile.url}
              fileName={viewingFile.name}
              fileType={viewingFile.type}
              onClose={() => setViewingFile(null)} // Clear viewingFile state on close
              onDownload={() => {
                  // Re-trigger PIN check for download from viewer
                  const fileToDownload = vaultFiles.find(f => f.fileId === viewingFile.originalFileId);
                  if (fileToDownload) {
                      handleAccessFile(fileToDownload, 'download');
                  }
              }}
              onShare={() => { /* Add share logic if needed */ }}
          />
      )}
    </Layout>
  );
}