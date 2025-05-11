import React, { useState, useEffect, useCallback } from 'react';
import { useParams, useNavigate, useLocation } from 'react-router-dom';
import { FileText, Download, Eye, Edit2, Calendar, AlertCircle, LockKeyhole } from 'lucide-react';
import { DocumentViewer } from '../components/DocumentViewer';
import { api } from '../services/api';
import { useAuth } from '../components/AuthContext';

interface PublicShareInfo {
  fileName: string;
  fileSize: number;
  fileType: string;
  expiresAt?: string | null;
  permissions: {
    canView: boolean;
    canEdit: boolean;
    canDownload: boolean;
  };
  isPrivateShare: boolean;
}

export function SharedFilePage() {
  const { shareToken } = useParams<{ shareToken: string }>();
  const navigate = useNavigate();
  const location = useLocation();
  const { isAuthenticated, user } = useAuth();

  const [publicInfo, setPublicInfo] = useState<PublicShareInfo | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isViewing, setIsViewing] = useState(false);
  const [viewingFile, setViewingFile] = useState<{ url: string; name: string; type: string } | null>(null);
  const [promptLogin, setPromptLogin] = useState(false);

  const fetchPublicMetadata = useCallback(async () => {
    if (!shareToken) {
      setError('Invalid share link token.');
      setIsLoading(false);
      return;
    }
    try {
      setIsLoading(true);
      setError(null);
      setPromptLogin(false);
      const data: PublicShareInfo = await api.shares.getPublicShareMetadata(shareToken);
      setPublicInfo(data);

      if (data.isPrivateShare && !isAuthenticated) {
        setPromptLogin(true);
      }
    } catch (err: any) {
      console.error('Error loading shared file metadata:', err);
      setError(err.message || 'This link appears to be invalid or expired.');
      setPublicInfo(null);
    } finally {
      setIsLoading(false);
    }
  }, [shareToken, isAuthenticated]);

  useEffect(() => {
    fetchPublicMetadata();
  }, [fetchPublicMetadata]);

  const handleDownload = async () => {
    if (!publicInfo || !shareToken) return;

    try {
      if (publicInfo.isPrivateShare) {
        if (!isAuthenticated) {
          setError("Please log in to download this private file.");
          setPromptLogin(true);
          return;
        }
        await api.shares.downloadPrivateShare(shareToken, publicInfo.fileName);
      } else {
        if (!publicInfo.permissions.canDownload) {
          setError("Downloading is not permitted for this public share.");
          return;
        }
        window.location.href = 'https://elysian-ryc6x.ondigitalocean.app/elysian-back/api/share/${shareToken}/download';
      }
    } catch (err: any) {
      console.error('Download error:', err);
      setError(err.message || 'Failed to download file.');
      if ((err as any).status === 403) {
        setError("You are not authorized to download this private file.");
      }
    }
  };

  const handleView = async () => {
    if (!publicInfo || !shareToken) return;
    try {
      let targetUrl = '';
      let isBlob = false;

      if (publicInfo.isPrivateShare) {
        if (!isAuthenticated) {
          setError("Please log in to view this private file.");
          setPromptLogin(true);
          return;
        }
        const blob = await api.shares.getPrivateShareViewBlob(shareToken);
        targetUrl = URL.createObjectURL(blob);
        isBlob = true;
      } else {
        if (!publicInfo.permissions.canView) {
          setError("Viewing is not permitted for this public share.");
          return;
        }
        targetUrl = `https://elysian-ryc6x.ondigitalocean.app/elysian-back/api/share/${shareToken}/view`;
      }

      setViewingFile({
        url: targetUrl,
        name: publicInfo.fileName,
        type: publicInfo.fileType || 'application/octet-stream'
      });
      setIsViewing(true);
    } catch (err: any) {
      console.error('View error:', err);
      setError(err.message || 'Failed to view file.');
      if ((err as any).status === 403) {
        setError("You are not authorized to view this private file.");
      }
    }
  };

  const handleLoginRedirect = () => {
    navigate('/login', { state: { from: location.pathname, reason: 'private_share_access' } });
  };

  if (isLoading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-primary-500"></div>
      </div>
    );
  }

  if (promptLogin && publicInfo?.isPrivateShare && !isAuthenticated) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center p-4">
        <div className="bg-white p-8 rounded-lg shadow-md max-w-md w-full text-center">
          <LockKeyhole className="h-16 w-16 text-primary-500 mx-auto mb-4" />
          <h1 className="text-2xl font-bold text-gray-900 mb-3">Private Share</h1>
          <p className="text-gray-600 mb-6">This file is shared privately. Please log in to access it.</p>
          <button
            onClick={handleLoginRedirect}
            className="w-full bg-primary-600 text-white px-6 py-3 rounded-lg hover:bg-primary-700 transition-colors text-lg font-semibold"
          >
            Log In
          </button>
          <button
            onClick={() => { setPromptLogin(false); setError("Access denied without login."); }}
            className="mt-4 w-full text-gray-500 hover:text-gray-700 py-2"
          >
            Cancel
          </button>
        </div>
      </div>
    );
  }

  if (error && !publicInfo) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center p-4">
        <div className="bg-white p-8 rounded-lg shadow-md max-w-md w-full">
          <div className="flex items-center justify-center text-red-500 mb-4">
            <AlertCircle className="h-12 w-12" />
          </div>
          <h1 className="text-2xl font-bold text-center text-gray-900 mb-2">Access Denied</h1>
          <p className="text-center text-gray-600">{error}</p>
        </div>
      </div>
    );
  }

  if (!publicInfo) return null;

  const currentPermissions = publicInfo.permissions;
  const canViewFile = publicInfo.isPrivateShare ? isAuthenticated && currentPermissions.canView : currentPermissions.canView;
  const canDownloadFile = publicInfo.isPrivateShare ? isAuthenticated && currentPermissions.canDownload : currentPermissions.canDownload;

  return (
    <>
      <div className="min-h-screen bg-gray-50 py-12">
        <div className="max-w-3xl mx-auto px-4">
          <div className="bg-white rounded-lg shadow-md p-6">
            {publicInfo.isPrivateShare && (
              <div className="mb-4 p-3 bg-orange-50 border-l-4 border-orange-400 rounded-md">
                <div className="flex items-center">
                  <LockKeyhole className="h-5 w-5 text-orange-600 mr-2" />
                  <p className="text-sm text-orange-700">This is a private share. Access is restricted.</p>
                </div>
              </div>
            )}
            {error && (
              <div className="mb-4 p-3 bg-red-50 border-l-4 border-red-400 text-red-700 rounded-md">
                <p>{error}</p>
              </div>
            )}
            <div className="flex items-center mb-6">
              <div className="w-12 h-12 rounded-lg bg-[#f2f2f3] flex items-center justify-center text-[#217eaa]">
                <FileText className="w-6 h-6" />
              </div>
              <div className="ml-4">
                <h1 className="text-xl font-semibold text-gray-900">{publicInfo.fileName}</h1>
                <p className="text-sm text-[#8ca4ac]">{formatFileSize(publicInfo.fileSize)}</p>
              </div>
            </div>

            <div className="border-t border-gray-200 pt-4 mt-4">
              <h2 className="text-sm font-medium text-gray-700 mb-2">Permissions</h2>
              <div className="flex space-x-4">
                {currentPermissions.canView && (
                  <div className="flex items-center text-sm text-gray-600">
                    <Eye className="w-4 h-4 mr-1 text-[#217eaa]" />
                    <span>View</span>
                  </div>
                )}
                {currentPermissions.canEdit && (
                  <div className="flex items-center text-sm text-gray-600">
                    <Edit2 className="w-4 h-4 mr-1 text-[#217eaa]" />
                    <span>Edit</span>
                  </div>
                )}
                {currentPermissions.canDownload && (
                  <div className="flex items-center text-sm text-gray-600">
                    <Download className="w-4 h-4 mr-1 text-[#217eaa]" />
                    <span>Download</span>
                  </div>
                )}
              </div>
            </div>

            {publicInfo.expiresAt && (
              <div className="border-t border-gray-200 pt-4 mt-4">
                <div className="flex items-center text-sm text-gray-600">
                  <Calendar className="w-4 h-4 mr-1 text-[#217eaa]" />
                  <span>Expires on {new Date(publicInfo.expiresAt).toLocaleDateString()}</span>
                </div>
              </div>
            )}

            <div className="mt-6 flex space-x-4">
              {canViewFile && (
                <button
                  onClick={handleView}
                  className="bg-[#217eaa] text-white px-4 py-2 rounded-lg hover:bg-[#1a6389] transition-colors flex items-center"
                >
                  <Eye className="w-4 h-4 mr-2" />
                  View File
                </button>
              )}

              {canDownloadFile && (
                <button
                  onClick={handleDownload}
                  className="bg-[#217eaa] text-white px-4 py-2 rounded-lg hover:bg-[#1a6389] transition-colors flex items-center"
                >
                  <Download className="w-4 h-4 mr-2" />
                  Download File
                </button>
              )}

              {(!canViewFile && !canDownloadFile && !isLoading && !promptLogin) && (
                <div className="text-sm text-gray-500">
                  You do not have permission to view or download this file, or the necessary permissions are not enabled for this share.
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {isViewing && viewingFile && (
        <DocumentViewer
          fileUrl={viewingFile.url}
          fileName={viewingFile.name}
          fileType={viewingFile.type}
          onClose={() => {
            if (viewingFile.url.startsWith('blob:')) {
              URL.revokeObjectURL(viewingFile.url);
            }
            setIsViewing(false);
            setViewingFile(null);
          }}
          onDownload={canDownloadFile ? handleDownload : undefined}
        />
      )}
    </>
  );
}

function formatFileSize(bytes: number, decimals = 2) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}