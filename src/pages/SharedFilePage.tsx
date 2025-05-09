import React, { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { FileText, Download, Eye, Edit2, Calendar, AlertCircle } from 'lucide-react';
import { DocumentViewer } from '../components/DocumentViewer';

interface SharedFilePageProps {}

export function SharedFilePage({}: SharedFilePageProps) {
  // Update this line to match the :shareToken parameter name in your route
  const { shareToken } = useParams<{ shareToken: string }>();
  console.log("Token from URL:", shareToken);
  
  // Then use shareToken instead of token in the rest of your component
  const [fileInfo, setFileInfo] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isViewing, setIsViewing] = useState(false);
  const [viewingFile, setViewingFile] = useState<{ url: string; name: string; type: string } | null>(null);
  
  useEffect(() => {
    const fetchSharedFile = async () => {
      try {
        setIsLoading(true);
        
        if (!shareToken) {
          setError('Invalid share link');
          setIsLoading(false);
          return;
        }
        
        // Also update all occurrences of token to shareToken
        console.log("Fetching shared file with token:", shareToken);
        
        // Make sure token doesn't have any unwanted characters
        const cleanToken = shareToken.trim();
        const response = await fetch(`https://elysian-ryc6x.ondigitalocean.app/elysian-back/api/share/${cleanToken}`, {
          method: 'GET'
        });
        
        console.log("Response status:", response.status);
        
        if (!response.ok) {
          const errorData = await response.json().catch(() => ({}));
          throw new Error(errorData.error || 'Failed to load shared file');
        }
        
        const data = await response.json();
        console.log("Shared file data:", data);
        setFileInfo(data);
        setIsLoading(false);
      } catch (error) {
        console.error('Error loading shared file:', error);
        setError('This link appears to be invalid or expired');
        setIsLoading(false);
      }
    };
    
    fetchSharedFile();
  }, [shareToken]);

  const handleDownload = async () => {
    if (!fileInfo || !fileInfo.permissions.canDownload) return;
    
    try {
      // Use the proxy for API requests but full URL for downloads
      window.location.href = `https://elysian-ryc6x.ondigitalocean.app/elysian-back/api/share/${shareToken}/download`;
    } catch (err) {
      console.error('Download error:', err);
    }
  };

  const handleView = () => {
    if (!fileInfo || !fileInfo.permissions.canView) return;
    
    // Create a proper URL for viewing
    const viewUrl = `https://elysian-ryc6x.ondigitalocean.app/elysian-back/api/share/${shareToken}/view`;
    
    setViewingFile({
      url: viewUrl,
      name: fileInfo.fileName,
      type: fileInfo.fileType || 'application/octet-stream'
    });
    
    setIsViewing(true);
  };

  const formatFileSize = (bytes: number) => {
    if (bytes < 1024) return bytes + ' B';
    else if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    else if (bytes < 1073741824) return (bytes / 1048576).toFixed(1) + ' MB';
    else return (bytes / 1073741824).toFixed(1) + ' GB';
  };

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-[#217eaa]"></div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="bg-white p-8 rounded-lg shadow-md max-w-md w-full">
          <div className="flex items-center justify-center text-red-500 mb-4">
            <AlertCircle className="h-12 w-12" />
          </div>
          <h1 className="text-2xl font-bold text-center text-gray-900 mb-2">Error</h1>
          <p className="text-center text-gray-600">{error}</p>
        </div>
      </div>
    );
  }

  if (!fileInfo) return null;

  return (
    <>
      <div className="min-h-screen bg-gray-50 py-12">
        <div className="max-w-3xl mx-auto px-4">
          <div className="bg-white rounded-lg shadow-md p-6">
            <div className="flex items-center mb-6">
              <div className="w-12 h-12 rounded-lg bg-[#f2f2f3] flex items-center justify-center text-[#217eaa]">
                <FileText className="w-6 h-6" />
              </div>
              <div className="ml-4">
                <h1 className="text-xl font-semibold text-gray-900">{fileInfo.fileName}</h1>
                <p className="text-sm text-[#8ca4ac]">{formatFileSize(fileInfo.fileSize)}</p>
              </div>
            </div>
            
            <div className="border-t border-gray-200 pt-4 mt-4">
              <h2 className="text-sm font-medium text-gray-700 mb-2">Permissions</h2>
              <div className="flex space-x-4">
                {fileInfo.permissions.canView && (
                  <div className="flex items-center text-sm text-gray-600">
                    <Eye className="w-4 h-4 mr-1 text-[#217eaa]" />
                    <span>View</span>
                  </div>
                )}
                {fileInfo.permissions.canEdit && (
                  <div className="flex items-center text-sm text-gray-600">
                    <Edit2 className="w-4 h-4 mr-1 text-[#217eaa]" />
                    <span>Edit</span>
                  </div>
                )}
                {fileInfo.permissions.canDownload && (
                  <div className="flex items-center text-sm text-gray-600">
                    <Download className="w-4 h-4 mr-1 text-[#217eaa]" />
                    <span>Download</span>
                  </div>
                )}
              </div>
            </div>
            
            {fileInfo.expiresAt && (
              <div className="border-t border-gray-200 pt-4 mt-4">
                <div className="flex items-center text-sm text-gray-600">
                  <Calendar className="w-4 h-4 mr-1 text-[#217eaa]" />
                  <span>Expires on {new Date(fileInfo.expiresAt).toLocaleDateString()}</span>
                </div>
              </div>
            )}
            
            <div className="mt-6 flex space-x-4">
              {fileInfo.permissions.canView && (
                <button
                  onClick={handleView}
                  className="bg-[#217eaa] text-white px-4 py-2 rounded-lg hover:bg-[#1a6389] transition-colors flex items-center"
                >
                  <Eye className="w-4 h-4 mr-2" />
                  View File
                </button>
              )}
              
              {fileInfo.permissions.canDownload && (
                <button
                  onClick={handleDownload}
                  className="bg-[#217eaa] text-white px-4 py-2 rounded-lg hover:bg-[#1a6389] transition-colors flex items-center"
                >
                  <Download className="w-4 h-4 mr-2" />
                  Download File
                </button>
              )}
              
              {!fileInfo.permissions.canView && !fileInfo.permissions.canDownload && (
                <div className="text-sm text-gray-500">
                  The owner has not enabled viewing or downloading for this file.
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
          onClose={() => setIsViewing(false)}
          onDownload={fileInfo?.permissions.canDownload ? handleDownload : undefined}
        />
      )}
    </>
  );
  
  function getFileTypeFromName(filename: string): string {
    const extension = filename.split('.').pop()?.toLowerCase();
    switch (extension) {
      case 'pdf': return 'pdf';
      case 'doc':
      case 'docx': return 'word';
      case 'xls':
      case 'xlsx': return 'excel';
      case 'ppt':
      case 'pptx': return 'powerpoint';
      case 'jpg':
      case 'jpeg':
      case 'png':
      case 'gif': return 'image';
      default: return 'other';
    }
  }
}