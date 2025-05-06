import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { Layout } from '../components/Layout';
import { api } from '../services/api';
import { motion } from 'framer-motion';
import { 
  ChevronLeft, FileText, Search, Filter, MoreVertical, 
  Download, Share, Trash2, Eye, Upload
} from 'lucide-react';
import { Button } from '../components/Button';
import { FileUploadModal } from '../components/FileUploadModal';
import { ShareModal } from '../components/ShareModal';
import { DocumentViewer } from '../components/DocumentViewer';

interface TeamFile {
  id: string;
  originalName: string;
  fileSize: number;
  fileType: string;
  uploadDate: string;
  uploadedBy: string;
}

export function TeamFilesPage() {
  const { teamId } = useParams<{ teamId: string }>();
  const navigate = useNavigate();
  const [teamName, setTeamName] = useState('');
  const [files, setFiles] = useState<TeamFile[]>([]);
  const [filteredFiles, setFilteredFiles] = useState<TeamFile[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [showUploadModal, setShowUploadModal] = useState(false);
  const [showShareModal, setShowShareModal] = useState(false);
  const [selectedFile, setSelectedFile] = useState<TeamFile | null>(null);
  const [viewingFile, setViewingFile] = useState<{url: string; name: string; type: string} | null>(null);

  const [teamSettings, setTeamSettings] = useState<any>(null);
  const [canUploadFiles, setCanUploadFiles] = useState(false);
  const [canDeleteFiles, setCanDeleteFiles] = useState(false);
  
  useEffect(() => {
    if (teamId) {
      // Fetch basic team details first to check status
      const checkTeamStatusAndLoad = async () => {
        setIsLoading(true);
        setError(null);
        try {
          const teamData = await api.teams.getTeam(teamId);
          setTeamName(teamData.name); // Store basic team data

          // If user is invited, redirect back to team details page
          if (teamData.status === 'invited') {
            console.log('[TeamFilesPage] User is invited, redirecting back to team details.');
            navigate(`/teams/${teamId}`);
            return; // Stop further execution
          }

          // If active, proceed to load files and settings
          await fetchFiles(teamId);
          await fetchTeamSettings(); // Keep fetching settings for permissions

        } catch (err: any) {
          console.error('Failed to fetch initial team data:', err);
          setError(err.message || 'Failed to load team information');
        } finally {
           if (window.location.pathname.includes(`/teams/${teamId}/files`)) {
             setIsLoading(false);
          }
        }
      };
      checkTeamStatusAndLoad();
    } else {
      setError("Team ID not found.");
      setIsLoading(false);
    }
  }, [teamId, navigate]); // Add navigate

  // Separate function to fetch files, called only if status is active
  const fetchFiles = async (id: string) => {
     try {
        const filesData = await api.teams.getTeamFiles(id);
        setFiles(filesData);
        setFilteredFiles(filesData); // Also update filtered files initially
     } catch (err) {
        console.error('Failed to fetch team files:', err);
        setError(prev => prev ? `${prev}\nFailed to load files.` : 'Failed to load files.');
     }
  };

  // Keep fetchTeamSettings as it was, called only if status is active
  const fetchTeamSettings = async () => {
    try {
      const settings = await api.teams.getSettings(teamId!);
      setTeamSettings(settings);

      // Fetch the full team details again to get the current user's role within that team
      const teamDataWithRole = await api.teams.getTeam(teamId!);

      if (teamDataWithRole && (teamDataWithRole.role === 'owner' || teamDataWithRole.role === 'admin')) {
        setCanUploadFiles(true);
        setCanDeleteFiles(true);
      } else if (settings && settings.memberPermissions) {
        setCanUploadFiles(settings.memberPermissions.canUploadFiles);
        setCanDeleteFiles(settings.memberPermissions.canDeleteFiles);
      }
    } catch (err) {
      console.error('Failed to fetch team settings:', err);
      // Handle error appropriately, maybe set default permissions or show an error
    }
  };
  
  const formatFileSize = (bytes: number) => {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
    return (bytes / (1024 * 1024 * 1024)).toFixed(1) + ' GB';
  };
  
  const handleFileUpload = async () => {
    setShowUploadModal(true);
  };
  
  const handleFileUploadSuccess = () => {
    fetchFiles(teamId!);
    setShowUploadModal(false);
  };
  
  const handleDownload = async (file: TeamFile) => {
    try {
      await api.files.download(file.id);
    } catch (error) {
      console.error('Download error:', error);
    }
  };
  
  const handleShare = (file: TeamFile) => {
    setSelectedFile(file);
    setShowShareModal(true);
  };
  
  const handleDelete = async (file: TeamFile) => {
    if (confirm(`Are you sure you want to delete ${file.originalName}?`)) {
      try {
        await api.files.delete(file.id); // Use the correct API function for deleting files
        fetchFiles(teamId!); // Refresh the file list
      } catch (error) {
        console.error('Delete error:', error);
        setError(`Failed to delete file: ${error instanceof Error ? error.message : String(error)}`);
      }
    }
  };
  
  const handleView = async (file: TeamFile) => {
    try {
      const viewUrl = await api.files.getViewUrl(file.id);
      
      setViewingFile({
        url: viewUrl,
        name: file.originalName,
        type: file.fileType
      });
    } catch (error) {
      console.error('View error:', error);
    }
  };
  
  if (isLoading) {
    return (
      <Layout>
        <div className="flex justify-center my-20">
          <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-primary-500"></div>
        </div>
      </Layout>
    );
  }
  
  if (error && !isLoading) {
    return (
      <Layout>
        <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg">
          {error}
        </div>
      </Layout>
    );
  }

  // Render null or minimal layout while redirecting
  // Add a check for teamName as well, as it's set only after getTeam succeeds
   if (!teamName) {
      return null;
   }
  
  return (
    <Layout>
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="flex justify-between items-center mb-8">
          <div className="flex items-center">
            <button 
              className="mr-4 p-2 rounded-full hover:bg-gray-100"
              onClick={() => navigate(`/teams/${teamId}`)}
            >
              <ChevronLeft className="w-5 h-5 text-gray-600" />
            </button>
            <motion.div
              initial={{ opacity: 0, y: -10 }}
              animate={{ opacity: 1, y: 0 }}
            >
              <h1 className="text-3xl font-display font-semibold text-gray-900">
                {teamName} - Files
              </h1>
            </motion.div>
          </div>
          
          {canUploadFiles && (
            <Button 
              variant="primary"
              icon={<Upload className="w-4 h-4" />}
              onClick={handleFileUpload}
            >
              Upload File
            </Button>
          )}
        </div>
        
        {/* Search and Filters */}
        <div className="bg-white rounded-lg shadow-sm p-4 mb-6">
          <div className="flex flex-col md:flex-row md:items-center md:justify-between space-y-4 md:space-y-0">
            <div className="relative w-full md:w-80">
              <input
                type="text"
                placeholder="Search files..."
                className="pl-10 pr-4 py-2 w-full rounded-lg border border-gray-200 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-transparent"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-4 h-4" />
            </div>
            
            <div className="flex items-center space-x-2">
              <Button
                variant="outline"
                icon={<Filter className="w-4 h-4" />}
              >
                Filter
              </Button>
              <div className="text-sm text-gray-600">
                {filteredFiles.length} {filteredFiles.length === 1 ? 'file' : 'files'}
              </div>
            </div>
          </div>
        </div>
        
        {/* Files List */}
        <div className="bg-white rounded-lg shadow-sm overflow-hidden mb-6">
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    File
                  </th>
                  <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Size
                  </th>
                  <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Uploaded
                  </th>
                  <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Uploaded By
                  </th>
                  <th scope="col" className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {filteredFiles.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="px-6 py-10 text-center text-gray-500">
                      No files found
                    </td>
                  </tr>
                ) : (
                  filteredFiles.map((file) => (
                    <tr key={file.id} className="hover:bg-gray-50">
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="flex items-center">
                          <div className="flex-shrink-0 h-10 w-10 rounded bg-gray-100 flex items-center justify-center">
                            <FileText className="h-5 w-5 text-gray-500" />
                          </div>
                          <div className="ml-4">
                            <div className="text-sm font-medium text-gray-900">{file.originalName}</div>
                            <div className="text-xs text-gray-500">{file.fileType}</div>
                          </div>
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                        {formatFileSize(file.fileSize)}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                        {new Date(file.uploadDate).toLocaleDateString()}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                        {file.uploadedBy}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                        <div className="flex justify-end space-x-2">
                          <button 
                            className="text-gray-500 hover:text-primary-600"
                            onClick={() => handleView(file)}
                          >
                            <Eye className="w-4 h-4" />
                          </button>
                          <button 
                            className="text-gray-500 hover:text-primary-600"
                            onClick={() => handleDownload(file)}
                          >
                            <Download className="w-4 h-4" />
                          </button>
                          <button 
                            className="text-gray-500 hover:text-primary-600"
                            onClick={() => handleShare(file)}
                          >
                            <Share className="w-4 h-4" />
                          </button>
                          {canDeleteFiles && (
                            <button 
                              className="text-gray-500 hover:text-red-600"
                              onClick={() => handleDelete(file)}
                            >
                              <Trash2 className="w-4 h-4" />
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
      
      {/* Upload Modal */}
      {showUploadModal && (
        <FileUploadModal 
          onClose={() => setShowUploadModal(false)}
          onSuccess={handleFileUploadSuccess}
          teamId={teamId}
        />
      )}
      
      {/* Share Modal */}
      {showShareModal && selectedFile && (
        <ShareModal 
          onClose={() => setShowShareModal(false)} 
          file={{
            id: selectedFile.id,
            name: selectedFile.originalName
          }}
        />
      )}
      
      {/* Document Viewer */}
      {viewingFile && (
        <DocumentViewer
          fileUrl={viewingFile.url}
          fileName={viewingFile.name}
          fileType={viewingFile.type}
          onClose={() => setViewingFile(null)}
          onDownload={() => selectedFile && handleDownload(selectedFile)}
          onShare={() => selectedFile && handleShare(selectedFile)}
        />
      )}
    </Layout>
  );
}