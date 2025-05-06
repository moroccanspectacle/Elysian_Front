import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom'; // Add useLocation
import { Layout } from '../components/Layout';
import { FileCard } from '../components/FileCard';
import { ShareModal } from '../components/ShareModal';
import { ActivityTable } from '../components/ActivityTable';
import { api } from '../services/api'; // Make sure api is imported
import { Search, FileText, AlertCircle, Upload } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { LoadingSpinner } from '../components/LoadingSpinner';
import { EmptyState } from '../components/EmptyState';
import { Button } from '../components/Button';
import { DocumentViewer } from '../components/DocumentViewer';
import type { FileItem, ActivityLog } from '../types'; // Import ActivityLog type
import { toast } from 'react-hot-toast';
import { PinEntryModal } from '../components/PinEntryModal'; // Import the new modal
import { useAuth } from '../components/AuthContext'; // Import useAuth

export function Dashboard() {
    const [showShareModal, setShowShareModal] = useState(false);
    const [currentView, setCurrentView] = useState<'files' | 'activity'>('files');
    const [selectedFile, setSelectedFile] = useState<FileItem | null>(null);
    const [files, setFiles] = useState<FileItem[]>([]);
    const [isLoading, setIsLoading] = useState(true); // Keep track of initial loading
    const [isFilesLoading, setIsFilesLoading] = useState(false); // Specific loading for files
    const [error, setError] = useState<string | null>(null);
    const [viewingFile, setViewingFile] = useState<{
        url: string;
        name: string;
        type: string;
    } | null>(null);
    const [showPinModal, setShowPinModal] = useState(false);
    const [pinActionFileId, setPinActionFileId] = useState<string | null>(null);
    const [pinError, setPinError] = useState<string | null>(null);
    const [searchQuery, setSearchQuery] = useState(''); // Add state for search query

    // Add State for Activity Logs
    const [activityLogs, setActivityLogs] = useState<ActivityLog[]>([]);
    const [activityPage, setActivityPage] = useState(1);
    const [activityTotalPages, setActivityTotalPages] = useState(1);
    const [isActivityLoading, setIsActivityLoading] = useState(false);
    const [activityError, setActivityError] = useState<string | null>(null);

    const navigate = useNavigate();
    const location = useLocation(); // Get current location
    const { user } = useAuth(); // Get user info from context

    // Effect to set the view based on location state and fetch data
    useEffect(() => {
        const desiredView = location.state?.view || 'files'; // Default to 'files' if no state
        setCurrentView(desiredView); // Set the view based on navigation state

        if (desiredView === 'files') {
            console.log('Dashboard view set to files - fetching files');
            fetchFiles(searchQuery); // Fetch files with current query
            // Clear activity state if needed
            setActivityLogs([]);
            setActivityPage(1);
            setActivityTotalPages(1);
        } else if (desiredView === 'activity') {
            console.log('Dashboard view set to activity - fetching activity');
            fetchActivityLogs(1); // Fetch first page of activity logs
            // Clear file state if needed
            setFiles([]);
        } else {
            // Handle other potential views or default case
            setIsFilesLoading(false);
            setIsActivityLoading(false);
            setIsLoading(false);
        }

    }, [location.pathname, location.state]); // Add location.state to dependencies

    const fetchFiles = async (query: string = searchQuery) => { // Accept query, default to state
        try {
          setIsFilesLoading(true); // Use specific loading state
          setError(null);
          const fetchedFiles = await api.files.list(); // Call without parameters
          
          // Filter files client-side based on query
          const filteredFiles = query.trim() 
            ? fetchedFiles.filter((file: any) => 
                file.originalName.toLowerCase().includes(query.trim().toLowerCase()))
            : fetchedFiles;

          // Convert API response to FileItem format
          const formattedFiles: FileItem[] = filteredFiles.map((file: any) => ({
            id: file.id,
            name: file.originalName,
            size: formatFileSize(file.fileSize),
            uploadDate: new Date(file.uploadDate).toLocaleDateString(),
            type: getFileTypeFromName(file.originalName)
          }));

          setFiles(formattedFiles);
        } catch (err: any) {
          console.error('Error fetching files:', err);
          setError('Failed to load files');
          setFiles([]); // Clear files on error
        } finally {
          setIsFilesLoading(false); // Use specific loading state
          setIsLoading(false); // Also set general loading to false if it was the initial load
        }
      };

      // Add Function to Fetch Activity Logs
      const fetchActivityLogs = async (page = activityPage) => {
        setIsActivityLoading(true);
        setActivityError(null);
        try {
          // This API call fetches logs including the associated File object
          const result = await api.auth.getActivityLogs({ page, limit: 15 }); // #file:api.ts line 773

          if (result && result.logs) {
            // Format logs
            const formattedLogs = result.logs.map((log: any) => ({
              ...log, // Spread the original log data
              id: log.id, // Ensure ID is explicitly mapped if needed by ActivityTable
              timestamp: new Date(log.timestamp),
              username: user?.username || 'User', // Use current user's name
              action: log.action, // Ensure action is explicitly mapped

              // --- Prioritize File.originalName ---
              // Access the included File object's originalName if it exists
              fileName: log.File?.originalName || log.details?.fileName || log.fileId || 'N/A',
              // --- End Change ---

              // Keep details if ActivityTable might use it for other things
              details: log.details,
            }));
            setActivityLogs(formattedLogs);
            setActivityTotalPages(result.totalPages || 1);
            setActivityPage(page);
          } else {
            setActivityLogs([]);
            setActivityTotalPages(1);
          }
        } catch (err: any) {
          console.error('Error fetching activity logs:', err);
          setActivityError('Failed to load activity logs.');
          setActivityLogs([]);
        } finally {
          setIsActivityLoading(false);
          setIsLoading(false);
        }
      };

      // Add Handler for Activity Page Change
      const handleActivityPageChange = (newPage: number) => {
        fetchActivityLogs(newPage); // Fetch data for the new page
      };

      // Helper to format file size
      const formatFileSize = (bytes: number) => {
        if (bytes < 1024) return bytes + ' B';
        else if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
        else if (bytes < 1073741824) return (bytes / 1048576).toFixed(1) + ' MB';
        else return (bytes / 1073741824).toFixed(1) + ' GB';
      };

      // Helper to determine file type from filename
      const getFileTypeFromName = (filename: string): string => {
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
      };

      const handleSearchChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        setSearchQuery(e.target.value);
        fetchFiles(e.target.value); // Trigger fetch on change
      };

      const handleShare = (file: FileItem) => {
        setSelectedFile(file);
        setShowShareModal(true);
      };

      const handleDownload = async (file: FileItem) => {
        try {
          // Skip the integrity check alert entirely
          // Just proceed with download directly
          await api.files.download(file.id);

          // Optional: If you want to keep integrity checking but not show alerts:
          // const integrityCheck = await api.files.verifyIntegrity(file.id);
          // console.log("Integrity check:", integrityCheck.integrityVerified ? "Passed" : "Failed");
        } catch (error) {
          console.error('Download error:', error);
          alert("Error downloading file: " + (error as Error).message);
        }
      };

      const handleDelete = async (file: FileItem) => {
        if (confirm(`Are you sure you want to delete ${file.name}?`)) {
          try {
            await api.files.delete(file.id);
            fetchFiles(); // Refresh the file list
          } catch (error) {
            console.error('Delete error:', error);
          }
        }
      };

      const handleView = async (file: FileItem) => {
        try {
          // First verify integrity (optional)
          await api.files.verifyIntegrity(file.id);

          // Get the URL for viewing this file
          const viewUrl = await api.files.getViewUrl(file.id);

          setViewingFile({
            url: viewUrl,
            name: file.name,
            type: file.type
          });
        } catch (error) {
          console.error('View error:', error);
          alert(`Error viewing file: ${(error as Error).message}`);
        }
      };

      // Modify handleMoveToVault
      const handleMoveToVault = (fileId: string) => {
        setPinActionFileId(fileId); // Store the file ID
        setPinError(null); // Clear previous errors
        setShowPinModal(true); // Open the PIN modal
      };

      // New function to handle PIN submission for adding to vault
      const submitMoveToVaultWithPin = async (pin: string, selfDestruct?: boolean, destructAfter?: Date | null) => { // Update signature
        if (!pinActionFileId) return;

        try {
            // Pass self-destruct options to API call
            await api.vault.add(pinActionFileId, pin, { selfDestruct, destructAfter }); // #file:api.ts line 911
            toast.success('File moved to vault successfully!');
            setShowPinModal(false); // Close modal on success
            setPinActionFileId(null);
            fetchFiles(); // Refresh file list
        } catch (error: any) {
            console.error('Failed to move file to vault:', error);
            // Throw the error so the modal can display it
            throw new Error(error.message || 'Failed to move file to vault.');
        }
    };

    // Add this to completely bail out if not on dashboard
    if (location.pathname !== '/dashboard') {
      return null;
    }

    return (
      <>
        <Layout 
          onFileUploaded={() => {
            if (currentView === 'files') fetchFiles(); // Refresh files if in files view
          }}
        >
          <AnimatePresence mode="wait">
            <motion.div
              key={currentView}
              initial={{ opacity: 0, x: currentView === 'files' ? -20 : 20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: currentView === 'files' ? 20 : -20 }}
              transition={{ duration: 0.3 }}
            >
              {currentView === 'files' ? (
                <div>
                  <div className="flex flex-col md:flex-row justify-between items-center mb-8 gap-4">
                    <motion.h2 
                      className="text-3xl font-display font-semibold text-gray-900"
                      initial={{ opacity: 0, y: -10 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: 0.2 }}
                    >
                      My Files
                    </motion.h2>
                    <div className="relative w-full md:w-auto">
                      <Search className="w-5 h-5 absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" />
                      <motion.input 
                        type="text"
                        placeholder="Search my files..." 
                        value={searchQuery}
                        onChange={handleSearchChange}
                        className="pl-10 pr-4 py-2 rounded-lg border border-gray-300 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-transparent transition-all w-full md:w-64"
                        initial={{ opacity: 0, width: "80%" }}
                        animate={{ opacity: 1, width: "100%" }}
                        transition={{ delay: 0.3, duration: 0.2 }}
                      />
                    </div>
                    <Button
                      variant="primary"
                      icon={<Upload className="w-4 h-4" />}
                      onClick={() => document.querySelector<HTMLButtonElement>('button:has(.lucide-upload)')?.click()}
                    >
                      Upload File
                    </Button>
                  </div>

                  {isLoading ? (
                    <div className="flex flex-col items-center justify-center h-64">
                      <LoadingSpinner size="lg" />
                      <motion.p
                        className="text-neutral-500 mt-4"
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        transition={{ delay: 0.5 }}
                      >
                        Loading your files...
                      </motion.p>
                    </div>
                  ) : error ? (
                    <div className="bg-red-100 border-l-4 border-red-500 text-red-700 p-4 rounded-md">
                      <div className="flex">
                        <AlertCircle className="h-5 w-5 mr-2" />
                        <p>{error}</p>
                      </div>
                    </div>
                  ) : files.length === 0 ? (
                    <EmptyState
                      icon={FileText}
                      title="No files yet"
                      description="Upload your first file to get started"
                      action={
                        <Button 
                          variant="primary"
                          onClick={() => document.querySelector<HTMLButtonElement>('button:has(.lucide-upload)')?.click()}
                          icon={<Upload className="w-4 h-4" />}
                        >
                          Upload your first file
                        </Button>
                      }
                    />
                  ) : (
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                      {files.map((file) => (
                        <FileCard
                          key={file.id}
                          file={file}
                          // Use the correct handler names and pass the full file object
                          onView={() => handleView(file)} 
                          onDownload={() => handleDownload(file)} 
                          onShare={() => handleShare(file)} 
                          onDelete={() => handleDelete(file)} 
                          // Pass the handler function here
                          onMoveToVault={() => handleMoveToVault(file.id)} 
                        />
                      ))}
                    </div>
                  )}
                </div>
              ) : (
                <div>
                  <div className="flex items-center mb-8">
                    <h2 className="text-3xl font-display font-semibold text-gray-900">My Activity</h2>
                  </div>
                  <ActivityTable
                    logs={activityLogs}
                    totalPages={activityTotalPages}
                    currentPage={activityPage}
                    onPageChange={handleActivityPageChange}
                    isLoading={isActivityLoading}
                    error={activityError}
                  />
                </div>
              )}
            </motion.div>
          </AnimatePresence>
        </Layout>

        {showShareModal && selectedFile && (
          <ShareModal 
            onClose={() => setShowShareModal(false)} 
            file={{
              id: selectedFile.id,
              name: selectedFile.name
            }}
          />
        )}

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

        {/* Add the PinEntryModal */}
        <PinEntryModal
            isOpen={showPinModal && !!pinActionFileId} // Only open if fileId is set
            onClose={() => {
                setShowPinModal(false);
                setPinActionFileId(null); // Clear fileId on close
            }}
            onSubmit={submitMoveToVaultWithPin}
            title="Set Vault Access PIN"
            description="Create a 6-digit PIN to secure this file in the vault. You will need this PIN to access it later."
            errorMessage={pinError}
        />
      </>
    );
}