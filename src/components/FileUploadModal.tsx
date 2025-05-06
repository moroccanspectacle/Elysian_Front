import React, { useState, useRef, useEffect } from 'react';
import { X, Upload, File as FileIcon } from 'lucide-react';
import { Button } from './Button';
import { api } from '../services/api';

interface FileUploadModalProps {
  onClose: () => void;
  onSuccess: (fileData: any) => void;
  teamId?: string; // Accept teamId as a prop
}

export function FileUploadModal({ onClose, onSuccess, teamId }: FileUploadModalProps) {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [uploading, setUploading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [maxFileSize, setMaxFileSize] = useState<number>(50); // Default 50MB
  const fileInputRef = useRef<HTMLInputElement>(null);

  const fetchMaxFileSize = async () => {
    try {
      const settings = await api.files.getSettings();
      setMaxFileSize(settings.maxFileSize || 50);
    } catch (error) {
      console.error('Failed to fetch max file size', error);
    }
  };

  useEffect(() => {
    fetchMaxFileSize();
  }, []);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setSelectedFile(e.target.files[0]);
      setError(null);
    }
  };

  const handleDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      setSelectedFile(e.dataTransfer.files[0]);
      setError(null);
    }
  };

  const handleDragOver = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
  };

  const handleUpload = async () => {
    if (!selectedFile) {
      setError('Please select a file to upload');
      return;
    }

    if (selectedFile.size > maxFileSize * 1024 * 1024) {
      setError(`File size exceeds ${maxFileSize}MB limit`);
      return;
    }

    setUploading(true);
    setProgress(0);
    setError(null);

    try {
      const uploadedFile = await api.files.upload(
        selectedFile!, // Add non-null assertion as selectedFile is checked above
        teamId,
        (uploadProgress) => setProgress(uploadProgress)
      );

      onSuccess(uploadedFile);
      onClose(); // Close the modal after successful upload

    } catch (err) {
      console.error('Upload error:', err);
      setError(err instanceof Error ? err.message : 'Upload failed');
      setUploading(false); // Keep modal open on error
    }
  };

  return (
    <div className="fixed inset-0 flex items-center justify-center z-50 bg-black bg-opacity-50">
      <div className="bg-white rounded-lg shadow-lg w-full max-w-md">
        <div className="flex justify-between items-center p-4 border-b">
          <h2 className="text-xl font-semibold text-gray-800">Upload File</h2>
          <button 
            className="text-gray-500 hover:text-gray-700"
            onClick={onClose}
            disabled={uploading}
          >
            <X className="w-5 h-5" />
          </button>
        </div>
        
        <div className="p-4">
          {error && (
            <div className="mb-4 p-3 bg-red-50 text-red-700 rounded-md">
              {error}
            </div>
          )}
          
          <div 
            className="border-2 border-dashed border-gray-300 rounded-lg p-8 mb-4 text-center cursor-pointer hover:border-primary-500 transition-colors"
            onClick={() => fileInputRef.current?.click()}
            onDrop={handleDrop}
            onDragOver={handleDragOver}
          >
            {selectedFile ? (
              <div>
                <FileIcon className="w-12 h-12 mx-auto mb-3 text-primary-500" />
                <p className="text-gray-700 font-medium">{selectedFile.name}</p>
                <p className="text-gray-500 text-sm">
                  {(selectedFile.size / (1024 * 1024)).toFixed(2)} MB
                </p>
              </div>
            ) : (
              <div>
                <Upload className="w-12 h-12 mx-auto mb-3 text-gray-400" />
                <p className="text-gray-700 mb-1">Drag and drop a file here, or click to select</p>
                <p className="text-gray-500 text-sm">Maximum file size: {maxFileSize}MB</p>
              </div>
            )}
            <input 
              type="file" 
              className="hidden" 
              ref={fileInputRef}
              onChange={handleFileChange}
              disabled={uploading}
            />
          </div>
          
          {uploading && (
            <div className="mb-4">
              <div className="h-2 bg-gray-200 rounded-full">
                <div 
                  className="h-full bg-primary-500 rounded-full transition-all duration-300"
                  style={{ width: `${progress}%` }}
                ></div>
              </div>
              <p className="text-center text-sm text-gray-600 mt-1">
                Uploading: {progress}%
              </p>
            </div>
          )}
          
          <div className="flex justify-end space-x-3">
            <Button
              variant="outline"
              onClick={onClose}
              disabled={uploading}
            >
              Cancel
            </Button>
            <Button
              variant="primary"
              onClick={handleUpload}
              disabled={!selectedFile || uploading}
              icon={<Upload className="w-4 h-4 mr-1" />}
            >
              {uploading ? 'Uploading...' : 'Upload'}
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}