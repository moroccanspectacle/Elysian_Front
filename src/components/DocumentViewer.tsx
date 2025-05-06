import React, { useState, useEffect } from 'react';
import { X, ChevronLeft, ChevronRight, Download, Share2, Eye, Volume2, Film } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

interface DocumentViewerProps {
  fileUrl: string;
  fileName: string;
  fileType: string;
  onClose: () => void;
  onDownload?: () => void;
  onShare?: () => void;
}

export function DocumentViewer({
  fileUrl,
  fileName,
  fileType,
  onClose,
  onDownload,
  onShare
}: DocumentViewerProps) {
  const [numPages, setNumPages] = useState<number | null>(null);
  const [pageNumber, setPageNumber] = useState(1);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [scale, setScale] = useState(1);
  const [blobUrl, setBlobUrl] = useState<string | null>(null);
  
  // Fetch the file and create a blob URL
  useEffect(() => {
    const fetchFile = async () => {
      try {
        setIsLoading(true);
        
        // Check if this is a shared file URL
        const isSharedFileUrl = fileUrl.includes('/api/share/');
        
        // Only add auth token for non-shared URLs
        let url = fileUrl;
        if (!isSharedFileUrl && url.includes('/api/') && !url.includes('token=')) {
          const token = localStorage.getItem('auth-token');
          url += (url.includes('?') ? '&' : '?') + `token=${token}`;
        }
        
        // Fetch the file with authentication only for non-shared URLs
        const response = await fetch(url, {
          headers: isSharedFileUrl ? {} : {
            'auth-token': localStorage.getItem('auth-token') || ''
          }
        });
        
        if (!response.ok) {
          throw new Error(`Failed to load file: ${response.status} ${response.statusText}`);
        }
        
        // Rest of your code remains the same...
        const blob = await response.blob();
        const objectUrl = URL.createObjectURL(blob);
        setBlobUrl(objectUrl);
        setIsLoading(false);
      } catch (err) {
        console.error("File fetching error:", err);
        setError('Failed to load file. Please try downloading it instead.');
        setIsLoading(false);
      }
    };
    
    fetchFile();
    
    // Cleanup the blob URL when the component unmounts
    return () => {
      if (blobUrl) {
        URL.revokeObjectURL(blobUrl);
      }
    };
  }, [fileUrl]);

  function onDocumentLoadSuccess({ numPages }: { numPages: number }) {
    setNumPages(numPages);
    setIsLoading(false);
  }

  function changeScale(delta: number) {
    setScale(Math.max(0.5, Math.min(2.5, scale + delta)));
  }

  const nextPage = () => {
    if (numPages && pageNumber < numPages) {
      setPageNumber(pageNumber + 1);
    }
  };

  const prevPage = () => {
    if (pageNumber > 1) {
      setPageNumber(pageNumber - 1);
    }
  };

  const isPdf = fileName.toLowerCase().endsWith('.pdf');
  const isImage = /\.(jpe?g|png|gif|bmp|webp)$/i.test(fileName);
  const isVideo = /\.(mp4|webm|ogg|mov|avi|wmv|flv|mkv)$/i.test(fileName);
  const isAudio = /\.(mp3|wav|ogg|aac|flac|m4a)$/i.test(fileName);

  const renderContent = () => {
    if (isPdf) {
      return (
        <div className="flex flex-col items-center w-full h-full">
          <iframe
            src={`${blobUrl}#toolbar=0`}
            className="w-full h-full"
            title={fileName}
            onLoad={() => setIsLoading(false)}
            onError={(e) => {
              console.error("PDF loading error:", e);
              setError('Failed to load PDF. Please try downloading it instead.');
              setIsLoading(false);
            }}
          />
        </div>
      );
    } else if (isImage) {
      return (
        <div className="flex justify-center">
          <img 
            src={blobUrl || fileUrl} 
            alt={fileName} 
            className="max-h-[80vh] object-contain shadow-md"
            style={{ transform: `scale(${scale})` }}
            onLoad={() => setIsLoading(false)}
            onError={() => {
              setError('Failed to load image. Please try downloading it instead.');
              setIsLoading(false);
            }}
          />
        </div>
      );
    } else if (isVideo) {
      return (
        <div className="flex flex-col items-center w-full max-w-4xl mx-auto">
          <video
            src={blobUrl || undefined}
            className="max-h-[80vh] max-w-full shadow-md rounded-md"
            controls
            autoPlay={false}
            controlsList="nodownload"
            onLoadedData={() => setIsLoading(false)}
            onError={() => {
              setError('Failed to load video. Please try downloading it instead.');
              setIsLoading(false);
            }}
          >
            Your browser does not support the video tag.
          </video>
          <p className="text-white text-sm mt-2 opacity-75">{fileName}</p>
        </div>
      );
    } else if (isAudio) {
      return (
        <div className="flex flex-col items-center bg-white p-8 rounded-lg shadow-md">
          <div className="w-16 h-16 rounded-full bg-primary-100 flex items-center justify-center mb-4">
            <Volume2 className="w-8 h-8 text-primary-500" />
          </div>
          <h3 className="text-xl font-medium mb-4 text-center">{fileName}</h3>
          <audio
            src={blobUrl || undefined}
            className="w-full max-w-md"
            controls
            autoPlay={false}
            controlsList="nodownload"
            onLoadedData={() => setIsLoading(false)}
            onError={() => {
              setError('Failed to load audio. Please try downloading it instead.');
              setIsLoading(false);
            }}
          >
            Your browser does not support the audio tag.
          </audio>
        </div>
      );
    } else {
      return (
        <div className="text-center p-10 bg-white rounded-lg shadow-md m-10">
          <Eye className="w-12 h-12 text-neutral-400 mx-auto mb-4" />
          <h3 className="text-xl font-medium mb-2">Preview not available</h3>
          <p className="text-neutral-500 mb-6">
            This file type cannot be previewed in the browser. 
            Please download the file to view it.
          </p>
          {onDownload && (
            <button 
              onClick={onDownload}
              className="bg-primary-500 text-white px-4 py-2 rounded-lg hover:bg-primary-600 transition-colors"
            >
              <Download className="w-4 h-4 mr-2 inline" />
              Download File
            </button>
          )}
        </div>
      );
    }
  };

  return (
    <AnimatePresence>
      <motion.div 
        className="fixed inset-0 bg-black bg-opacity-75 z-50 flex flex-col"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
      >
        <div className="bg-white shadow-md p-4 flex justify-between items-center">
          <h3 className="text-xl font-medium truncate">
            {isVideo && <Film className="w-5 h-5 inline mr-2 text-blue-500" />}
            {isAudio && <Volume2 className="w-5 h-5 inline mr-2 text-green-500" />}
            {fileName}
          </h3>
          <div className="flex items-center space-x-3">
            {(isPdf || isImage) && (
              <>
                <button 
                  onClick={() => changeScale(-0.1)}
                  className="p-2 rounded-md text-neutral-600 hover:bg-neutral-100 transition-colors"
                  title="Zoom out"
                >
                  <span className="font-bold">-</span>
                </button>
                <span className="text-sm text-neutral-500">
                  {Math.round(scale * 100)}%
                </span>
                <button 
                  onClick={() => changeScale(0.1)}
                  className="p-2 rounded-md text-neutral-600 hover:bg-neutral-100 transition-colors"
                  title="Zoom in"
                >
                  <span className="font-bold">+</span>
                </button>
                <div className="h-6 border-r border-neutral-200 mx-1"></div>
              </>
            )}
            {onDownload && (
              <button 
                onClick={onDownload}
                className="p-2 rounded-md text-neutral-600 hover:bg-neutral-100 transition-colors"
                title="Download"
              >
                <Download className="w-5 h-5" />
              </button>
            )}
            {onShare && (
              <button 
                onClick={onShare}
                className="p-2 rounded-md text-neutral-600 hover:bg-neutral-100 transition-colors"
                title="Share"
              >
                <Share2 className="w-5 h-5" />
              </button>
            )}
            <button 
              onClick={onClose}
              className="p-2 rounded-md text-neutral-600 hover:bg-neutral-100 transition-colors"
              title="Close"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>
        
        <div className="flex-1 overflow-auto bg-neutral-800 p-4 flex items-center justify-center">
          {error ? (
            <div className="bg-red-100 border border-red-400 text-red-700 px-6 py-4 rounded-lg">
              {error}
            </div>
          ) : isLoading ? (
            <div className="flex flex-col items-center">
              <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-white"></div>
              <p className="text-white mt-4">Loading {isVideo ? 'video' : isAudio ? 'audio' : 'file'}...</p>
            </div>
          ) : (
            renderContent()
          )}
        </div>
        
        {isPdf && numPages && numPages > 1 && (
          <div className="bg-white p-4 flex justify-center items-center space-x-4">
            <button 
              onClick={prevPage}
              disabled={pageNumber <= 1}
              className="p-2 rounded-full text-neutral-600 hover:bg-neutral-100 disabled:opacity-50"
            >
              <ChevronLeft className="w-5 h-5" />
            </button>
            <span className="text-sm font-medium">
              Page {pageNumber} of {numPages}
            </span>
            <button 
              onClick={nextPage}
              disabled={pageNumber >= (numPages || 1)}
              className="p-2 rounded-full text-neutral-600 hover:bg-neutral-100 disabled:opacity-50"
            >
              <ChevronRight className="w-5 h-5" />
            </button>
          </div>
        )}
      </motion.div>
    </AnimatePresence>
  );
}