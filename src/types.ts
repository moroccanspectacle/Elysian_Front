export interface FileItem {
  id: string;
  name: string;
  size: string;
  uploadDate: string;
  type: string;
}

export interface ActivityLog {
  id: string;
  timestamp: string;
  action: 'upload' | 'download' | 'share' | 'delete';
  fileName: string;
}