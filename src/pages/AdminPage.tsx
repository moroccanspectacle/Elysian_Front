import React, { useState, useEffect } from 'react';
import { Layout } from '../components/Layout';
import { 
  Users, FileText, Activity, Settings, Search, Download, Trash2, 
  Shield, X, User as UserIcon, Users as TeamIcon, Key, Calendar, Hash, ShieldCheck, ShieldAlert, Save, AlertCircle, Check
} from 'lucide-react';
import { api } from '../services/api';
import { CreateUserModal } from '../components/CreateUserModal';
import { DepartmentManagement } from '../components/DepartmentManagement';
import { ConfirmationModal } from '../components/ConfirmationModal';
import { ActivityTable } from '../components/ActivityTable'; // Import the ActivityTable component
import { Button } from '../components/Button'; // Import Button
import type { ActivityLog } from '../types'; // Assuming ActivityLog type is defined in types.ts

interface User {
  id: string;
  email: string;
  username: string;
  profileImage?: string;
  role: 'user' | 'admin' | 'super_admin';
  status: 'active' | 'suspended';
  mfaEnabled?: boolean;
  Department?: {
    name: string;
    vaultQuotaBonus: number;
    requireMfa: boolean;
  };
  departmentId?: number; // Added departmentId
}

interface SystemSettings {
  enforceTwo2FA: boolean;
  fileExpiration: boolean;
  maxFileSize: number;
  storageQuota: number;
}

interface AdminPageProps {
  activeTab?: 'users' | 'files' | 'activity' | 'settings' | 'departments';
}

const mockUsers: User[] = [
  { id: '1', email: 'admin@example.com', username: 'Admin', role: 'admin', status: 'active' },
  { id: '2', email: 'user1@example.com', username: 'User1', role: 'user', status: 'active' },
  { id: '3', email: 'user2@example.com', username: 'User2', role: 'user', status: 'suspended' },
];

export function AdminPage({ activeTab: initialTab = 'users' }: AdminPageProps) {
  const [activeTab, setActiveTab] = useState<'users' | 'files' | 'activity' | 'settings' | 'departments'>(initialTab);

  useEffect(() => {
    if (initialTab) {
      setActiveTab(initialTab);
    }
  }, [initialTab]);

  const renderContent = () => {
    switch (activeTab) {
      case 'users':
        return <UserManagement />;
      case 'files':
        return <FileManagement />;
      case 'activity':
        return <ActivityMonitor />;
      case 'settings':
        return <SystemSettings />;
      case 'departments':
        return <DepartmentManagement />;
      default:
        return <UserManagement />;
    }
  };

  return (
    <Layout>
      <div className="container mx-auto px-4 py-8">
        <h1 className="text-3xl font-semibold mb-8">Admin Dashboard</h1>

        <div className="flex border-b border-gray-200 mb-6 overflow-x-auto">
          <button
            className={`px-4 py-2 font-medium mr-4 ${
              activeTab === 'users'
                ? 'text-[#217eaa] border-b-2 border-[#217eaa]'
                : 'text-gray-500 hover:text-gray-700'
            }`}
            onClick={() => setActiveTab('users')}
          >
            Users
          </button>
          <button
            className={`px-4 py-2 font-medium mr-4 ${
              activeTab === 'departments'
                ? 'text-[#217eaa] border-b-2 border-[#217eaa]'
                : 'text-gray-500 hover:text-gray-700'
            }`}
            onClick={() => setActiveTab('departments')}
          >
            Departments
          </button>
          <button
            className={`px-4 py-2 font-medium mr-4 ${
              activeTab === 'files'
                ? 'text-[#217eaa] border-b-2 border-[#217eaa]'
                : 'text-gray-500 hover:text-gray-700'
            }`}
            onClick={() => setActiveTab('files')}
          >
            Files
          </button>
          <button
            className={`px-4 py-2 font-medium mr-4 ${
              activeTab === 'activity'
                ? 'text-[#217eaa] border-b-2 border-[#217eaa]'
                : 'text-gray-500 hover:text-gray-700'
            }`}
            onClick={() => setActiveTab('activity')}
          >
            Activity
          </button>
          <button
            className={`px-4 py-2 font-medium mr-4 ${
              activeTab === 'settings'
                ? 'text-[#217eaa] border-b-2 border-[#217eaa]'
                : 'text-gray-500 hover:text-gray-700'
            }`}
            onClick={() => setActiveTab('settings')}
          >
            Settings
          </button>
        </div>

        {renderContent()}
      </div>
    </Layout>
  );
}

function UserManagement() {
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [search, setSearch] = useState('');
  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  const [showEditUserModal, setShowEditUserModal] = useState(false);
  const [showCreateModal, setShowCreateModal] = useState(false);

  useEffect(() => {
    fetchUsers();
  }, [page]);

  const fetchUsers = async () => {
    setLoading(true);
    try {
      const result = await api.admin.listUsers({
        page,
        limit: 10,
        search: search.trim() ? search : undefined
      });
      setUsers(result.users);
      setTotalPages(result.pages);
    } catch (error) {
      console.error('Failed to fetch users:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleSearch = () => {
    setPage(1);
    fetchUsers();
  };

  const handleRoleChange = async (userId: string, newRole: 'user' | 'admin') => {
    try {
      await api.admin.updateUser(userId, { role: newRole });
      setUsers(users.map(user => 
        user.id === userId ? { ...user, role: newRole } : user
      ));
    } catch (error) {
      console.error('Failed to update user role:', error);
    }
  };

  const handleStatusChange = async (userId: string, newStatus: 'active' | 'suspended') => {
    try {
      await api.admin.updateUser(userId, { status: newStatus });
      setUsers(users.map(user => 
        user.id === userId ? { ...user, status: newStatus } : user
      ));
    } catch (error) {
      console.error('Failed to update user status:', error);
    }
  };

  return (
    <div>
      <div className="flex justify-between items-center mb-6">
        <h2 className="text-2xl font-semibold">User Management</h2>
        <div className="flex space-x-2">
          <button
            onClick={() => setShowCreateModal(true)}
            className="bg-primary-600 text-white px-4 py-2 rounded-lg hover:bg-primary-700"
          >
            Create User
          </button>
          <div className="relative">
            <Search className="w-5 h-5 absolute left-3 top-1/2 transform -translate-y-1/2 text-[#8ca4ac]" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
              placeholder="Search users..."
              className="pl-10 pr-4 py-2 rounded-lg border border-[#8ca4ac] focus:outline-none focus:ring-2 focus:ring-[#217eaa]"
            />
          </div>
          <button 
            onClick={handleSearch}
            className="bg-[#217eaa] text-white px-4 py-2 rounded-lg hover:bg-[#1a6389]"
          >
            Search
          </button>
        </div>
      </div>
      
      <div className="bg-white rounded-lg shadow-sm overflow-hidden">
        {loading ? (
          <div className="p-6 flex justify-center">
            <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-[#217eaa]"></div>
          </div>
        ) : (
          <table className="w-full">
            <thead>
              <tr className="bg-[#f2f2f3] text-[#8ca4ac] text-sm">
                <th className="px-6 py-3 text-left">User</th>
                <th className="px-6 py-3 text-left">Email</th>
                <th className="px-6 py-3 text-left">Role</th>
                <th className="px-6 py-3 text-left">MFA</th>
                <th className="px-6 py-3 text-left">Status</th>
                <th className="px-6 py-3 text-left">Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.map((user) => (
                <tr key={user.id} className="border-b border-[#f2f2f3]">
                  <td className="px-6 py-4">
                    <div className="flex items-center">
                      <div className="w-8 h-8 rounded-full bg-gray-200 flex items-center justify-center overflow-hidden mr-3 flex-shrink-0">
                        {user.profileImage ? (
                          <img
                            src={`https://elysian-ryc6x.ondigitalocean.app/elysian-back${user.profileImage}`}
                            alt={user.username}
                            className="w-full h-full object-cover"
                            onError={(e) => (e.currentTarget.style.display = 'none')}
                          />
                        ) : (
                          <span className="text-gray-500 text-sm font-medium">
                            {user.username?.charAt(0).toUpperCase()}
                          </span>
                        )}
                      </div>
                      <span>{user.username}</span>
                    </div>
                  </td>
                  <td className="px-6 py-4">{user.email}</td>
                  <td className="px-6 py-4">
                    <select
                      className="rounded-lg border border-[#8ca4ac] px-2 py-1 text-sm min-w-[120px]" 
                      value={user.role}
                      onChange={(e) => handleRoleChange(user.id, e.target.value as 'user' | 'admin')}
                      disabled={user.role === 'super_admin'}
                    >
                      <option value="user">User</option>
                      <option value="admin">Admin</option>
                    </select>
                  </td>
                  <td className="px-6 py-4">
                    {user.mfaEnabled ? (
                      <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                        Enabled
                      </span>
                    ) : (
                      <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-800">
                        Disabled
                      </span>
                    )}
                  </td>
                  <td className="px-6 py-4">
                    <select
                      className={`rounded-lg border px-2 py-1 text-sm ${
                        user.status === 'active'
                          ? 'border-green-300 bg-green-50'
                          : 'border-red-300 bg-red-50'
                      }`}
                      value={user.status}
                      onChange={(e) => handleStatusChange(user.id, e.target.value as 'active' | 'suspended')}
                      disabled={user.role === 'super_admin'}
                    >
                      <option value="active">Active</option>
                      <option value="suspended">Suspended</option>
                    </select>
                  </td>
                  <td className="px-6 py-4">
                    <button 
                      onClick={() => {
                        setSelectedUser(user);
                        setShowEditUserModal(true);
                      }}
                      className="text-[#217eaa] hover:text-[#1a6389] font-medium"
                    >
                      Edit Details
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        
        <div className="px-6 py-3 bg-white border-t border-[#f2f2f3] flex justify-between items-center">
          <div>
            <span className="text-sm text-gray-700">
              Page {page} of {totalPages}
            </span>
          </div>
          <div className="flex space-x-2">
            <button
              onClick={() => setPage(Math.max(1, page - 1))}
              disabled={page === 1}
              className={`px-3 py-1 rounded ${
                page === 1
                  ? 'bg-gray-100 text-gray-400 cursor-not-allowed'
                  : 'bg-[#217eaa] text-white hover:bg-[#1a6389]'
              }`}
            >
              Previous
            </button>
            <button
              onClick={() => setPage(Math.min(totalPages, page + 1))}
              disabled={page === totalPages}
              className={`px-3 py-1 rounded ${
                page === totalPages
                  ? 'bg-gray-100 text-gray-400 cursor-not-allowed'
                  : 'bg-[#217eaa] text-white hover:bg-[#1a6389]'
              }`}
            >
              Next
            </button>
          </div>
        </div>
      </div>
      
      {showEditUserModal && selectedUser && (
        <EditUserModal
          user={selectedUser}
          onClose={() => setShowEditUserModal(false)}
          onSaveSuccess={() => {
            fetchUsers();
          }}
        />
      )}

      {showCreateModal && (
        <CreateUserModal 
          onClose={() => setShowCreateModal(false)} 
          onSuccess={() => {
            fetchUsers();
          }} 
        />
      )}
    </div>
  );
}

function FileManagement() {
  const [files, setFiles] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [search, setSearch] = useState('');
  const [selectedFileId, setSelectedFileId] = useState<string | null>(null);
  const [showDetailsModal, setShowDetailsModal] = useState(false);
  const [fileToDelete, setFileToDelete] = useState<any | null>(null);

  useEffect(() => {
    fetchFiles();
  }, [page]);

  const fetchFiles = async () => {
    setLoading(true);
    try {
      const result = await api.admin.listAllFiles({
        page,
        limit: 10,
        search: search.trim() ? search : undefined
      });
      setFiles(result.files);
      setTotalPages(result.pages);
    } catch (error) {
      console.error('Failed to fetch files:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleSearch = () => {
    setPage(1);
    fetchFiles();
  };

  const formatFileSize = (bytes: number) => {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
    return (bytes / (1024 * 1024 * 1024)).toFixed(1) + ' GB';
  };

  const handleDeleteClick = (file: any) => {
    setFileToDelete(file);
  };

  const confirmDelete = async () => {
    if (!fileToDelete) return;

    try {
      await api.admin.deleteFile(fileToDelete.id);
      setFileToDelete(null);
      fetchFiles();
    } catch (error) {
      console.error('Failed to delete file:', error);
      setFileToDelete(null);
    }
  };

  return (
    <div>
      <div className="flex justify-between items-center mb-6">
        <h2 className="text-2xl font-semibold">File Management</h2>
        <div className="flex space-x-2">
          <div className="relative">
            <Search className="w-5 h-5 absolute left-3 top-1/2 transform -translate-y-1/2 text-[#8ca4ac]" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
              placeholder="Search files..."
              className="pl-10 pr-4 py-2 rounded-lg border border-[#8ca4ac] focus:outline-none focus:ring-2 focus:ring-[#217eaa]"
            />
          </div>
          <button
            onClick={handleSearch}
            className="bg-[#217eaa] text-white px-4 py-2 rounded-lg hover:bg-[#1a6389]"
          >
            Search
          </button>
        </div>
      </div>

      <div className="bg-white rounded-lg shadow-sm overflow-hidden">
        {loading ? (
          <div className="p-6 flex justify-center">
            <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-[#217eaa]"></div>
          </div>
        ) : (
          <table className="w-full">
            <thead>
              <tr className="bg-[#f2f2f3] text-[#8ca4ac] text-sm">
                <th className="px-6 py-3 text-left">File</th>
                <th className="px-6 py-3 text-left">Owner</th>
                <th className="px-6 py-3 text-left">Size</th>
                <th className="px-6 py-3 text-left">Uploaded</th>
                <th className="px-6 py-3 text-left">Actions</th>
              </tr>
            </thead>
            <tbody>
              {files.map((file) => (
                <tr key={file.id} className="border-b border-[#f2f2f3]">
                  <td className="px-6 py-4">
                    <div className="flex items-center">
                      <FileText className="w-5 h-5 mr-2 text-gray-500" />
                      <span>{file.originalName}</span>
                    </div>
                  </td>
                  <td className="px-6 py-4">{file.User?.username || 'N/A'}</td>
                  <td className="px-6 py-4">{formatFileSize(file.fileSize)}</td>
                  <td className="px-6 py-4">{new Date(file.uploadDate).toLocaleDateString()}</td>
                  <td className="px-6 py-4">
                    <div className="flex space-x-2">
                      <button
                        onClick={() => {
                          setSelectedFileId(file.id);
                          setShowDetailsModal(true);
                        }}
                        className="text-[#217eaa] hover:text-[#1a6389] font-medium text-sm"
                      >
                        Details
                      </button>
                      <button
                        onClick={() => handleDeleteClick(file)}
                        className="text-red-600 hover:text-red-800 font-medium text-sm"
                        title="Delete File"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        <div className="px-6 py-3 bg-white border-t border-[#f2f2f3] flex justify-between items-center">
          <div>
            <span className="text-sm text-gray-700">
              Page {page} of {totalPages}
            </span>
          </div>
          <div className="flex space-x-2">
            <button
              onClick={() => setPage(Math.max(1, page - 1))}
              disabled={page === 1}
              className={`px-3 py-1 rounded ${
                page === 1
                  ? 'bg-gray-100 text-gray-400 cursor-not-allowed'
                  : 'bg-[#217eaa] text-white hover:bg-[#1a6389]'
              }`}
            >
              Previous
            </button>
            <button
              onClick={() => setPage(Math.min(totalPages, page + 1))}
              disabled={page === totalPages}
              className={`px-3 py-1 rounded ${
                page === totalPages
                  ? 'bg-gray-100 text-gray-400 cursor-not-allowed'
                  : 'bg-[#217eaa] text-white hover:bg-[#1a6389]'
              }`}
            >
              Next
            </button>
          </div>
        </div>
      </div>

      {showDetailsModal && selectedFileId && (
        <FileDetailsModal
          fileId={selectedFileId}
          onClose={() => {
            setShowDetailsModal(false);
            setSelectedFileId(null);
          }}
        />
      )}

      {fileToDelete && (
        <ConfirmationModal
          title="Delete File"
          message={`Are you sure you want to permanently delete "${fileToDelete.originalName}"? This action cannot be undone.`}
          confirmLabel="Delete Permanently"
          confirmVariant="danger"
          onConfirm={confirmDelete}
          onCancel={() => setFileToDelete(null)}
        />
      )}
    </div>
  );
}

function ActivityMonitor() {
  const [logs, setLogs] = useState<ActivityLog[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [filters, setFilters] = useState({
    action: '',
    userId: '',
    startDate: '',
    endDate: '',
  });

  const fetchLogs = async (currentPage = page, currentFilters = filters) => {
    setIsLoading(true);
    setError(null);
    try {
      const params: any = {
        page: currentPage,
        limit: 15, // Adjust limit as needed
      };
      if (currentFilters.action) params.action = currentFilters.action;
      if (currentFilters.userId) params.userId = currentFilters.userId;
      if (currentFilters.startDate) params.startDate = currentFilters.startDate;
      if (currentFilters.endDate) params.endDate = currentFilters.endDate;

      // Use the admin API endpoint
      const result = await api.admin.getActivityLogs(params);

      if (result && result.logs) {
        // Format logs slightly for the table if needed (e.g., date formatting)
        const formattedLogs = result.logs.map((log: any) => ({
          ...log,
          // Ensure timestamp is a Date object or formatted string if ActivityTable expects it
          timestamp: new Date(log.timestamp),
          // Extract username if ActivityTable needs it directly
          username: log.User?.username || 'System',
          // Extract filename if ActivityTable needs it directly
          // Note: The admin route doesn't include File by default, adjust if needed
          fileName: log.details?.fileName || log.fileId || 'N/A',
        }));
        setLogs(formattedLogs);
        setTotalPages(result.pages || 1);
      } else {
        setLogs([]);
        setTotalPages(1);
      }
    } catch (err: any) {
      console.error('Failed to fetch activity logs:', err);
      setError(err.message || 'Failed to load activity logs.');
      setLogs([]);
      setTotalPages(1);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs(page, filters);
  }, [page, filters]); // Refetch when page or filters change

  const handleFilterChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => {
    const { name, value } = e.target;
    setFilters(prev => ({ ...prev, [name]: value }));
    setPage(1); // Reset to page 1 when filters change
  };

  const handlePageChange = (newPage: number) => {
    setPage(newPage);
  };

  return (
    <div>
      <h2 className="text-2xl font-semibold mb-6">Activity Monitor</h2>

      {/* --- Add Filter Controls --- */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6 p-4 bg-gray-50 rounded-lg border">
        <div>
          <label htmlFor="actionFilter" className="block text-sm font-medium text-gray-700 mb-1">Action</label>
          <select
            id="actionFilter"
            name="action"
            value={filters.action}
            onChange={handleFilterChange}
            className="w-full rounded-lg border border-gray-300 px-3 py-2 focus:outline-none focus:ring-2 focus:ring-[#217eaa]"
          >
            <option value="">All Actions</option>
            {/* Add relevant actions from Activity_Log model ENUM */}
            <option value="login">Login</option>
            <option value="upload">Upload</option>
            <option value="download">Download</option>
            <option value="share">Share</option>
            <option value="delete">Delete</option>
            <option value="admin_delete_file">Admin Delete File</option>
            <option value="create_user">Create User</option>
            <option value="update_user">Update User</option>
            <option value="update_system_settings">Update Settings</option>
            {/* Add other actions as needed */}
          </select>
        </div>
        <div>
          <label htmlFor="userFilter" className="block text-sm font-medium text-gray-700 mb-1">User ID</label>
          <input
            type="text"
            id="userFilter"
            name="userId"
            value={filters.userId}
            onChange={handleFilterChange}
            placeholder="Enter User ID"
            className="w-full rounded-lg border border-gray-300 px-3 py-2 focus:outline-none focus:ring-2 focus:ring-[#217eaa]"
          />
        </div>
        <div>
          <label htmlFor="startDateFilter" className="block text-sm font-medium text-gray-700 mb-1">Start Date</label>
          <input
            type="date"
            id="startDateFilter"
            name="startDate"
            value={filters.startDate}
            onChange={handleFilterChange}
            className="w-full rounded-lg border border-gray-300 px-3 py-2 focus:outline-none focus:ring-2 focus:ring-[#217eaa]"
          />
        </div>
        <div>
          <label htmlFor="endDateFilter" className="block text-sm font-medium text-gray-700 mb-1">End Date</label>
          <input
            type="date"
            id="endDateFilter"
            name="endDate"
            value={filters.endDate}
            onChange={handleFilterChange}
            className="w-full rounded-lg border border-gray-300 px-3 py-2 focus:outline-none focus:ring-2 focus:ring-[#217eaa]"
          />
        </div>
      </div>
      {/* --- End Filter Controls --- */}

      {isLoading ? (
        <div className="flex justify-center items-center p-16">
          <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-[#217eaa]"></div>
        </div>
      ) : error ? (
        <div className="p-6 text-center text-red-600 bg-red-50 rounded-lg">{error}</div>
      ) : (
        // Use the ActivityTable component for display
        <ActivityTable
          logs={logs}
          totalPages={totalPages}
          currentPage={page}
          onPageChange={handlePageChange}
          // Pass any other props ActivityTable might need
        />
      )}
    </div>
  );
}

function SystemSettings() {
  const [settings, setSettings] = useState<SystemSettings>({
    enforceTwo2FA: false,
    fileExpiration: true,
    maxFileSize: 100, // Default MB
    storageQuota: 5000, // Default GB
  });
  const [isLoading, setIsLoading] = useState(true);
  const [isSaving, setIsSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  useEffect(() => {
    const fetchSettings = async () => {
      setIsLoading(true);
      setError(null);
      try {
        const data = await api.admin.getSystemSettings(); // Use getSystemSettings
        setSettings(data);
      } catch (err: any) {
        setError(err.message || 'Failed to load system settings.');
      } finally {
        setIsLoading(false);
      }
    };
    fetchSettings();
  }, []);

  const handleToggleChange = (key: keyof Pick<SystemSettings, 'enforceTwo2FA' | 'fileExpiration'>) => {
    setSettings(prev => ({ ...prev, [key]: !prev[key] }));
    setSuccessMessage(null);
  };

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    const numValue = Math.max(0, parseInt(value, 10) || 0);
    setSettings(prev => ({ ...prev, [name]: numValue }));
    setSuccessMessage(null);
  };

  const handleSave = async () => {
    setIsSaving(true);
    setError(null);
    setSuccessMessage(null);
    try {
      const updatedSettings = await api.admin.updateSystemSettings(settings); // Use updateSystemSettings
      setSettings(updatedSettings);
      setSuccessMessage('System settings updated successfully.');
    } catch (err: any) {
      setError(err.message || 'Failed to save system settings.');
    } finally {
      setIsSaving(false);
    }
  };

  if (isLoading) {
    return (
      <div className="flex justify-center items-center p-16">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-[#217eaa]"></div>
      </div>
    );
  }

  return (
    <div>
      <h2 className="text-2xl font-semibold mb-6">System Settings</h2>

      {error && (
        <div className="mb-6 p-4 rounded-lg bg-red-100 text-red-700 flex items-center">
          <AlertCircle className="h-5 w-5 mr-2" />
          {error}
        </div>
      )}
      {successMessage && (
        <div className="mb-6 p-4 rounded-lg bg-green-100 text-green-700 flex items-center">
          <Check className="h-5 w-5 mr-2" />
          {successMessage}
        </div>
      )}

      <div className="bg-white rounded-lg shadow-sm p-6 space-y-6">
        <div className="flex items-center justify-between border-b pb-4">
          <div>
            <p className="text-sm font-medium text-gray-700">Enforce Two-Factor Authentication</p>
            <p className="text-xs text-gray-500">Require all users to set up and use 2FA.</p>
          </div>
          <label className="relative inline-flex items-center cursor-pointer">
            <input
              type="checkbox"
              className="sr-only peer"
              checked={settings.enforceTwo2FA}
              onChange={() => handleToggleChange('enforceTwo2FA')}
              disabled={isSaving}
            />
            <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-[#217eaa] rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-[#217eaa]"></div>
          </label>
        </div>

        <div className="flex items-center justify-between border-b pb-4">
          <div>
            <p className="text-sm font-medium text-gray-700">Enable Automatic File Expiration</p>
            <p className="text-xs text-gray-500">Allow users to set expiration dates for shared links/files.</p>
          </div>
          <label className="relative inline-flex items-center cursor-pointer">
            <input
              type="checkbox"
              className="sr-only peer"
              checked={settings.fileExpiration}
              onChange={() => handleToggleChange('fileExpiration')}
              disabled={isSaving}
            />
            <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-[#217eaa] rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-[#217eaa]"></div>
          </label>
        </div>

        <div className="border-b pb-4">
          <label htmlFor="maxFileSize" className="block text-sm font-medium text-gray-700 mb-1">
            Maximum File Upload Size (MB)
          </label>
          <p className="text-xs text-gray-500 mb-2">Set the maximum size for individual file uploads.</p>
          <input
            id="maxFileSize"
            name="maxFileSize"
            type="number"
            value={settings.maxFileSize}
            onChange={handleInputChange}
            min="1"
            className="w-full md:w-1/3 rounded-lg border border-gray-300 px-3 py-2 focus:outline-none focus:ring-2 focus:ring-[#217eaa]"
            disabled={isSaving}
          />
        </div>

        <div className="border-b pb-4">
          <label htmlFor="storageQuota" className="block text-sm font-medium text-gray-700 mb-1">
            Default User Storage Quota (GB)
          </label>
          <p className="text-xs text-gray-500 mb-2">Set the default storage limit for new users (can be overridden by department).</p>
          <input
            id="storageQuota"
            name="storageQuota"
            type="number"
            value={settings.storageQuota}
            onChange={handleInputChange}
            min="1"
            className="w-full md:w-1/3 rounded-lg border border-gray-300 px-3 py-2 focus:outline-none focus:ring-2 focus:ring-[#217eaa]"
            disabled={isSaving}
          />
        </div>

        <div className="flex justify-end pt-4">
          <Button
            variant="primary"
            icon={<Save className="w-4 h-4" />}
            onClick={handleSave}
            isLoading={isSaving}
            disabled={isLoading}
          >
            Save Settings
          </Button>
        </div>
      </div>
    </div>
  );
}

interface EditUserModalProps {
  user: User;
  onClose: () => void;
  onSaveSuccess: () => void;
}

function EditUserModal({ user, onClose, onSaveSuccess }: EditUserModalProps) {
  const [editedUsername, setEditedUsername] = useState(user.username);
  const [editedEmail, setEditedEmail] = useState(user.email);
  const [selectedDepartmentId, setSelectedDepartmentId] = useState<string | null>(user.departmentId?.toString() || null); // Store ID as string or null
  const [departments, setDepartments] = useState<{ id: number; name: string }[]>([]);
  const [loadingDepartments, setLoadingDepartments] = useState(true);
  const [isSaving, setIsSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchDepartments = async () => {
      setLoadingDepartments(true);
      try {
        const deptData = await api.admin.getDepartments();
        setDepartments(deptData || []);
      } catch (err) {
        console.error("Failed to fetch departments for modal:", err);
      } finally {
        setLoadingDepartments(false);
      }
    };
    fetchDepartments();
  }, []);

  const handleSave = async () => {
    setIsSaving(true);
    setError(null);

    const dataToUpdate: { username?: string; email?: string; departmentId?: number | null } = {};
    if (editedUsername !== user.username) {
      dataToUpdate.username = editedUsername;
    }
    if (editedEmail !== user.email) {
      dataToUpdate.email = editedEmail;
    }
    const currentDepartmentId = user.departmentId?.toString() || null;
    if (selectedDepartmentId !== currentDepartmentId) {
      dataToUpdate.departmentId = selectedDepartmentId ? parseInt(selectedDepartmentId, 10) : null;
    }

    if (Object.keys(dataToUpdate).length > 0) {
      try {
        await api.admin.updateUser(user.id, dataToUpdate);
        onSaveSuccess();
        onClose();
      } catch (err: any) {
        setError(err.message || 'Failed to update user details.');
      } finally {
        setIsSaving(false);
      }
    } else {
      setIsSaving(false);
      onClose();
    }
  };

  const handleDepartmentChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const value = e.target.value;
    setSelectedDepartmentId(value === '' ? null : value); // Set to null if 'None' is chosen
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-lg p-6 w-full max-w-md">
        <div className="flex justify-between items-center mb-6">
          <h3 className="text-xl font-semibold">Edit User Details</h3>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-700" disabled={isSaving}>
            &times;
          </button>
        </div>

        {error && (
          <div className="bg-red-50 p-3 rounded-lg mb-4 text-red-700 text-sm">
            {error}
          </div>
        )}

        <div className="space-y-4 mb-6">
          <div className="flex items-center">
            <div className="w-16 h-16 rounded-full bg-gray-200 flex items-center justify-center mr-4 overflow-hidden">
              {user.profileImage ? (
                <img src={user.profileImage} alt={user.username} className="w-full h-full object-cover" />
              ) : (
                <span className="text-gray-500 text-xl">{user.username?.charAt(0).toUpperCase()}</span>
              )}
            </div>
            <span className="text-lg font-medium">{user.username}</span>
          </div>

          <div>
            <label htmlFor="username" className="block text-sm font-medium text-gray-700 mb-1">
              Username
            </label>
            <input
              id="username"
              type="text"
              value={editedUsername}
              onChange={(e) => setEditedUsername(e.target.value)}
              className="w-full rounded-lg border border-gray-300 px-3 py-2 focus:outline-none focus:ring-2 focus:ring-[#217eaa]"
              disabled={isSaving}
            />
          </div>

          <div>
            <label htmlFor="email" className="block text-sm font-medium text-gray-700 mb-1">
              Email
            </label>
            <input
              id="email"
              type="email"
              value={editedEmail}
              onChange={(e) => setEditedEmail(e.target.value)}
              className="w-full rounded-lg border border-gray-300 px-3 py-2 focus:outline-none focus:ring-2 focus:ring-[#217eaa]"
              disabled={isSaving}
            />
          </div>

          <div>
            <label htmlFor="department" className="block text-sm font-medium text-gray-700 mb-1">
              Department
            </label>
            {loadingDepartments ? (
              <div className="h-10 w-full rounded-lg border border-gray-300 px-3 py-2 bg-gray-100 animate-pulse"></div>
            ) : (
              <select
                id="department"
                name="department"
                value={selectedDepartmentId ?? ''} // Use empty string for 'None' option value
                onChange={handleDepartmentChange} // Use the new handler
                disabled={isSaving}
                className="w-full rounded-lg border border-gray-300 px-3 py-2 focus:outline-none focus:ring-2 focus:ring-[#217eaa]" // Basic styling
              >
                <option value="">-- None --</option>
                {departments.map((dept) => (
                  <option key={dept.id} value={dept.id.toString()}>
                    {dept.name}
                  </option>
                ))}
              </select>
            )}
          </div>

          <div className="space-y-1 text-sm text-gray-600 pt-2">
            <p><span className="font-medium text-gray-800">User ID:</span> {user.id}</p>
            <p><span className="font-medium text-gray-800">Role:</span> {user.role}</p>
            <p><span className="font-medium text-gray-800">Status:</span> {user.status}</p>
            <p><span className="font-medium text-gray-800">MFA:</span> {user.mfaEnabled ? 'Enabled' : 'Disabled'}</p>
            <p>
              <span className="font-medium text-gray-800">Department:</span>{' '}
              {user.Department ? user.Department.name : 'None'}
            </p>
          </div>
        </div>

        <div className="flex justify-end space-x-3">
          <button
            onClick={onClose}
            className="bg-gray-200 text-gray-700 px-4 py-2 rounded-lg hover:bg-gray-300"
            disabled={isSaving}
          >
            Cancel
          </button>
          <button
            onClick={handleSave}
            className={`bg-[#217eaa] text-white px-4 py-2 rounded-lg hover:bg-[#1a6389] ${
              isSaving ? 'opacity-70 cursor-not-allowed' : ''
            }`}
            disabled={isSaving}
          >
            {isSaving ? 'Saving...' : 'Save Changes'}
          </button>
        </div>
      </div>
    </div>
  );
}

interface FileDetailsModalProps {
  fileId: string;
  onClose: () => void;
}

function FileDetailsModal({ fileId, onClose }: FileDetailsModalProps) {
  const [details, setDetails] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchDetails = async () => {
      setIsLoading(true);
      setError(null);
      try {
        const data = await api.admin.getFileDetails(fileId);
        setDetails(data);
      } catch (err: any) {
        setError(err.message || 'Failed to load file details.');
      } finally {
        setIsLoading(false);
      }
    };
    fetchDetails();
  }, [fileId]);

  const formatBytes = (bytes: number, decimals = 2) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-lg p-6 w-full max-w-lg max-h-[90vh] overflow-y-auto">
        <div className="flex justify-between items-center mb-6">
          <h3 className="text-xl font-semibold flex items-center">
            <FileText className="w-5 h-5 mr-2 text-[#217eaa]" />
            File Details
          </h3>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-700">
            <X className="w-5 h-5" />
          </button>
        </div>

        {isLoading && (
          <div className="flex justify-center items-center h-40">
             <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-[#217eaa]"></div>
          </div>
        )}
        {error && (
          <div className="bg-red-50 p-3 rounded-lg mb-4 text-red-700 text-sm">
            {error}
          </div>
        )}
        {details && !isLoading && !error && (
          <div className="space-y-4 text-sm">
            <p><strong className="font-medium text-gray-700 w-32 inline-block">File ID:</strong> {details.id}</p>
            <p><strong className="font-medium text-gray-700 w-32 inline-block">Original Name:</strong> {details.originalName}</p>
            <p><strong className="font-medium text-gray-700 w-32 inline-block">Stored Name:</strong> {details.fileName}</p>
            <p><strong className="font-medium text-gray-700 w-32 inline-block">Size:</strong> {formatBytes(details.fileSize)}</p>
            <p><strong className="font-medium text-gray-700 w-32 inline-block">Type:</strong> {details.fileType}</p>
            <p><strong className="font-medium text-gray-700 w-32 inline-block">Uploaded:</strong> {new Date(details.uploadDate).toLocaleString()}</p>
            {details.expiryDate && <p><strong className="font-medium text-gray-700 w-32 inline-block">Expires:</strong> {new Date(details.expiryDate).toLocaleString()}</p>}
            <p><strong className="font-medium text-gray-700 w-32 inline-block">Deleted:</strong> {details.isDeleted ? 'Yes' : 'No'}</p>

            <div className="pt-2 mt-2 border-t">
              <h4 className="font-semibold mb-2 flex items-center"><UserIcon className="w-4 h-4 mr-2 text-gray-600"/>Owner</h4>
              <p><strong className="font-medium text-gray-700 w-32 inline-block">User ID:</strong> {details.User?.id || 'N/A'}</p>
              <p><strong className="font-medium text-gray-700 w-32 inline-block">Username:</strong> {details.User?.username || 'N/A'}</p>
              <p><strong className="font-medium text-gray-700 w-32 inline-block">Email:</strong> {details.User?.email || 'N/A'}</p>
            </div>

            {details.Team && (
              <div className="pt-2 mt-2 border-t">
                <h4 className="font-semibold mb-2 flex items-center"><TeamIcon className="w-4 h-4 mr-2 text-gray-600"/>Team</h4>
                <p><strong className="font-medium text-gray-700 w-32 inline-block">Team ID:</strong> {details.Team.id}</p>
                <p><strong className="font-medium text-gray-700 w-32 inline-block">Team Name:</strong> {details.Team.name}</p>
              </div>
            )}

            <div className="pt-2 mt-2 border-t">
              <h4 className="font-semibold mb-2 flex items-center"><Key className="w-4 h-4 mr-2 text-gray-600"/>Security</h4>
              <p><strong className="font-medium text-gray-700 w-32 inline-block">IV:</strong> {details.iv ? 'Present' : 'Missing'}</p>
              <p><strong className="font-medium text-gray-700 w-32 inline-block">File Hash:</strong> <span className="break-all">{details.fileHash || 'N/A'}</span></p>
            </div>

          </div>
        )}

        <div className="flex justify-end mt-6">
          <button
            onClick={onClose}
            className="bg-gray-200 text-gray-700 px-4 py-2 rounded-lg hover:bg-gray-300"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}