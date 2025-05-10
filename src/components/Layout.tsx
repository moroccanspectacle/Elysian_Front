import React, { useState, useEffect } from 'react'; // Import useEffect
import { Files, Activity, Settings, Upload, Bell, User, Share2, Users, Shield } from 'lucide-react';
import { useNavigate, Link, useLocation } from 'react-router-dom'; // Import useLocation
import { ProfileMenu } from './ProfileMenu';
import { useAuth } from './AuthContext';
import { FileUploadModal } from './FileUploadModal';
import { NotificationDropdown } from './NotificationDropdown';

interface LayoutProps {
  children: React.ReactNode;
  onFileUploaded?: () => void;
  // Removed currentView/setCurrentView props - manage active state via route
}

export function Layout({ children, onFileUploaded }: LayoutProps) {
  const navigate = useNavigate();
  const location = useLocation(); // Get current location
  const [activeTab, setActiveTab] = useState('Files'); // Single state for active tab label

  const [isProfileMenuOpen, setIsProfileMenuOpen] = useState(false);
  const [showUploadModal, setShowUploadModal] = useState(false);
  const { user } = useAuth();

  // Effect to update activeTab based on the current route
  useEffect(() => {
    const path = location.pathname;
    const currentView = location.state?.view; // Check for view state passed during navigation

    if (path === '/dashboard') {
      // Check state passed via navigate to differentiate between Files and Activity on the same path
      setActiveTab(currentView === 'activity' ? 'Activity' : 'Files');
    } else if (path === '/teams') {
      setActiveTab('Teams');
    } else if (path === '/shared-links') {
      setActiveTab('Shared Links');
    } else if (path === '/settings') {
      setActiveTab('Settings');
    } else if (path === '/vault') {
      setActiveTab('Vault');
    } else if (path === '/admin') {
      setActiveTab('Admin');
    } else {
      // Optional: Handle default or other paths if necessary
      // setActiveTab(''); // Or set to a default if needed
    }
  }, [location.pathname, location.state]); // Re-run when path or state changes

  // Remove unused handleTabClick and safeNavigate functions
  // ...

  const handleUpload = () => {
    setShowUploadModal(true);
  };

  const handleUploadSuccess = () => {
    if (onFileUploaded) {
      onFileUploaded();
    }
  };

  const getProfileImageUrl = (imagePath: string | null | undefined) => {
    if (!imagePath) return undefined;
    if (imagePath.startsWith('http')) return imagePath;
    return `hhttps://elysian-ryc6x.ondigitalocean.app/elysian-back${imagePath}`;
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-neutral-50 to-neutral-100 flex">
      {/* Sidebar */}
      <aside className="w-64 bg-white shadow-lg rounded-r-xl my-4 ml-4 overflow-hidden flex flex-col">
        <div className="p-6 border-b border-neutral-100">
          <h1
            className="text-2xl font-display font-bold bg-gradient-to-r from-primary-600 to-secondary-500 bg-clip-text text-transparent cursor-pointer"
            onClick={() => navigate('/')} // Navigate to home/root
          >
            Elysian Vault
          </h1>
        </div>
        <nav className="mt-6 flex-grow">
          {[
            { icon: Files, label: 'Files', path: '/dashboard', view: 'files' }, // Add view:'files' for clarity
            { icon: Users, label: 'Teams', path: '/teams' },
            { icon: Share2, label: 'Shared Links', path: '/shared-links' },
            { icon: Activity, label: 'Activity', path: '/dashboard', view: 'activity' },
            { icon: Settings, label: 'Settings', path: '/settings' },
            { icon: Shield, label: 'Vault', path: '/vault' }
          ].map((item) => (
            <button
              key={item.label}
              className={`w-full flex items-center px-6 py-4 ${
                activeTab === item.label
                  ? 'text-primary-600 bg-primary-50 border-r-4 border-primary-500'
                  : 'text-neutral-600'
              } hover:bg-neutral-50 transition-all duration-200`}
              onClick={() => {
                // Navigate and pass 'view' state if defined (for Dashboard)
                navigate(item.path, { replace: true, state: { view: item.view } });
              }}
            >
              <item.icon className={`w-5 h-5 mr-3 ${activeTab === item.label ? 'text-primary-500' : 'text-neutral-500'}`} />
              <span className="font-medium">{item.label}</span>
            </button>
          ))}
          {user && (user.role === 'admin' || user.role === 'super_admin') && (
            <Link
              to="/admin"
              className={`w-full flex items-center px-6 py-4 ${ // Use button styling
                activeTab === 'Admin'
                  ? 'text-primary-600 bg-primary-50 border-r-4 border-primary-500'
                  : 'text-neutral-600'
              } hover:bg-neutral-50 transition-all duration-200`}
            >
              <Shield className={`w-5 h-5 mr-3 ${activeTab === 'Admin' ? 'text-primary-500' : 'text-neutral-500'}`} />
              <span className="font-medium">Admin</span>
            </Link>
          )}
        </nav>
        <div className="p-6 border-t border-neutral-100">
          <div className="text-xs text-neutral-500">
            Elysian Vault v1.0
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <div className="flex-1 flex flex-col">
        {/* ... Header ... */}
         <header className="bg-white m-4 rounded-xl flex items-center justify-between px-6 py-3 shadow-sm">
          <button
            className="bg-gradient-to-r from-primary-500 to-secondary-500 hover:from-primary-600 hover:to-secondary-600 text-white px-5 py-2.5 rounded-lg flex items-center transition-all duration-300 shadow-md hover:shadow-lg font-medium"
            onClick={handleUpload}
          >
            <Upload className="w-4 h-4 mr-2" />
            Upload File
          </button>
          <div className="flex items-center space-x-4">
            <NotificationDropdown />
            <div className="relative">
              <button
                className="w-10 h-10 rounded-full ring-2 ring-neutral-200 flex items-center justify-center text-white overflow-hidden shadow-md hover:ring-primary-300 transition-all"
                onClick={() => setIsProfileMenuOpen(!isProfileMenuOpen)}
              >
                {user?.profileImage ? (
                  <img
                    className="h-10 w-10 rounded-full object-cover"
                    src={getProfileImageUrl(user.profileImage)}
                    alt={user.username || 'User'}
                    key={user.profileImage}
                  />
                ) : (
                  <div className="w-full h-full bg-gradient-to-br from-primary-500 to-primary-600 flex items-center justify-center">
                    <User className="w-5 h-5" />
                  </div>
                )}
              </button>
              <ProfileMenu
                isOpen={isProfileMenuOpen}
                onClose={() => setIsProfileMenuOpen(false)}
              />
            </div>
          </div>
        </header>
        <main className="flex-grow p-6 overflow-auto">
          <div className="max-w-7xl mx-auto">
            {children}
          </div>
        </main>
      </div>

      {showUploadModal && (
        <FileUploadModal
          onClose={() => setShowUploadModal(false)}
          onSuccess={handleUploadSuccess}
        />
      )}
    </div>
  );
}