import React, { useRef, useEffect, useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { User, Settings, LogOut } from 'lucide-react';
import { useAuth } from '../components/AuthContext';

interface ProfileMenuProps {
  isOpen: boolean;
  onClose: () => void;
}

export const ProfileMenu: React.FC<ProfileMenuProps> = ({ isOpen, onClose }) => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const menuRef = useRef<HTMLDivElement>(null);

  // Close menu when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) {
        onClose();
      }
    };

    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside);
    }
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  return (
    <div 
      className="absolute right-0 top-16 mt-2 w-56 rounded-md shadow-lg bg-white ring-1 ring-black ring-opacity-5 z-50"
      ref={menuRef}
    >
      <div className="py-1">
        <div className="px-4 py-3 border-b">
          <p className="text-sm font-medium text-gray-900">{user.username || 'User'}</p>
          <p className="text-sm text-gray-500 truncate">{user.email}</p>
        </div>
        
        <button 
          onClick={() => {
            navigate('/profile');
            onClose();
          }}
          className="flex items-center px-4 py-2 text-sm text-gray-700 w-full text-left hover:bg-gray-100"
        >
          <User className="mr-3 h-4 w-4" />
          Profile
        </button>
        
        <button 
          onClick={() => {
            navigate('/settings');
            onClose();
          }}
          className="flex items-center px-4 py-2 text-sm text-gray-700 w-full text-left hover:bg-gray-100"
        >
          <Settings className="mr-3 h-4 w-4" />
          Settings
        </button>

        {user?.role === 'admin' || user?.role === 'super_admin' ? (
          <Link 
            to="/admin"
            className="block px-4 py-2 text-gray-700 hover:bg-gray-100 flex items-center"
            onClick={onClose}
          >
            <Settings className="w-4 h-4 mr-2" />
            Admin Dashboard
          </Link>
        ) : null}
        
        <button 
          onClick={() => {
            logout();
            onClose();
          }}
          className="flex items-center px-4 py-2 text-sm text-gray-700 w-full text-left hover:bg-gray-100"
        >
          <LogOut className="mr-3 h-4 w-4" />
          Logout
        </button>
      </div>
    </div>
  );
};