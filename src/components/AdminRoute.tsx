import React from 'react';
import { Navigate, Outlet } from 'react-router-dom';
import { useAuth } from './AuthContext';

export function AdminRoute() {
  const { user, isLoading } = useAuth();
  
  // Show loading state
  if (isLoading) {
    return (
      <div className="flex justify-center items-center h-screen">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-[#217eaa]"></div>
      </div>
    );
  }
  
  // Redirect if not admin
  if (!user || (user.role !== 'admin' && user.role !== 'super_admin')) {
    return <Navigate to="/dashboard" replace />;
  }
  
  // Render child routes
  return <Outlet />;
}