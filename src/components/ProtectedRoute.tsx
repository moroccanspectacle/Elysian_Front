import React from 'react';
import { Navigate, Outlet, useLocation } from 'react-router-dom';
import { useAuth } from './AuthContext';

export const ProtectedRoute = () => {
  const { isAuthenticated } = useAuth();
  const location = useLocation();
  
  // Only check authentication, don't redirect anywhere else
  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  // Use Outlet to render child routes
  return <Outlet />;
};