import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { LandingPage } from './pages/LandingPage';
import { AdminPage } from './pages/AdminPage';
import { AuthForm } from './components/AuthForm';
import { Layout } from './components/Layout';
import { FileCard } from './components/FileCard';
import { ShareModal } from './components/ShareModal';
import { ActivityTable } from './components/ActivityTable';
import type { FileItem, ActivityLog } from './types';
import { AuthProvider, useAuth } from './components/AuthContext';
import { ProtectedRoute } from './components/ProtectedRoute';
import { ProfilePage } from './pages/ProfilePage';
import { api } from './services/api';
import { SettingsPage } from './pages/SettingsPage';
import { SharedFilePage } from './pages/SharedFilePage';
import { SharedLinksPage } from './pages/SharedLinksPage';
import { Search, FileText, AlertCircle, Upload, Settings } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { LoadingSpinner } from './components/LoadingSpinner';
import { EmptyState } from './components/EmptyState';
import { Button } from './components/Button';
import { DocumentViewer } from './components/DocumentViewer';
import { TeamsPage } from './pages/TeamsPage';
import { TeamDetailsPage } from './pages/TeamDetailsPage';
import { TeamMembersPage } from './pages/TeamMembersPage';
import { TeamFilesPage } from './pages/TeamFilesPage';
import { TeamSettingsPage } from './pages/TeamSettingsPage';
import { ForgotPasswordPage } from './pages/ForgotPasswordPage';
import { ResetPasswordPage } from './pages/ResetPasswordPage';
import { SetupPasswordPage } from './pages/SetupPasswordPage';
import { AdminRoute } from './components/AdminRoute';
import { AdminDashboard } from './pages/AdminDashboard';
import { Dashboard } from './pages/Dashboard';
import { VaultPage } from './pages/VaultPage';

// Mock data for activity logs - we'll keep this for now
const mockLogs: ActivityLog[] = [
  { id: '1', timestamp: '2024-02-20 14:30', action: 'upload', fileName: 'Project Proposal.pdf' },
  { id: '2', timestamp: '2024-02-19 16:45', action: 'download', fileName: 'Financial Report.xlsx' },
  { id: '3', timestamp: '2024-02-18 09:15', action: 'share', fileName: 'Meeting Notes.docx' },
  { id: '4', timestamp: '2024-02-17 11:20', action: 'delete', fileName: 'Old Version.pdf' },
];

function SpecialMfaSetupPage() {
  return <AuthForm mode="login" />;
}

function AppContent() {
  return (
    <Routes>
      {/* Public routes */}
      <Route path="/" element={<LandingPage />} />
      <Route path="/login" element={<AuthForm mode="login" />} />
      <Route path="/register" element={<AuthForm mode="register" />} />
      <Route path="/forgot-password" element={<ForgotPasswordPage />} />
      <Route path="/reset-password/:token" element={<ResetPasswordPage />} />
      <Route path="/setup-password/:token" element={<SetupPasswordPage />} />
      <Route path="/share/:shareToken" element={<SharedFilePage />} />
      
      {/* Protected routes */}
      <Route element={<ProtectedRoute />}>
        {/* Other protected routes */}
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/teams/" element={<TeamsPage />} />
        <Route path="/teams/:teamId" element={<TeamDetailsPage />} />
        {/* --- Add these routes --- */}
        <Route path="/teams/:teamId/members" element={<TeamMembersPage />} />
        <Route path="/teams/:teamId/files" element={<TeamFilesPage />} />
        <Route path="/teams/:teamId/settings" element={<TeamSettingsPage />} />
        {/* --- End added routes --- */}
        <Route path="/profile" element={<ProfilePage />} />
        <Route path="/shared-links" element={<SharedLinksPage />} /> 
        <Route path="/settings" element={<SettingsPage />} />       
        <Route path="/vault" element={<VaultPage />} />  
        
        {/* Admin routes - consolidated approach */}
        <Route element={<AdminRoute />}>
          <Route path="/admin" element={<AdminDashboard />} />
          <Route path="/admin/users" element={<AdminPage activeTab="users" />} />
          <Route path="/admin/departments" element={<AdminPage activeTab="departments" />} />
          <Route path="/admin/files" element={<AdminPage activeTab="files" />} />
          <Route path="/admin/activity" element={<AdminPage activeTab="activity" />} />
          <Route path="/admin/settings" element={<AdminPage activeTab="settings" />} />
        </Route>
        
        {/* Default redirect */}
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Route>
    </Routes>
  );
}

function App() {
  return (
    <Router>
      <AuthProvider>
        <AppContent />
      </AuthProvider>
    </Router>
  );
}

export default App;