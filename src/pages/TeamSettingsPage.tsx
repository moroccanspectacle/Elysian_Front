import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { Layout } from '../components/Layout';
import { api } from '../services/api';
import { 
  Settings, ChevronLeft, Shield, Trash2, AlertCircle, Save, Users, Lock
} from 'lucide-react';
import { Button } from '../components/Button';
import { ConfirmationModal } from '../components/ConfirmationModal';
import { useAuth } from '../components/AuthContext';
import { TwoFactorVerifyModal } from '../components/TwoFactorVerifyModal';

export function TeamSettingsPage() {
  const { teamId } = useParams<{ teamId: string }>();
  const navigate = useNavigate();
  const { user } = useAuth();
  const [team, setTeam] = useState<any>(null); // Keep state for team name display
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [showTwoFactorModal, setShowTwoFactorModal] = useState(false);
  const [pendingSaveData, setPendingSaveData] = useState<any>(null);
  
  // Settings states
  const [isUpdating, setIsUpdating] = useState(false);
  const [memberPermissions, setMemberPermissions] = useState({
    canInviteMembers: false,
    canUploadFiles: true,
    canDeleteFiles: false
  });
  const [securitySettings, setSecuritySettings] = useState({
    enforceFileEncryption: true,
    require2FAForSensitiveOperations: false
  });
  
  useEffect(() => {
    if (teamId) {
      // Fetch basic team details first to check status
      const checkTeamStatusAndLoad = async () => {
        setIsLoading(true);
        setError(null);
        try {
          const teamData = await api.teams.getTeam(teamId);
          setTeam(teamData); // Store basic team data for display

          // If user is invited, redirect back to team details page
          if (teamData.status === 'invited') {
            console.log('[TeamSettingsPage] User is invited, redirecting back to team details.');
            navigate(`/teams/${teamId}`);
            return; // Stop further execution
          }

          // If active, proceed to load actual settings
          await fetchTeamSettingsData(teamId);

        } catch (err: any) {
          console.error('Failed to fetch initial team data:', err);
          setError(err.message || 'Failed to load team information');
        } finally {
           if (window.location.pathname.includes(`/teams/${teamId}/settings`)) {
             setIsLoading(false);
          }
        }
      };
      checkTeamStatusAndLoad();
    } else {
      setError("Team ID not found.");
      setIsLoading(false);
    }
  }, [teamId, navigate]); // Add navigate

  // Renamed original fetch function
  const fetchTeamSettingsData = async (id: string) => {
    try {
      const settingsData = await api.teams.getSettings(id);
      if (settingsData) {
        setMemberPermissions(settingsData.memberPermissions || memberPermissions);
        setSecuritySettings(settingsData.securitySettings || securitySettings);
      }
    } catch (err) {
      console.error('Failed to fetch team settings data:', err);
      setError(prev => prev ? `${prev}\nFailed to load settings.` : 'Failed to load settings.');
    }
  };

  const saveSettings = async () => {
    try {
      setIsUpdating(true);
      
      const dataToSave = {
        memberPermissions,
        securitySettings
      };
      
      try {
        await api.teams.updateSettings(teamId!, dataToSave);
        setIsUpdating(false);
      } catch (err) {
        if (err instanceof Error && err.message === '2FA_REQUIRED') {
          // Save the data for after 2FA verification
          setPendingSaveData(dataToSave);
          setShowTwoFactorModal(true);
          setIsUpdating(false);
          return;
        }
        throw err;
      }
    } catch (err) {
      console.error('Failed to update team settings:', err);
      setError('Failed to save settings');
      setIsUpdating(false);
    }
  };

  const handleTwoFactorVerified = async (token: string) => {
    // Store the token in sessionStorage
    sessionStorage.setItem('sensitive-op-token', token);
    
    // Retry the operation with the token
    if (pendingSaveData) {
      try {
        setIsUpdating(true);
        await api.teams.updateSettings(teamId!, pendingSaveData);
        setPendingSaveData(null);
        setShowTwoFactorModal(false);
        setIsUpdating(false);
      } catch (err) {
        console.error('Failed to update team settings after 2FA:', err);
        setError('Failed to save settings');
        setIsUpdating(false);
      }
    }
  };
  
  const handleDeleteTeam = async () => {
    try {
      await api.teams.deleteTeam(teamId!);
      navigate('/teams');
    } catch (err) {
      console.error('Failed to delete team:', err);
      setError('Failed to delete team');
    }
  };
  
  if (isLoading) {
    return (
      <Layout>
        <div className="flex justify-center my-20">
          <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-primary-500"></div>
        </div>
      </Layout>
    );
  }

  if (error && !isLoading) {
    return (
      <Layout>
        <div className="max-w-4xl mx-auto">
          <div className="mb-6 bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg flex items-center">
            <AlertCircle className="w-5 h-5 mr-2" />
            {error}
          </div>
        </div>
      </Layout>
    );
  }

   // Ensure team exists before rendering main content
   if (!team || team.status === 'invited') {
       return null; // Render null while redirecting
   }

  return (
    <Layout>
      <div className="max-w-4xl mx-auto">
        {/* Header */}
        <div className="flex items-center mb-8">
          <button 
            className="mr-4 p-2 rounded-full hover:bg-gray-100"
            onClick={() => navigate(`/teams/${teamId}`)}
          >
            <ChevronLeft className="w-5 h-5 text-gray-600" />
          </button>
          <div>
            <h1 className="text-2xl font-bold text-gray-900">Team Settings</h1>
            <p className="text-gray-600">{team?.name}</p>
          </div>
        </div>
        
        {/* Member Permissions */}
        <div className="bg-white rounded-lg shadow-sm p-6 mb-6">
          <h2 className="text-lg font-medium text-gray-800 mb-4 flex items-center">
            <Users className="w-5 h-5 mr-2 text-primary-500" />
            Member Permissions
          </h2>
          
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-700">Allow members to invite others</p>
                <p className="text-xs text-gray-500">Members can invite new people to the team</p>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input 
                  type="checkbox"
                  className="sr-only peer"
                  checked={memberPermissions.canInviteMembers}
                  onChange={() => setMemberPermissions({
                    ...memberPermissions,
                    canInviteMembers: !memberPermissions.canInviteMembers
                  })}
                />
                <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-primary-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary-500"></div>
              </label>
            </div>
            
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-700">Allow members to upload files</p>
                <p className="text-xs text-gray-500">Members can upload new files to the team storage</p>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input 
                  type="checkbox"
                  className="sr-only peer"
                  checked={memberPermissions.canUploadFiles}
                  onChange={() => setMemberPermissions({
                    ...memberPermissions,
                    canUploadFiles: !memberPermissions.canUploadFiles
                  })}
                />
                <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-primary-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary-500"></div>
              </label>
            </div>
            
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-700">Allow members to delete files</p>
                <p className="text-xs text-gray-500">Members can delete team files</p>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input 
                  type="checkbox"
                  className="sr-only peer"
                  checked={memberPermissions.canDeleteFiles}
                  onChange={() => setMemberPermissions({
                    ...memberPermissions,
                    canDeleteFiles: !memberPermissions.canDeleteFiles
                  })}
                />
                <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-primary-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary-500"></div>
              </label>
            </div>
          </div>
        </div>
        
        {/* Security Settings */}
        <div className="bg-white rounded-lg shadow-sm p-6 mb-6">
          <h2 className="text-lg font-medium text-gray-800 mb-4 flex items-center">
            <Lock className="w-5 h-5 mr-2 text-primary-500" />
            Security Settings
          </h2>
          
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-700">Enforce file encryption</p>
                <p className="text-xs text-gray-500">All team files will be encrypted</p>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input 
                  type="checkbox"
                  className="sr-only peer"
                  checked={securitySettings.enforceFileEncryption}
                  onChange={() => setSecuritySettings({
                    ...securitySettings,
                    enforceFileEncryption: !securitySettings.enforceFileEncryption
                  })}
                />
                <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-primary-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary-500"></div>
              </label>
            </div>
            
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-700">Require 2FA for sensitive operations</p>
                <p className="text-xs text-gray-500">Team members need 2FA for deleting files or changing settings</p>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input 
                  type="checkbox"
                  className="sr-only peer"
                  checked={securitySettings.require2FAForSensitiveOperations}
                  onChange={() => setSecuritySettings({
                    ...securitySettings,
                    require2FAForSensitiveOperations: !securitySettings.require2FAForSensitiveOperations
                  })}
                />
                <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-primary-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary-500"></div>
              </label>
            </div>
          </div>
        </div>
        
        {/* Danger Zone */}
        <div className="bg-white rounded-lg shadow-sm p-6 border border-red-100">
          <h2 className="text-lg font-medium text-red-600 mb-4">Danger Zone</h2>
          
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-700">Delete Team</p>
                <p className="text-xs text-gray-500">This action cannot be undone</p>
              </div>
              <Button
                variant="danger"
                onClick={() => setShowDeleteConfirm(true)}
              >
                Delete Team
              </Button>
            </div>
          </div>
        </div>
        
        {/* Save Button */}
        <div className="mt-6 flex justify-end">
          <Button
            variant="primary"
            icon={<Save className="w-4 h-4" />}
            onClick={saveSettings}
            isLoading={isUpdating}
          >
            Save Settings
          </Button>
        </div>
        
        {/* Delete Confirmation Modal */}
        {showDeleteConfirm && (
          <ConfirmationModal
            title="Delete Team"
            message={`Are you sure you want to delete ${team?.name}? This action cannot be undone and all team data will be lost.`}
            confirmLabel="Delete"
            confirmVariant="danger"
            onConfirm={handleDeleteTeam}
            onCancel={() => setShowDeleteConfirm(false)}
          />
        )}

        {/* Two-Factor Verification Modal */}
        {showTwoFactorModal && (
          <TwoFactorVerifyModal
            onClose={() => setShowTwoFactorModal(false)}
            onVerify={handleTwoFactorVerified}
          />
        )}
      </div>
    </Layout>
  );
}