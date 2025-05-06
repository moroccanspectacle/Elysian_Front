import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { Layout } from '../components/Layout';
import { api } from '../services/api';
import { motion } from 'framer-motion';
import { 
  Users, FileText, Settings, HardDrive, Edit2, 
  Mail, Trash2, Shield, UserPlus, ChevronRight
} from 'lucide-react';
import { Button } from '../components/Button';
import { EditTeamModal } from '../components/EditTeamModal';
import { InviteMembersModal } from '../components/InviteMembersModal';
import { TeamInvitationView } from '../components/TeamInvitationView';

interface TeamDetails {
  id: string;
  name: string;
  description: string;
  currentUsage: number;
  storageQuota: number;
  ownerId: number;
  avatar?: string;
  createdAt: string;
  status?: string;
}

interface TeamMember {
  id: string;
  userId: number;
  role: 'owner' | 'admin' | 'member';
  username: string;
  email: string;
  profileImage?: string;
  joinedAt: string;
}

interface TeamInvitation {
  id: string;
  teamId: string;
  role: string;
  status?: string;
}

interface TeamFile {
  id: string;
  originalName: string;
  fileSize: number;
}

export function TeamDetailsPage() {
  const { teamId } = useParams<{ teamId: string }>();
  console.log("[TeamDetailsPage] Extracted teamId from URL:", teamId);

  const navigate = useNavigate();
  const [team, setTeam] = useState<TeamDetails | null>(null);
  const [members, setMembers] = useState<TeamMember[]>([]);
  const [recentFiles, setRecentFiles] = useState<TeamFile[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showEditModal, setShowEditModal] = useState(false);
  const [showInviteModal, setShowInviteModal] = useState(false);
  const [invitation, setInvitation] = useState<{
    id: string;
    role: string;
    status: string;
  } | null>(null);

  useEffect(() => {
    console.log("[TeamDetailsPage] useEffect running with teamId:", teamId);
    if (teamId) {
      fetchTeamData(teamId);
    } else {
      console.error("[TeamDetailsPage] useEffect: teamId is missing, cannot fetch data.");
      setError("Team ID not found in URL.");
      setIsLoading(false);
    }
  }, [teamId]);

  const fetchTeamData = async (id: string) => {
    console.log("[TeamDetailsPage] fetchTeamData called for ID:", id);
    setIsLoading(true);
    setError(null);
    try {
      const teamData = await api.teams.getTeam(id);
      setTeam(teamData);
      
      if (teamData.status === 'invited') {
        const invitations = await api.notifications.getInvitations();
        const matchingInvitation = invitations.find((inv: TeamInvitation) => inv.teamId === id);
        if (matchingInvitation) {
          setInvitation({
            id: matchingInvitation.id,
            role: matchingInvitation.role,
            status: 'invited'
          });
          setIsLoading(false);
          return;
        }
      }
      
      try {
        fetchMembers(id);
        fetchFiles(id);
      } catch (err) {
        console.error('Failed to fetch additional team data:', err);
        setMembers([]);
        setRecentFiles([]);
      }
      
      setIsLoading(false);
    } catch (err) {
      console.error('Failed to fetch team data:', err);
      setError('Failed to load team information');
      setIsLoading(false);
    }
  };

  const fetchMembers = async (id: string) => {
    try {
      const membersData = await api.teams.getMembers(id);
      if (Array.isArray(membersData)) {
        setMembers(membersData);
      } else {
        console.error('Expected array for members but got:', membersData);
        setMembers([]);
      }
    } catch (err) {
      console.error('Failed to fetch members:', err);
      setMembers([]);
    }
  };

  const fetchFiles = async (id: string) => {
    try {
      const filesData = await api.teams.getTeamFiles(id);
      if (Array.isArray(filesData)) {
        setRecentFiles(filesData.slice(0, 5));
      } else {
        console.error('Expected array for files but got:', filesData);
        setRecentFiles([]);
      }
    } catch (err) {
      console.error('Failed to fetch files:', err);
      setRecentFiles([]);
    }
  };

  const handleDelete = async (file: TeamFile) => {
    if (!teamId) return;

    if (confirm(`Are you sure you want to delete ${file.originalName}?`)) {
      try {
        await api.files.delete(file.id);
        fetchFiles(teamId);
        fetchTeamData(teamId);
      } catch (error) {
        console.error('Delete error:', error);
        setError(`Failed to delete file: ${error instanceof Error ? error.message : String(error)}`);
      }
    }
  };

  const formatStorage = (bytes: number) => {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
    return (bytes / (1024 * 1024 * 1024)).toFixed(1) + ' GB';
  };
  
  const usagePercentage = team 
    ? Math.min(Math.round((team.currentUsage / team.storageQuota) * 100), 100)
    : 0;
  
  if (isLoading) {
    return (
      <Layout>
        <div className="flex justify-center my-20">
          <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-primary-500"></div>
        </div>
      </Layout>
    );
  }
  
  if (error || !team) {
    return (
      <Layout>
        <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg">
          {error || "Team not found"}
        </div>
      </Layout>
    );
  }

  if (invitation && team) {
    return (
      <Layout>
        <TeamInvitationView
          teamId={team.id}
          teamName={team.name}
          teamDescription={team.description}
          invitationId={invitation.id}
          role={invitation.role}
        />
      </Layout>
    );
  }
  
  return (
    <Layout>
      <div className="max-w-7xl mx-auto">
        {/* Team Header */}
        <div className="flex justify-between items-start mb-8">
          <motion.div
            className="flex items-center"
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
          >
            <div className="w-16 h-16 rounded-lg bg-primary-100 flex items-center justify-center mr-4 text-primary-600">
              {team.avatar ? (
                <img src={team.avatar} alt={team.name} className="w-16 h-16 rounded-lg object-cover" />
              ) : (
                <Users className="w-8 h-8" />
              )}
            </div>
            <div>
              <h1 className="text-3xl font-display font-semibold text-gray-900">{team.name}</h1>
              <p className="text-gray-500">{team.description}</p>
            </div>
          </motion.div>
          
          <div className="flex space-x-3">
            <Button 
              variant="outline"
              icon={<Edit2 className="w-4 h-4" />}
              onClick={() => setShowEditModal(true)}
            >
              Edit Team
            </Button>
            <Button 
              variant="primary"
              icon={<UserPlus className="w-4 h-4" />}
              onClick={() => setShowInviteModal(true)}
            >
              Invite Members
            </Button>
          </div>
        </div>
        
        {/* Team Dashboard */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
          {/* Team Stats */}
          <div className="bg-white rounded-lg shadow-sm p-6">
            <h2 className="text-lg font-medium mb-4 text-gray-800">Team Statistics</h2>
            
            <div className="space-y-4">
              <div>
                <div className="flex justify-between text-sm mb-1">
                  <span className="text-gray-600">Storage</span>
                  <span className="text-gray-800 font-medium">
                    {formatStorage(team.currentUsage)} / {formatStorage(team.storageQuota)}
                  </span>
                </div>
                <div className="w-full bg-gray-100 rounded-full h-2.5">
                  <div 
                    className={`h-2.5 rounded-full ${
                      usagePercentage > 90 ? 'bg-red-500' : 
                      usagePercentage > 70 ? 'bg-orange-500' : 
                      'bg-primary-500'
                    }`}
                    style={{ width: `${usagePercentage}%` }}
                  ></div>
                </div>
              </div>
              
              <div className="flex justify-between items-center py-2 border-b border-gray-100">
                <div className="flex items-center text-gray-600">
                  <Users className="w-4 h-4 mr-2" />
                  <span>Members</span>
                </div>
                <span className="text-gray-800 font-medium">{members.length}</span>
              </div>
              
              <div className="flex justify-between items-center py-2 border-b border-gray-100">
                <div className="flex items-center text-gray-600">
                  <FileText className="w-4 h-4 mr-2" />
                  <span>Files</span>
                </div>
                <span className="text-gray-800 font-medium">{recentFiles.length}</span>
              </div>
              
              <div className="flex justify-between items-center py-2">
                <div className="flex items-center text-gray-600">
                  <HardDrive className="w-4 h-4 mr-2" />
                  <span>Storage Quota</span>
                </div>
                <span className="text-gray-800 font-medium">{formatStorage(team.storageQuota)}</span>
              </div>
            </div>
          </div>
          
          {/* Recent Team Members */}
          <div className="bg-white rounded-lg shadow-sm p-6">
            <div className="flex justify-between items-center mb-4">
              <h2 className="text-lg font-medium text-gray-800">Recent Members</h2>
              <button 
                className="text-primary-600 hover:text-primary-700 text-sm flex items-center"
                onClick={() => navigate(`/teams/${teamId}/members`)}
              >
                View All <ChevronRight className="w-4 h-4" />
              </button>
            </div>
            
            <div className="space-y-3">
              {Array.isArray(members) && members.length > 0 ? (
                members.slice(0, 5).map(member => (
                  <div key={member.id} className="flex items-center justify-between">
                    <div className="flex items-center">
                      <div className="w-8 h-8 rounded-full bg-gray-100 flex items-center justify-center overflow-hidden mr-3">
                        {member.profileImage ? (
                          <img 
                            src={member.profileImage.startsWith('http') 
                              ? member.profileImage 
                              : `http://localhost:3000${member.profileImage}`} 
                            alt={member.username} 
                            className="w-8 h-8 object-cover" 
                          />
                        ) : (
                          <Users className="w-4 h-4 text-gray-500" />
                        )}
                      </div>
                      <div>
                        <div className="text-sm font-medium text-gray-800">{member.username}</div>
                        <div className="text-xs text-gray-500">{member.email}</div>
                      </div>
                    </div>
                    <span className={`text-xs px-2 py-1 rounded-full ${
                      member.role === 'owner' 
                        ? 'bg-purple-100 text-purple-800' 
                        : member.role === 'admin' 
                          ? 'bg-blue-100 text-blue-800' 
                          : 'bg-gray-100 text-gray-800'
                    }`}>
                      {member.role}
                    </span>
                  </div>
                ))
              ) : (
                <div className="text-center py-4 text-gray-500">
                  No members yet
                </div>
              )}
            </div>
          </div>
          
          {/* Recent Files */}
          <div className="bg-white rounded-lg shadow-sm p-6">
            <div className="flex justify-between items-center mb-4">
              <h2 className="text-lg font-medium text-gray-800">Recent Files</h2>
              <button 
                className="text-primary-600 hover:text-primary-700 text-sm flex items-center"
                onClick={() => navigate(`/teams/${teamId}/files`)}
              >
                View All <ChevronRight className="w-4 h-4" />
              </button>
            </div>
            
            <div className="space-y-3">
              {Array.isArray(recentFiles) && recentFiles.length > 0 ? (
                recentFiles.map(file => (
                  <div key={file.id} className="flex items-center justify-between">
                    <div className="flex items-center">
                      <div className="w-8 h-8 rounded bg-gray-100 flex items-center justify-center mr-3">
                        <FileText className="w-4 h-4 text-gray-500" />
                      </div>
                      <div>
                        <div className="text-sm font-medium text-gray-800 truncate max-w-[150px]">{file.originalName}</div>
                        <div className="text-xs text-gray-500">{formatStorage(file.fileSize)}</div>
                      </div>
                    </div>
                    <button 
                      className="text-gray-500 hover:text-primary-600"
                      onClick={() => handleDelete(file)}
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                ))
              ) : (
                <div className="text-center py-4 text-gray-500">
                  No files yet
                </div>
              )}
            </div>
          </div>
        </div>
        
        {/* Quick Actions */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
          <button 
            className="bg-white rounded-lg shadow-sm p-6 text-left hover:shadow-md transition-shadow"
            onClick={() => navigate(`/teams/${teamId}/files`)}
          >
            <div className="flex items-center mb-2">
              <div className="w-10 h-10 rounded-lg bg-blue-50 flex items-center justify-center mr-3">
                <FileText className="w-5 h-5 text-blue-600" />
              </div>
              <h3 className="text-gray-800 font-medium">Files</h3>
            </div>
            <p className="text-sm text-gray-500">View and manage team files</p>
          </button>
          
          <button 
            className="bg-white rounded-lg shadow-sm p-6 text-left hover:shadow-md transition-shadow"
            onClick={() => navigate(`/teams/${teamId}/members`)}
          >
            <div className="flex items-center mb-2">
              <div className="w-10 h-10 rounded-lg bg-green-50 flex items-center justify-center mr-3">
                <Users className="w-5 h-5 text-green-600" />
              </div>
              <h3 className="text-gray-800 font-medium">Members</h3>
            </div>
            <p className="text-sm text-gray-500">Manage team members and roles</p>
          </button>
          
          <button 
            className="bg-white rounded-lg shadow-sm p-6 text-left hover:shadow-md transition-shadow"
            onClick={() => setShowInviteModal(true)}
          >
            <div className="flex items-center mb-2">
              <div className="w-10 h-10 rounded-lg bg-purple-50 flex items-center justify-center mr-3">
                <Mail className="w-5 h-5 text-purple-600" />
              </div>
              <h3 className="text-gray-800 font-medium">Invite</h3>
            </div>
            <p className="text-sm text-gray-500">Invite new members to join team</p>
          </button>
          
          <button 
            className="bg-white rounded-lg shadow-sm p-6 text-left hover:shadow-md transition-shadow"
            onClick={() => navigate(`/teams/${teamId}/settings`)}
          >
            <div className="flex items-center mb-2">
              <div className="w-10 h-10 rounded-lg bg-gray-50 flex items-center justify-center mr-3">
                <Settings className="w-5 h-5 text-gray-600" />
              </div>
              <h3 className="text-gray-800 font-medium">Settings</h3>
            </div>
            <p className="text-sm text-gray-500">Configure team settings</p>
          </button>
        </div>
      </div>
      
      {/* Edit Team Modal */}
      {showEditModal && (
        <EditTeamModal 
          team={team}
          onClose={() => setShowEditModal(false)}
          onSave={(updatedTeam) => {
            setTeam(updatedTeam);
            setShowEditModal(false);
          }}
        />
      )}
      
      {/* Invite Members Modal */}
      {showInviteModal && (
        <InviteMembersModal 
          teamId={team.id}
          onClose={() => setShowInviteModal(false)}
          onInvite={(newMembers) => {
            setMembers([...members, ...newMembers]);
            setShowInviteModal(false);
          }}
        />
      )}
    </Layout>
  );
}