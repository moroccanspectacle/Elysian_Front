import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { Layout } from '../components/Layout';
import { api } from '../services/api';
import { motion } from 'framer-motion';
import { 
  Users, ChevronLeft, UserPlus, Search, Shield, Settings, 
  MoreVertical, Trash2, Edit, Send, User, Mail
} from 'lucide-react';
import { Button } from '../components/Button';
import { InviteMembersModal } from '../components/InviteMembersModal';
import { ConfirmationModal } from '../components/ConfirmationModal';
import { useAuth } from '../components/AuthContext';
import { format } from 'date-fns';

interface TeamMember {
  id: string;
  userId: number;
  role: 'owner' | 'admin' | 'member';
  username: string;
  email: string;
  profileImage?: string;
  joinedAt: string;
  status: 'invited' | 'active' | 'suspended';
}

interface Team {
  id: string;
  name: string;
  ownerId: number;
  role?: 'owner' | 'admin' | 'member'; // Add this property
}

export function TeamMembersPage() {
  const { teamId } = useParams<{ teamId: string }>();
  const navigate = useNavigate();
  const { user } = useAuth();
  const [team, setTeam] = useState<Team | null>(null);
  const [members, setMembers] = useState<TeamMember[]>([]);
  const [filteredMembers, setFilteredMembers] = useState<TeamMember[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [showInviteModal, setShowInviteModal] = useState(false);
  const [showConfirmRemove, setShowConfirmRemove] = useState(false);
  const [selectedMember, setSelectedMember] = useState<TeamMember | null>(null);
  const [showMemberMenu, setShowMemberMenu] = useState<string | null>(null);

  const [teamSettings, setTeamSettings] = useState<any>(null);
  const [canInviteMembers, setCanInviteMembers] = useState(false);
  
  // Check if current user is owner or admin
  const isOwnerOrAdmin = () => {
    if (!user || !team) return false;
    
    const currentUserMember = members.find(m => m.userId === user.id);
    return currentUserMember && (currentUserMember.role === 'owner' || currentUserMember.role === 'admin');
  };
  
  useEffect(() => {
    if (teamId) {
      // Fetch basic team details first to check status
      const checkTeamStatusAndLoad = async () => {
        setIsLoading(true);
        setError(null);
        try {
          const teamData = await api.teams.getTeam(teamId);
          setTeam(teamData); // Store basic team data

          // If user is invited, redirect back to team details page
          if (teamData.status === 'invited') {
            console.log('[TeamMembersPage] User is invited, redirecting back to team details.');
            navigate(`/teams/${teamId}`);
            // No need to setIsLoading(false) here as navigation will unmount
            return; // Stop further execution
          }

          // If active, proceed to load members and settings
          await fetchMembers(teamId);
          await fetchTeamSettings(); // Keep fetching settings if needed for permissions

        } catch (err: any) {
          console.error('Failed to fetch initial team data:', err);
          setError(err.message || 'Failed to load team information');
        } finally {
          // Only set loading false if we didn't redirect
          // Check if component is still mounted might be safer, but this works if redirect happens
          if (window.location.pathname.includes(`/teams/${teamId}/members`)) {
             setIsLoading(false);
          }
        }
      };
      checkTeamStatusAndLoad();
    } else {
      setError("Team ID not found.");
      setIsLoading(false);
    }
  }, [teamId, navigate]); // Add navigate to dependencies

  // Separate function to fetch members, called only if status is active
  const fetchMembers = async (id: string) => {
    try {
      const membersData = await api.teams.getMembers(id);
      setMembers(membersData);
      setFilteredMembers(membersData);
    } catch (err) {
       console.error('Failed to fetch team members:', err);
       setError(prev => prev ? `${prev}\nFailed to load members.` : 'Failed to load members.');
    }
  };

  // Keep fetchTeamSettings as it was, called only if status is active
  const fetchTeamSettings = async () => {
    try {
      const settings = await api.teams.getSettings(teamId!);
      setTeamSettings(settings);
      
      // Fix: Add proper parentheses and null checks
      if (team && (team.role === 'owner' || team.role === 'admin')) {
        setCanInviteMembers(true);
      } else if (settings && settings.memberPermissions) {
        setCanInviteMembers(settings.memberPermissions.canInviteMembers);
      }
    } catch (err) {
      console.error('Failed to fetch team settings:', err);
    }
  };
  
  const handleRemoveMember = async () => {
    if (!selectedMember || !teamId) return;
    
    try {
      await api.teams.removeMember(teamId, selectedMember.id);
      
      // Update the members list
      const updatedMembers = members.filter(m => m.id !== selectedMember.id);
      setMembers(updatedMembers);
      setFilteredMembers(
        searchQuery.trim() === '' 
          ? updatedMembers 
          : updatedMembers.filter(m => 
              m.username.toLowerCase().includes(searchQuery.toLowerCase()) || 
              m.email.toLowerCase().includes(searchQuery.toLowerCase())
            )
      );
      
      setShowConfirmRemove(false);
      setSelectedMember(null);
    } catch (err) {
      console.error('Failed to remove member:', err);
      // Show error message
    }
  };
  
  const handleChangeRole = async (memberId: string, newRole: 'owner' | 'admin' | 'member') => {
    if (!teamId) return;
    
    try {
      await api.teams.updateMemberRole(teamId, memberId, newRole);
      
      // Update the members list
      const updatedMembers = members.map(m => {
        if (m.id === memberId) {
          return { ...m, role: newRole };
        }
        return m;
      });
      
      setMembers(updatedMembers);
      setFilteredMembers(
        searchQuery.trim() === '' 
          ? updatedMembers 
          : updatedMembers.filter(m => 
              m.username.toLowerCase().includes(searchQuery.toLowerCase()) || 
              m.email.toLowerCase().includes(searchQuery.toLowerCase())
            )
      );
      
      setShowMemberMenu(null);
    } catch (err) {
      console.error('Failed to update member role:', err);
      // Show error message
    }
  };
  
  const handleResendInvite = async (memberId: string) => {
    if (!teamId) return;
    
    try {
      await api.teams.resendInvite(teamId, memberId);
      // Show success message
      setShowMemberMenu(null);
    } catch (err) {
      console.error('Failed to resend invite:', err);
      // Show error message
    }
  };
  
  // Modify the loading check to handle the case where team is fetched but status is invited
  if (isLoading) {
    return (
      <Layout>
        <div className="flex justify-center my-20">
          <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-primary-500"></div>
        </div>
      </Layout>
    );
  }

  // Error handling remains similar, but might show briefly before redirect
  if (error && !isLoading) { // Check isLoading to avoid showing error during redirect
    return (
      <Layout>
        <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg">
          {error}
        </div>
      </Layout>
    );
  }

  // Ensure team exists before rendering main content
  if (!team) {
      // Render null or a minimal layout while redirecting or if team is null
      return null;
  }

  const getRoleColor = (role: string) => {
    switch (role) {
      case 'owner': return 'bg-purple-100 text-purple-800';
      case 'admin': return 'bg-blue-100 text-blue-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };
  
  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active': return 'bg-green-100 text-green-800';
      case 'invited': return 'bg-yellow-100 text-yellow-800';
      default: return 'bg-red-100 text-red-800';
    }
  };
  
  return (
    <Layout>
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="flex justify-between items-center mb-8">
          <div className="flex items-center">
            <button 
              className="mr-4 p-2 rounded-full hover:bg-gray-100"
              onClick={() => navigate(`/teams/${teamId}`)}
            >
              <ChevronLeft className="w-5 h-5 text-gray-600" />
            </button>
            <motion.div
              initial={{ opacity: 0, y: -10 }}
              animate={{ opacity: 1, y: 0 }}
            >
              <h1 className="text-3xl font-display font-semibold text-gray-900">
                {team.name} - Members
              </h1>
              <p className="text-gray-500">Manage team members and permissions</p>
            </motion.div>
          </div>
          
          {canInviteMembers && (
            <Button 
              variant="primary"
              icon={<UserPlus className="w-4 h-4" />}
              onClick={() => setShowInviteModal(true)}
            >
              Invite Members
            </Button>
          )}
        </div>
        
        {/* Search and Filters */}
        <div className="bg-white rounded-lg shadow-sm p-4 mb-6">
          <div className="flex flex-col md:flex-row md:items-center md:justify-between space-y-4 md:space-y-0">
            <div className="relative w-full md:w-80">
              <input
                type="text"
                placeholder="Search members..."
                className="pl-10 pr-4 py-2 w-full rounded-lg border border-gray-200 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-transparent"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-4 h-4" />
            </div>
            
            <div className="text-sm text-gray-600">
              {filteredMembers.length} {filteredMembers.length === 1 ? 'member' : 'members'}
            </div>
          </div>
        </div>
        
        {/* Members List */}
        <div className="bg-white rounded-lg shadow-sm overflow-hidden mb-6">
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Member
                  </th>
                  <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Role
                  </th>
                  <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Status
                  </th>
                  <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Joined
                  </th>
                  <th scope="col" className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {filteredMembers.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="px-6 py-10 text-center text-gray-500">
                      No members found
                    </td>
                  </tr>
                ) : (
                  filteredMembers.map((member) => (
                    <tr key={member.id} className="hover:bg-gray-50">
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="flex items-center">
                          <div className="h-10 w-10 flex-shrink-0">
                            <div className="h-10 w-10 rounded-full bg-gray-100 flex items-center justify-center overflow-hidden">
                              {member.profileImage ? (
                                <img 
                                  src={member.profileImage.startsWith('http') 
                                    ? member.profileImage 
                                    : `http://localhost:3000${member.profileImage}`}
                                  alt={member.username} 
                                  className="h-10 w-10 object-cover"
                                />
                              ) : (
                                <User className="h-5 w-5 text-gray-500" />
                              )}
                            </div>
                          </div>
                          <div className="ml-4">
                            <div className="text-sm font-medium text-gray-900">{member.username}</div>
                            <div className="text-sm text-gray-500">{member.email}</div>
                          </div>
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getRoleColor(member.role)}`}>
                          {member.role === 'owner' && <Shield className="w-3 h-3 mr-1" />}
                          {member.role}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusColor(member.status)}`}>
                          {member.status}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                        {format(new Date(member.joinedAt), 'MMM d, yyyy')}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                        <div className="relative">
                          {/* Only allow actions if current user is owner/admin and not acting on themselves if they're the owner */}
                          {isOwnerOrAdmin() && (!user || member.userId !== user.id || team.ownerId !== user.id) && (
                            <>
                              <button 
                                className="text-gray-500 hover:text-gray-700 focus:outline-none"
                                onClick={() => setShowMemberMenu(showMemberMenu === member.id ? null : member.id)}
                              >
                                <MoreVertical className="w-5 h-5" />
                              </button>
                              
                              {showMemberMenu === member.id && (
                                <div 
                                  className="absolute right-0 mt-2 w-48 rounded-md shadow-lg bg-white ring-1 ring-black ring-opacity-5 z-10"
                                  onBlur={() => setShowMemberMenu(null)}
                                >
                                  <div className="py-1" role="menu" aria-orientation="vertical">
                                    {member.status === 'invited' && (
                                      <button
                                        className="flex items-center w-full text-left px-4 py-2 text-sm text-gray-700 hover:bg-gray-100"
                                        onClick={() => handleResendInvite(member.id)}
                                      >
                                        <Send className="w-4 h-4 mr-2" />
                                        Resend Invite
                                      </button>
                                    )}
                                    
                                    {/* Role change options */}
                                    {team.ownerId === user?.id && member.role !== 'owner' && (
                                      <button
                                        className="flex items-center w-full text-left px-4 py-2 text-sm text-gray-700 hover:bg-gray-100"
                                        onClick={() => handleChangeRole(member.id, 'admin')}
                                      >
                                        <Shield className="w-4 h-4 mr-2" />
                                        Make Admin
                                      </button>
                                    )}
                                    
                                    {team.ownerId === user?.id && member.role === 'admin' && (
                                      <button
                                        className="flex items-center w-full text-left px-4 py-2 text-sm text-gray-700 hover:bg-gray-100"
                                        onClick={() => handleChangeRole(member.id, 'member')}
                                      >
                                        <User className="w-4 h-4 mr-2" />
                                        Change to Member
                                      </button>
                                    )}
                                    
                                    {/* Remove member option */}
                                    <button
                                      className="flex items-center w-full text-left px-4 py-2 text-sm text-red-600 hover:bg-red-50"
                                      onClick={() => {
                                        setSelectedMember(member);
                                        setShowConfirmRemove(true);
                                        setShowMemberMenu(null);
                                      }}
                                    >
                                      <Trash2 className="w-4 h-4 mr-2" />
                                      Remove
                                    </button>
                                  </div>
                                </div>
                              )}
                            </>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
        
        {/* Modals */}
        {showInviteModal && (
          <InviteMembersModal 
            teamId={team.id}
            onClose={() => setShowInviteModal(false)}
            onInvite={(newMembers) => {
              // Update members list with newly invited members
              setMembers([...members, ...newMembers]);
              setShowInviteModal(false);
            }}
          />
        )}
        
        {showConfirmRemove && selectedMember && (
          <ConfirmationModal
            title="Remove Member"
            message={`Are you sure you want to remove ${selectedMember.username} from this team?`}
            confirmLabel="Remove"
            confirmVariant="danger"
            onConfirm={handleRemoveMember}
            onCancel={() => {
              setShowConfirmRemove(false);
              setSelectedMember(null);
            }}
          />
        )}
      </div>
    </Layout>
  );
}