import React, { useState, useEffect } from 'react';
import { Bell, Check, X } from 'lucide-react';
import { api } from '../services/api';
import { useNavigate } from 'react-router-dom';
import { format } from 'date-fns';

interface TeamInvitation {
  id: string;
  teamId: string;
  teamName: string;
  teamDescription: string;
  teamAvatar?: string;
  role: string;
  invitedAt: string;
}

export function NotificationDropdown() {
  const [invitations, setInvitations] = useState<TeamInvitation[]>([]);
  const [isOpen, setIsOpen] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const navigate = useNavigate();
  
  useEffect(() => {
    if (isOpen) {
      fetchInvitations();
    }
  }, [isOpen]);
  
  const fetchInvitations = async () => {
    try {
      setIsLoading(true);
      const response = await api.notifications.getInvitations();
      setInvitations(response);
    } catch (error) {
      console.error('Failed to fetch invitations:', error);
    } finally {
      setIsLoading(false);
    }
  };
  
  const handleAccept = async (invitationId: string, teamId: string) => {
    try {
      await api.notifications.acceptInvitation(invitationId);
      // Remove from the list
      setInvitations(invitations.filter(inv => inv.id !== invitationId));
      // Redirect to the team
      navigate(`/teams/${teamId}`);
    } catch (error) {
      console.error('Failed to accept invitation:', error);
    }
  };
  
  const handleDecline = async (invitationId: string) => {
    try {
      await api.notifications.declineInvitation(invitationId);
      // Remove from the list
      setInvitations(invitations.filter(inv => inv.id !== invitationId));
    } catch (error) {
      console.error('Failed to decline invitation:', error);
    }
  };
  
  return (
    <div className="relative">
      <button 
        className="relative flex items-center justify-center w-10 h-10 rounded-full text-gray-500 hover:bg-gray-100"
        onClick={() => setIsOpen(!isOpen)}
      >
        <Bell className="w-5 h-5" />
        {invitations.length > 0 && (
          <span className="absolute top-1 right-1 h-4 w-4 rounded-full bg-red-500 text-white text-xs flex items-center justify-center">
            {invitations.length}
          </span>
        )}
      </button>
      
      {isOpen && (
        <div className="absolute right-0 mt-2 w-80 bg-white rounded-md shadow-lg z-10">
          <div className="p-3 border-b border-gray-100">
            <h3 className="text-md font-medium text-gray-900">Notifications</h3>
          </div>
          
          <div className="max-h-96 overflow-y-auto">
            {isLoading ? (
              <div className="p-4 text-center text-gray-500">
                Loading...
              </div>
            ) : invitations.length === 0 ? (
              <div className="p-4 text-center text-gray-500">
                No new notifications
              </div>
            ) : (
              invitations.map(invitation => (
                <div key={invitation.id} className="p-3 border-b border-gray-100">
                  <div className="flex mb-2">
                    <div className="mr-3">
                      <div className="w-10 h-10 rounded-md bg-primary-100 flex items-center justify-center text-primary-600">
                        {invitation.teamAvatar ? (
                          <img src={invitation.teamAvatar} alt="" className="w-10 h-10 rounded-md" />
                        ) : (
                          invitation.teamName.charAt(0).toUpperCase()
                        )}
                      </div>
                    </div>
                    <div>
                      <p className="text-sm font-medium text-gray-900 mb-1">
                        Team Invitation: {invitation.teamName}
                      </p>
                      <p className="text-xs text-gray-500 mb-1">
                        You've been invited as {invitation.role}
                      </p>
                      <p className="text-xs text-gray-400">
                        {format(new Date(invitation.invitedAt), 'MMM d, yyyy')}
                      </p>
                    </div>
                  </div>
                  <div className="flex space-x-2">
                    <button 
                      className="flex-1 py-1 bg-primary-500 hover:bg-primary-600 text-white text-xs font-medium rounded-md flex items-center justify-center"
                      onClick={() => handleAccept(invitation.id, invitation.teamId)}
                    >
                      <Check className="w-3 h-3 mr-1" />
                      Accept
                    </button>
                    <button 
                      className="flex-1 py-1 bg-gray-100 hover:bg-gray-200 text-gray-700 text-xs font-medium rounded-md flex items-center justify-center"
                      onClick={() => handleDecline(invitation.id)}
                    >
                      <X className="w-3 h-3 mr-1" />
                      Decline
                    </button>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  );
}