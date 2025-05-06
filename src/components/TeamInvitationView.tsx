import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Users, Check, X, AlertCircle } from 'lucide-react';
import { Button } from './Button';
import { api } from '../services/api';

interface TeamInvitationViewProps {
  teamId: string;
  teamName: string;
  teamDescription?: string;
  invitationId: string;
  role: string;
}

export function TeamInvitationView({ 
  teamId, 
  teamName, 
  teamDescription,
  invitationId, 
  role 
}: TeamInvitationViewProps) {
  const navigate = useNavigate();
  const [isAccepting, setIsAccepting] = useState(false);
  const [isDeclining, setIsDeclining] = useState(false);
  const [error, setError] = useState<string | null>(null);
  
  const handleAccept = async () => {
    try {
      setIsAccepting(true);
      await api.notifications.acceptInvitation(invitationId);
      // Reload the page to show the team details
      navigate(`/teams/${teamId}`);
    } catch (err) {
      console.error('Failed to accept invitation:', err);
      setError('Failed to accept the invitation. Please try again.');
      setIsAccepting(false);
    }
  };
  
  const handleDecline = async () => {
    try {
      setIsDeclining(true);
      await api.notifications.declineInvitation(invitationId);
      // Go back to teams list
      navigate('/teams');
    } catch (err) {
      console.error('Failed to decline invitation:', err);
      setError('Failed to decline the invitation. Please try again.');
      setIsDeclining(false);
    }
  };
  
  return (
    <div className="bg-white rounded-lg shadow-md p-8 max-w-2xl mx-auto">
      {error && (
        <div className="mb-6 bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg flex items-center">
          <AlertCircle className="w-5 h-5 mr-2" />
          {error}
        </div>
      )}
      
      <motion.div 
        className="text-center mb-8"
        initial={{ opacity: 0, y: -10 }}
        animate={{ opacity: 1, y: 0 }}
      >
        <div className="w-20 h-20 bg-primary-100 rounded-full flex items-center justify-center mx-auto mb-4">
          <Users className="w-10 h-10 text-primary-600" />
        </div>
        <h2 className="text-2xl font-bold text-gray-800 mb-2">{teamName}</h2>
        <p className="text-gray-600 mb-2">You've been invited to join this team as a <span className="font-medium">{role}</span></p>
        {teamDescription && (
          <p className="text-gray-500 mt-4">{teamDescription}</p>
        )}
      </motion.div>
      
      <div className="flex flex-col sm:flex-row justify-center gap-4">
        <Button
          variant="outline"
          onClick={handleDecline}
          disabled={isAccepting || isDeclining}
          icon={<X className="w-4 h-4 mr-2" />}
        >
          {isDeclining ? 'Declining...' : 'Decline'}
        </Button>
        <Button
          variant="primary"
          onClick={handleAccept}
          disabled={isAccepting || isDeclining}
          icon={<Check className="w-4 h-4 mr-2" />}
          
        >
          {isAccepting ? 'Accepting...' : 'Accept Invitation'}
        </Button>
      </div>
    </div>
  );
}