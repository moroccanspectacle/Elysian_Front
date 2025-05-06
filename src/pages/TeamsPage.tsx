import React, { useState, useEffect } from 'react';
import { Layout } from '../components/Layout';
import { api } from '../services/api';
import { Users, Plus, Settings, UserPlus, BarChart2 } from 'lucide-react';
import { motion } from 'framer-motion';
import { Button } from '../components/Button';
import { TeamCard } from '../components/TeamCard';
import { CreateTeamModal } from '../components/CreateTeamModal';
import { useNavigate } from 'react-router-dom';

interface Team {
  id: string;
  name: string;
  description: string;
  currentUsage: number;
  storageQuota: number;
  role: 'owner' | 'admin' | 'member';
}

export function TeamsPage() {
  const [teams, setTeams] = useState<Team[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    fetchTeams();
  }, []);

  const fetchTeams = async () => {
    try {
      setIsLoading(true);
      const response = await api.teams.list();
      
      // If we get an error object instead of an array
      if (response && response.error) {
        console.error('API error:', response.error);
        setTeams([]);
        setError(response.error || 'Failed to load teams');
      }
      // Ensure we always have an array
      else if (Array.isArray(response)) {
        setTeams(response);
      } else {
        console.error('Expected array but got:', response);
        setTeams([]);
        setError('Invalid response format from server');
      }
      
      setIsLoading(false);
    } catch (err) {
      console.error('Failed to fetch teams:', err);
      setError('Failed to load teams');
      setIsLoading(false);
      // Make sure teams is an empty array when there's an error
      setTeams([]);
    }
  };

  useEffect(() => {
    console.log('Current teams:', teams);
  }, [teams]);

  return (
    <Layout>
      <div className="max-w-7xl mx-auto">
        <div className="flex justify-between items-center mb-8">
          <motion.h1
            className="text-3xl font-display font-semibold text-gray-900"
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
          >
            My Teams
          </motion.h1>
          <Button 
            variant="primary"
            icon={<Plus className="w-4 h-4" />}
            onClick={() => setShowCreateModal(true)}
          >
            Create Team
          </Button>
        </div>

        {isLoading ? (
          <div className="flex justify-center my-12">
            <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-primary-500"></div>
          </div>
        ) : error ? (
          <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg">
            {error}
          </div>
        ) : teams.length === 0 ? (
          <div className="text-center py-16 bg-white rounded-lg shadow-sm">
            <Users className="w-16 h-16 text-neutral-300 mx-auto mb-4" />
            <h2 className="text-xl font-medium text-gray-700 mb-2">No teams yet</h2>
            <p className="text-neutral-500 mb-6 max-w-md mx-auto">
              Create your first team to collaborate securely with colleagues and manage shared storage.
            </p>
            <Button 
              variant="primary"
              onClick={() => setShowCreateModal(true)}
            >
              Create Your First Team
            </Button>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {teams.map(team => (
              <TeamCard
                key={team.id}
                team={team}
                onView={() => navigate(`/teams/${team.id}`)}
              />
            ))}
          </div>
        )}
      </div>

      {showCreateModal && (
        <CreateTeamModal 
          onClose={() => setShowCreateModal(false)}
          onTeamCreated={(newTeam) => {
            // Option 1: Add the team to the existing array
            setTeams([...teams, newTeam]);
            
            // Option 2: Or refresh the entire list to be sure
            // fetchTeams(); 
            
            setShowCreateModal(false);
          }}
        />
      )}
    </Layout>
  );
}