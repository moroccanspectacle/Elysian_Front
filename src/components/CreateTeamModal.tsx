import React, { useState } from 'react';
import { api } from '../services/api';
import { X, Save } from 'lucide-react';
import { Button } from './Button';

interface CreateTeamModalProps {
  onClose: () => void;
  onTeamCreated: (team: any) => void;
}

export function CreateTeamModal({ onClose, onTeamCreated }: CreateTeamModalProps) {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [errors, setErrors] = useState<{ [key: string]: string }>({});
  
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    // Validate inputs
    const newErrors: { [key: string]: string } = {};
    if (!name.trim()) {
      newErrors.name = 'Team name is required';
    }
    
    if (Object.keys(newErrors).length > 0) {
      setErrors(newErrors);
      return;
    }
    
    setIsLoading(true);
    
    try {
      const newTeam = await api.teams.create({
        name,
        description: description.trim() || undefined,
      });
      
      console.log("Team created response:", newTeam);
      
      // Make sure the newTeam has all required fields for the UI
      // The backend response will include the default quota
      const formattedTeam = {
        id: newTeam.id,
        name: newTeam.name,
        description: newTeam.description || "",
        currentUsage: newTeam.currentUsage || 0,
        storageQuota: newTeam.storageQuota, // Use quota from backend response
        role: newTeam.role || "owner" // Assuming creator is owner
      };
      
      onTeamCreated(formattedTeam);
    } catch (error) {
      console.error('Failed to create team:', error);
      setErrors({ form: 'Failed to create team. Please try again.' });
    } finally {
      setIsLoading(false);
    }
  };
  
  return (
    <div className="fixed inset-0 flex items-center justify-center z-50 bg-black bg-opacity-50">
      <div className="bg-white rounded-lg shadow-lg w-full max-w-md">
        <div className="flex justify-between items-center p-4 border-b">
          <h2 className="text-xl font-semibold text-gray-800">Create New Team</h2>
          <button className="text-gray-500 hover:text-gray-700" onClick={onClose}>
            <X className="w-5 h-5" />
          </button>
        </div>
        
        <form onSubmit={handleSubmit} className="p-4">
          {errors.form && (
            <div className="mb-4 p-3 bg-red-50 text-red-700 rounded-md">
              {errors.form}
            </div>
          )}
          
          <div className="mb-4">
            <label className="block text-gray-700 text-sm font-medium mb-2">
              Team Name*
            </label>
            <input
              type="text"
              className={`w-full px-3 py-2 border rounded-md ${errors.name ? 'border-red-500' : 'border-gray-300'} focus:outline-none focus:ring-2 focus:ring-primary-500`}
              placeholder="Enter team name"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
            {errors.name && (
              <p className="mt-1 text-sm text-red-600">{errors.name}</p>
            )}
          </div>
          
          <div className="mb-4">
            <label className="block text-gray-700 text-sm font-medium mb-2">
              Description
            </label>
            <textarea
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-primary-500"
              rows={3}
              placeholder="Optional team description"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
            ></textarea>
          </div>
          
          <div className="mt-6 flex justify-end space-x-3">
            <Button type="button" variant="outline" onClick={onClose}>
              Cancel
            </Button>
            <Button 
              type="submit" 
              variant="primary" 
              icon={<Save className="w-4 h-4" />}
              isLoading={isLoading}
            >
              Create Team
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
}