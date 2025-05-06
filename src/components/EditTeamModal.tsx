import React, { useState } from 'react';
import { api } from '../services/api';
import { X, Save, Image } from 'lucide-react';
import { Button } from './Button';

interface EditTeamModalProps {
  team: {
    id: string;
    name: string;
    description: string;
    storageQuota: number;
    avatar?: string;
  };
  onClose: () => void;
  onSave: (updatedTeam: any) => void;
}

export function EditTeamModal({ team, onClose, onSave }: EditTeamModalProps) {
  const [name, setName] = useState(team.name);
  const [description, setDescription] = useState(team.description || '');
  const [storageQuota, setStorageQuota] = useState(Math.floor(team.storageQuota / (1024 * 1024 * 1024))); // Convert to GB
  const [avatar, setAvatar] = useState<File | null>(null);
  const [avatarPreview, setAvatarPreview] = useState<string | null>(team.avatar || null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errors, setErrors] = useState<{ [key: string]: string }>({});
  
  const handleNameChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setName(e.target.value);
    if (errors.name) {
      setErrors({ ...errors, name: '' });
    }
  };
  
  const handleDescriptionChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    setDescription(e.target.value);
    if (errors.description) {
      setErrors({ ...errors, description: '' });
    }
  };
  
  const handleStorageQuotaChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = parseInt(e.target.value);
    setStorageQuota(isNaN(value) ? 0 : value);
    if (errors.storageQuota) {
      setErrors({ ...errors, storageQuota: '' });
    }
  };
  
  const handleAvatarChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      setAvatar(file);
      
      const reader = new FileReader();
      reader.onload = () => {
        setAvatarPreview(reader.result as string);
      };
      reader.readAsDataURL(file);
    }
  };
  
  const validate = () => {
    const newErrors: { [key: string]: string } = {};
    
    if (!name.trim()) {
      newErrors.name = 'Team name is required';
    }
    
    if (storageQuota < 1) {
      newErrors.storageQuota = 'Storage quota must be at least 1 GB';
    }
    
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };
  
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!validate()) {
      return;
    }
    
    setIsSubmitting(true);
    
    try {
      // Convert GB to bytes for API
      const quotaInBytes = storageQuota * 1024 * 1024 * 1024;
      
      let updatedTeam;
      
      // First, update team details
      updatedTeam = await api.teams.update(team.id, {
        name,
        description,
        storageQuota: quotaInBytes
      });
      
      // If avatar is updated, send separately
      if (avatar) {
        const formData = new FormData();
        formData.append('avatar', avatar);
        
        updatedTeam = await api.teams.updateAvatar(team.id, formData);
      }
      
      onSave(updatedTeam);
    } catch (error) {
      console.error('Failed to update team:', error);
      setErrors({ form: 'Failed to update team. Please try again.' });
    } finally {
      setIsSubmitting(false);
    }
  };
  
  return (
    <div className="fixed inset-0 flex items-center justify-center z-50 bg-black bg-opacity-50">
      <div className="bg-white rounded-lg shadow-lg w-full max-w-md">
        <div className="flex justify-between items-center p-4 border-b">
          <h2 className="text-xl font-semibold text-gray-800">Edit Team</h2>
          <button 
            className="text-gray-500 hover:text-gray-700" 
            onClick={onClose}
          >
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
              Team Avatar
            </label>
            <div className="flex items-center space-x-4">
              <div className="w-16 h-16 rounded-lg bg-gray-100 flex items-center justify-center overflow-hidden">
                {avatarPreview ? (
                  <img 
                    src={avatarPreview} 
                    alt="Team avatar" 
                    className="h-16 w-16 object-cover"
                  />
                ) : (
                  <Image className="h-8 w-8 text-gray-400" />
                )}
              </div>
              <div className="flex-1">
                <label className="cursor-pointer inline-flex items-center px-4 py-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50">
                  <input
                    type="file"
                    className="sr-only"
                    accept="image/*"
                    onChange={handleAvatarChange}
                  />
                  Change Avatar
                </label>
              </div>
            </div>
          </div>
          
          <div className="mb-4">
            <label className="block text-gray-700 text-sm font-medium mb-2">
              Team Name*
            </label>
            <input
              type="text"
              className={`w-full px-3 py-2 border rounded-md ${errors.name ? 'border-red-500' : 'border-gray-300'} focus:outline-none focus:ring-2 focus:ring-primary-500`}
              value={name}
              onChange={handleNameChange}
            />
            {errors.name && (
              <p className="mt-1 text-sm text-red-600">
                {errors.name}
              </p>
            )}
          </div>
          
          <div className="mb-4">
            <label className="block text-gray-700 text-sm font-medium mb-2">
              Description
            </label>
            <textarea
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-primary-500"
              rows={3}
              value={description}
              onChange={handleDescriptionChange}
            ></textarea>
          </div>
          
          <div className="mb-4">
            <label className="block text-gray-700 text-sm font-medium mb-2">
              Storage Quota (GB)*
            </label>
            <input
              type="number"
              className={`w-full px-3 py-2 border rounded-md ${errors.storageQuota ? 'border-red-500' : 'border-gray-300'} focus:outline-none focus:ring-2 focus:ring-primary-500`}
              min="1"
              value={storageQuota}
              onChange={handleStorageQuotaChange}
            />
            {errors.storageQuota && (
              <p className="mt-1 text-sm text-red-600">
                {errors.storageQuota}
              </p>
            )}
          </div>
          
          <div className="mt-6 flex justify-end space-x-3">
            <Button
              type="button"
              variant="outline"
              onClick={onClose}
            >
              Cancel
            </Button>
            <Button
              type="submit"
              variant="primary"
              icon={<Save className="w-4 h-4" />}
              isLoading={isSubmitting}
            >
              Save Changes
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
}