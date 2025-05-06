import React from 'react';
import { Users, Lock, HardDrive, Info as InfoIcon } from 'lucide-react';
import { motion } from 'framer-motion';
import { Button } from './Button'; // Assuming Button is a custom component

// Removed duplicate ButtonProps interface as it should be defined in the Button component

interface TeamCardProps {
  team: {
    id: string;
    name: string;
    description: string;
    currentUsage: number;
    storageQuota: number;
    role: 'owner' | 'admin' | 'member';
    status?: 'active' | 'invited'; // Add status field
  };
  onView: () => void;
}

export function TeamCard({ team, onView }: TeamCardProps) {
  // Format storage values
  const formatStorage = (bytes: number) => {
    const gb = bytes / (1024 * 1024 * 1024);
    return gb.toFixed(1) + ' GB';
  };

  // Calculate percentage used
  const usagePercentage = Math.min(
    Math.round((team.currentUsage / team.storageQuota) * 100),
    100
  );

  return (
    <motion.div
      className="bg-white rounded-lg shadow-sm overflow-hidden hover:shadow-md transition-shadow"
      whileHover={{ y: -2 }}
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
    >
      {/* Add a badge for pending invitations */}
      {team.status === 'invited' && (
        <div className="bg-yellow-50 px-4 py-2 border-b border-yellow-100">
          <p className="text-sm text-yellow-700 flex items-center">
            <InfoIcon className="w-4 h-4 mr-2" />
            Pending invitation
          </p>
        </div>
      )}

      <div className="p-6">
        <div className="flex items-center mb-4">
          <div className="w-10 h-10 rounded-lg bg-primary-50 flex items-center justify-center text-primary-600">
            <Users className="w-5 h-5" />
          </div>
          <div className="ml-3">
            <h3 className="font-medium text-lg text-gray-900">{team.name}</h3>
            <span className="text-xs bg-gray-100 text-gray-600 px-2 py-1 rounded capitalize">{team.role}</span>
          </div>
        </div>
        
        {team.description && (
          <p className="text-sm text-gray-600 mb-4 line-clamp-2">{team.description}</p>
        )}

        {/* Storage usage */}
        <div className="mt-4">
          <div className="flex justify-between text-xs text-gray-500 mb-1">
            <span>Storage</span>
            <span>{formatStorage(team.currentUsage)} / {formatStorage(team.storageQuota)}</span>
          </div>
          <div className="w-full bg-gray-100 rounded-full h-2">
            <div 
              className={`h-2 rounded-full ${usagePercentage > 90 ? 'bg-red-500' : 'bg-primary-500'}`}
              style={{ width: `${usagePercentage}%` }}
            ></div>
          </div>
        </div>
      </div>
      <div className="bg-gray-50 px-6 py-3 flex justify-between items-center">
        <div className="text-sm text-gray-600 flex items-center">
          <HardDrive className="w-4 h-4 mr-1" />
          <span>{formatStorage(team.storageQuota)}</span>
        </div>
        <div className="text-sm text-gray-600">
          View Team →
        </div>
      </div>

      {/* For the action button at the bottom */}
      <div className="p-4 border-t border-gray-100">
        <Button
          variant="outline"
          onClick={onView}
        >
          {team.status === 'invited' ? 'View Invitation' : 'View Team'}
        </Button>
      </div>
    </motion.div>
  );
}