import React, { useState, useEffect, useCallback } from 'react';
import { X, UserPlus, AlertCircle } from 'lucide-react';
import { Button } from './Button';
import { api } from '../services/api';
import Select, { StylesConfig } from 'react-select'; // Import react-select
import debounce from 'lodash/debounce'; // Import debounce

interface InviteMembersModalProps {
  teamId: string;
  onClose: () => void;
  onInvite: (newMembers: any[]) => void; // Keep existing prop for simplicity
}

// Define User type for search results
interface SearchUser {
  id: number;
  username: string;
  email: string;
  profileImage?: string;
}

// Define option type for react-select
interface UserOption {
  value: number; // User ID
  label: string; // Display string (e.g., "username (email)")
  user: SearchUser; // Store the full user object
}

export function InviteMembersModal({ teamId, onClose, onInvite }: InviteMembersModalProps) {
  const [selectedUser, setSelectedUser] = useState<UserOption | null>(null); // State for selected user
  const [role, setRole] = useState<'member' | 'admin'>('member');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState(''); // State for search input
  const [options, setOptions] = useState<UserOption[]>([]); // State for dropdown options
  const [isSearching, setIsSearching] = useState(false); // State for search loading indicator

  // Debounced search function
  const debouncedSearch = useCallback(
    debounce(async (query: string) => {
      if (query.length < 2) { // Only search if query is long enough
        setOptions([]);
        setIsSearching(false);
        return;
      }
      setIsSearching(true);
      try {
        const users = await api.teams.searchInvitees(teamId, query);
        const userOptions: UserOption[] = users.map(user => ({
          value: user.id,
          label: `${user.username} (${user.email})`,
          user: user
        }));
        setOptions(userOptions);
      } catch (searchError: any) {
        console.error("Search error:", searchError);
        setOptions([]); // Clear options on error
      } finally {
        setIsSearching(false);
      }
    }, 300), // 300ms debounce delay
    [teamId] // Recreate debounce function if teamId changes
  );

  // Effect to trigger search when searchQuery changes
  useEffect(() => {
    debouncedSearch(searchQuery);
    // Cancel the debounce on unmount
    return () => {
      debouncedSearch.cancel();
    };
  }, [searchQuery, debouncedSearch]);


  const handleInvite = async () => {
    if (!selectedUser) {
      setError('Please select a user to invite.');
      return;
    }

    setIsLoading(true);
    setError(null);

    try {
      // Call the updated API function with userId and role
      const newMemberData = await api.teams.inviteMember(teamId, selectedUser.value, role);

      // Pass the newly invited member data back (adjust format if needed)
      onInvite([newMemberData]);
      onClose(); // Close modal on success
    } catch (err: any) {
      console.error('Failed to invite member:', err);
      setError(err.message || 'An unexpected error occurred.');
    } finally {
      setIsLoading(false);
    }
  };

  // Custom styles for react-select to match Tailwind theme (optional)
  const selectStyles: StylesConfig<UserOption, false> = {
    control: (provided) => ({
      ...provided,
      borderColor: '#D1D5DB', // gray-300
      '&:hover': {
        borderColor: '#9CA3AF', // gray-400
      },
      boxShadow: 'none',
      minHeight: '42px',
    }),
    option: (provided, state) => ({
      ...provided,
      backgroundColor: state.isSelected ? '#1E3A8A' : state.isFocused ? '#DBEAFE' : undefined, // primary-800, blue-100
      color: state.isSelected ? 'white' : '#1F2937', // gray-800
      ':active': {
        backgroundColor: state.isSelected ? '#1E3A8A' : '#BFDBFE', // primary-800, blue-200
      },
    }),
    input: (provided) => ({
      ...provided,
      margin: '0px',
      padding: '0px',
    }),
    valueContainer: (provided) => ({
      ...provided,
      padding: '0 8px',
    }),
    placeholder: (provided) => ({
      ...provided,
      color: '#6B7280', // gray-500
    }),
    // Add more styles as needed
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-60 flex justify-center items-center z-50 p-4">
      <div className="bg-white rounded-lg shadow-xl w-full max-w-md">
        {/* Header */}
        <div className="flex justify-between items-center p-5 border-b border-gray-200">
          <h2 className="text-xl font-semibold text-gray-800 flex items-center">
            <UserPlus className="w-6 h-6 mr-2 text-primary-600" />
            Invite Member
          </h2>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600">
            <X className="w-6 h-6" />
          </button>
        </div>

        {/* Body */}
        <div className="p-6 space-y-5">
          {error && (
            <div className="bg-red-50 border border-red-200 text-red-700 p-3 rounded-md flex items-center text-sm">
              <AlertCircle className="w-5 h-5 mr-2 flex-shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {/* User Search Input */}
          <div>
            <label htmlFor="user-search" className="block text-sm font-medium text-gray-700 mb-1">
              Search User
            </label>
            <Select<UserOption, false>
              id="user-search"
              options={options}
              value={selectedUser}
              onChange={(option) => setSelectedUser(option)}
              onInputChange={(inputValue) => setSearchQuery(inputValue)}
              isLoading={isSearching}
              placeholder="Type username or email..."
              isClearable
              styles={selectStyles}
              noOptionsMessage={({ inputValue }) =>
                inputValue.length < 2 ? 'Type at least 2 characters' : 'No users found'
              }
            />
            <p className="text-xs text-gray-500 mt-1">Search for existing users by username or email.</p>
          </div>

          {/* Role Selection */}
          <div>
            <label htmlFor="role" className="block text-sm font-medium text-gray-700 mb-1">
              Assign Role
            </label>
            <select
              id="role"
              value={role}
              onChange={(e) => setRole(e.target.value as 'member' | 'admin')}
              className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-primary-500 focus:border-primary-500 sm:text-sm"
            >
              <option value="member">Member</option>
              <option value="admin">Admin</option>
              {/* Add 'owner' if applicable, but usually owner is assigned on creation */}
            </select>
          </div>
        </div>

        {/* Footer */}
        <div className="flex justify-end items-center p-5 border-t border-gray-200 bg-gray-50 rounded-b-lg space-x-3">
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button
            variant="primary"
            onClick={handleInvite}
            isLoading={isLoading}
            disabled={!selectedUser || isLoading} // Disable if no user selected or loading
          >
            Send Invitation
          </Button>
        </div>
      </div>
    </div>
  );
}