import React, { useState, useEffect } from 'react';
import { Layout } from '../components/Layout';
import { useAuth } from '../components/AuthContext';
import { Edit2, Save, User, Mail, Key, Check, AlertCircle } from 'lucide-react';
import { api } from '../services/api';
import { validatePassword, getPasswordStrength } from '../utils/passwordValidation';

export function ProfilePage() {
  const { user, updateUser } = useAuth();
  const [isEditing, setIsEditing] = useState(false);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [profileImage, setProfileImage] = useState<File | null>(null);
  const [profileImagePreview, setProfileImagePreview] = useState<string | null>(
    user?.profileImage ? `http://localhost:3000${user.profileImage}` : null
  );
  
  const [profileData, setProfileData] = useState({
    username: user?.username || '',
    email: user?.email || '',
    currentPassword: '',
    newPassword: '',
    confirmPassword: ''
  });

  const [passwordErrors, setPasswordErrors] = useState<string[]>([]);
  const [passwordStrength, setPasswordStrength] = useState({ score: 0, label: 'No Password', color: 'bg-gray-200' });

  // Fetch user profile on component mount
  useEffect(() => {
    const fetchProfile = async () => {
      try {
        const userData = await api.profile.get();
        updateUser(userData);
        setProfileData({
          ...profileData,
          username: userData.username || '',
          email: userData.email || ''
        });
        if (userData.profileImage) {
          setProfileImagePreview(`http://localhost:3000${userData.profileImage}`);
        }
      } catch (error) {
        console.error('Error fetching profile:', error);
      }
    };

    fetchProfile();
  }, []);

  useEffect(() => {
    if (profileData.newPassword) {
      const { errors } = validatePassword(profileData.newPassword);
      setPasswordErrors(errors);
      setPasswordStrength(getPasswordStrength(profileData.newPassword));
    } else {
      setPasswordErrors([]);
      setPasswordStrength({ score: 0, label: 'No Password', color: 'bg-gray-200' });
    }
  }, [profileData.newPassword]);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setProfileData({
      ...profileData,
      [e.target.name]: e.target.value
    });
  };

  const handleImageChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      const file = e.target.files[0];
      setProfileImage(file);
      
      // Create a preview
      const reader = new FileReader();
      reader.onloadend = () => {
        setProfileImagePreview(reader.result as string);
      };
      reader.readAsDataURL(file);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setMessage(null);
    
    try {
      // Upload profile image if changed
      if (profileImage) {
        const imageResult = await api.profile.uploadImage(profileImage);
        updateUser({ profileImage: imageResult.profileImage });
      }
      
      // Update profile info
      if (profileData.username !== user?.username || profileData.email !== user?.email) {
        await api.profile.update({
          username: profileData.username,
          email: profileData.email
        });
        updateUser({
          username: profileData.username,
          email: profileData.email
        });
      }
      
      // Change password if provided
      if (profileData.currentPassword && profileData.newPassword) {
        if (profileData.newPassword !== profileData.confirmPassword) {
          setMessage({ type: 'error', text: 'New passwords do not match' });
          setLoading(false);
          return;
        }
        
        // Validate password strength
        const { valid, errors } = validatePassword(profileData.newPassword);
        if (!valid) {
          setMessage({ type: 'error', text: errors[0] });
          setLoading(false);
          return;
        }
        
        await api.profile.changePassword({
          currentPassword: profileData.currentPassword,
          newPassword: profileData.newPassword
        });
        
        // Clear password fields
        setProfileData({
          ...profileData,
          currentPassword: '',
          newPassword: '',
          confirmPassword: ''
        });
      }
      
      setMessage({ type: 'success', text: 'Profile updated successfully' });
      setIsEditing(false);
    } catch (error: any) {
      console.error('Error updating profile:', error);
      const errorMessage = error.response?.data?.error || error.message || 'Failed to update profile';
      setMessage({ 
        type: 'error', 
        text: errorMessage 
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <Layout>
      <div className="max-w-4xl mx-auto px-4 py-8">
        <div className="flex justify-between items-center mb-8">
          <h1 className="text-3xl font-bold text-gray-900">Profile Settings</h1>
          <button
            onClick={() => setIsEditing(!isEditing)}
            disabled={loading}
            className="flex items-center px-4 py-2 bg-[#217eaa] text-white rounded-md hover:bg-[#1a6389] transition-colors disabled:opacity-50"
          >
            {loading ? (
              <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white mr-2"></div>
            ) : isEditing ? (
              <>
                <Save className="h-5 w-5 mr-2" />
                Save
              </>
            ) : (
              <>
                <Edit2 className="h-5 w-5 mr-2" />
                Edit Profile
              </>
            )}
          </button>
        </div>

        {message && (
          <div className={`mb-6 p-4 rounded-lg ${
            message.type === 'success' ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'
          }`}>
            <div className="flex items-center">
              {message.type === 'success' ? (
                <Check className="h-5 w-5 mr-2" />
              ) : (
                <AlertCircle className="h-5 w-5 mr-2" />
              )}
              {message.text}
            </div>
          </div>
        )}

        <div className="bg-white rounded-xl shadow-md overflow-hidden">
          <div className="p-8">
            <div className="flex flex-col sm:flex-row items-center sm:items-start mb-8">
              <div className="w-32 h-32 bg-[#217eaa] rounded-full flex items-center justify-center mb-4 sm:mb-0 sm:mr-8 overflow-hidden">
                {profileImagePreview ? (
                  <img 
                    src={profileImagePreview} 
                    alt="Profile" 
                    className="w-full h-full object-cover" 
                  />
                ) : (
                  <User className="h-16 w-16 text-white" />
                )}
              </div>
              <div>
                <h2 className="text-2xl font-semibold">{user?.username || 'User'}</h2>
                <p className="text-gray-500">{user?.email}</p>
                {isEditing && (
                  <div className="mt-4">
                    <label className="block text-sm font-medium text-gray-700 mb-1">Upload new profile picture</label>
                    <input 
                      type="file" 
                      accept="image/*"
                      onChange={handleImageChange}
                      className="block w-full text-sm text-gray-500 file:mr-4 file:py-2 file:px-4 file:rounded file:border-0 file:text-sm file:font-semibold file:bg-[#e6f2f8] file:text-[#217eaa] hover:file:bg-[#d1e7f2]" 
                    />
                  </div>
                )}
              </div>
            </div>

            <form onSubmit={handleSubmit}>
              <div className="space-y-6">
                <div>
                  <label className="flex items-center text-sm font-medium text-gray-700 mb-1">
                    <User className="h-4 w-4 mr-2" />
                    Username
                  </label>
                  <input
                    type="text"
                    name="username"
                    value={profileData.username}
                    onChange={handleChange}
                    disabled={!isEditing || loading}
                    className="w-full rounded-lg border border-gray-300 px-3 py-2 focus:outline-none focus:ring-2 focus:ring-[#217eaa] disabled:bg-gray-100"
                  />
                </div>
                
                <div>
                  <label className="flex items-center text-sm font-medium text-gray-700 mb-1">
                    <Mail className="h-4 w-4 mr-2" />
                    Email
                  </label>
                  <input
                    type="email"
                    name="email"
                    value={profileData.email}
                    onChange={handleChange}
                    disabled={!isEditing || loading}
                    className="w-full rounded-lg border border-gray-300 px-3 py-2 focus:outline-none focus:ring-2 focus:ring-[#217eaa] disabled:bg-gray-100"
                  />
                </div>
                
                {isEditing && (
                  <div className="border-t border-gray-200 pt-6">
                    <h3 className="flex items-center text-lg font-medium text-gray-900 mb-4">
                      <Key className="h-5 w-5 mr-2" />
                      Change Password
                    </h3>
                    
                    <div className="space-y-4">
                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-1">Current Password</label>
                        <input
                          type="password"
                          name="currentPassword"
                          value={profileData.currentPassword}
                          onChange={handleChange}
                          disabled={loading}
                          className="w-full rounded-lg border border-gray-300 px-3 py-2 focus:outline-none focus:ring-2 focus:ring-[#217eaa]"
                          placeholder="••••••••"
                        />
                      </div>
                      
                      {/* New Password Field */}
                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-1">New Password</label>
                        <input
                          type="password"
                          name="newPassword"
                          value={profileData.newPassword}
                          onChange={handleChange}
                          className={`w-full rounded-lg border ${
                            passwordErrors.length > 0 ? 'border-red-500' : 'border-gray-300'
                          } px-3 py-2 focus:outline-none focus:ring-2 focus:ring-[#217eaa]`}
                          disabled={!isEditing}
                        />
                        
                        {/* Password strength indicator */}
                        {isEditing && profileData.newPassword && (
                          <div className="mt-2">
                            <div className="flex items-center justify-between mb-1">
                              <span className="text-xs text-gray-500">Password strength:</span>
                              <span className="text-xs font-medium" style={{ color: passwordStrength.color.replace('bg-', 'text-') }}>
                                {passwordStrength.label}
                              </span>
                            </div>
                            <div className="h-1.5 w-full bg-gray-200 rounded-full overflow-hidden">
                              <div 
                                className={`h-full ${passwordStrength.color}`} 
                                style={{ width: `${(passwordStrength.score / 5) * 100}%` }}
                              ></div>
                            </div>
                            
                            {passwordErrors.length > 0 && (
                              <div className="mt-2 space-y-1">
                                {passwordErrors.map((error, index) => (
                                  <p key={index} className="text-xs text-red-500">{error}</p>
                                ))}
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                      
                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-1">Confirm New Password</label>
                        <input
                          type="password"
                          name="confirmPassword"
                          value={profileData.confirmPassword}
                          onChange={handleChange}
                          disabled={loading}
                          className="w-full rounded-lg border border-gray-300 px-3 py-2 focus:outline-none focus:ring-2 focus:ring-[#217eaa]"
                          placeholder="••••••••"
                        />
                      </div>
                    </div>
                  </div>
                )}

                {isEditing && (
                  <div className="pt-6">
                    <button
                      type="submit"
                      disabled={loading}
                      className="w-full bg-[#217eaa] text-white rounded-lg px-4 py-2 hover:bg-[#1a6389] transition-colors disabled:opacity-50"
                    >
                      {loading ? (
                        <div className="flex items-center justify-center">
                          <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white mr-2"></div>
                          Saving...
                        </div>
                      ) : (
                        'Save Changes'
                      )}
                    </button>
                  </div>
                )}
              </div>
            </form>
          </div>
        </div>
      </div>
    </Layout>
  );
}