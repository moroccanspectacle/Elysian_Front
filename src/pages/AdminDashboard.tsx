import React, { useState, useEffect } from 'react';
import { Layout } from '../components/Layout';
import { api } from '../services/api';
import { 
  Users, FileText, Server, Briefcase, 
  Activity, TrendingUp, AlertTriangle, Calendar 
} from 'lucide-react';
import { format } from 'date-fns';
import { Link } from 'react-router-dom';

export function AdminDashboard() {
  const [stats, setStats] = useState({
    users: { total: 0, last30Days: 0 },
    files: { total: 0, totalSize: 0 },
    teams: { total: 0 }
  });
  const [activities, setActivities] = useState<any[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  
  useEffect(() => {
    fetchStats();
    fetchRecentActivities();
  }, []);
  
  const fetchStats = async () => {
    try {
      setIsLoading(true);
      const data = await api.admin.getSystemOverview();
      setStats(data);
    } catch (error) {
      console.error('Failed to fetch system overview:', error);
      setError('Failed to load system statistics');
    } finally {
      setIsLoading(false);
    }
  };
  
  const fetchRecentActivities = async () => {
    try {
      const data = await api.admin.getActivityLogs({ limit: 5 });
      setActivities(data.logs || []);
    } catch (error) {
      console.error('Failed to fetch activities:', error);
    }
  };
  
  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };
  
  if (isLoading) {
    return (
      <Layout>
        <div className="flex justify-center my-20">
          <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-[#217eaa]"></div>
        </div>
      </Layout>
    );
  }
  
  return (
    <Layout>
      <h1 className="text-3xl font-bold mb-8">Admin Dashboard</h1>

      <div className="flex border-b border-gray-200 mb-6">
        <Link to="/admin/users" className="px-4 py-2 font-medium mr-4 text-[#217eaa] hover:text-[#1a6389]">
          Users
        </Link>
        <Link to="/admin/files" className="px-4 py-2 font-medium mr-4 text-[#217eaa] hover:text-[#1a6389]">
          Files
        </Link>
        <Link to="/admin/activity" className="px-4 py-2 font-medium mr-4 text-[#217eaa] hover:text-[#1a6389]">
          Activity
        </Link>
        <Link to="/admin/settings" className="px-4 py-2 font-medium text-[#217eaa] hover:text-[#1a6389]">
          Settings
        </Link>
      </div>
      
      {error && (
        <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg mb-8">
          {error}
        </div>
      )}
      
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        {/* User Stats Card */}
        <div className="bg-white rounded-lg shadow-sm p-6">
          <div className="flex items-center justify-between">
            <h2 className="text-xl font-semibold text-gray-800">Users</h2>
            <div className="w-12 h-12 rounded-full bg-blue-50 flex items-center justify-center">
              <Users className="w-6 h-6 text-blue-500" />
            </div>
          </div>
          <div className="mt-4">
            <p className="text-3xl font-bold">{stats.users.total}</p>
            <p className="text-sm text-gray-500 mt-1">
              <span className="text-green-500">+{stats.users.last30Days}</span> new in last 30 days
            </p>
          </div>
        </div>
        
        {/* Files Stats Card */}
        <div className="bg-white rounded-lg shadow-sm p-6">
          <div className="flex items-center justify-between">
            <h2 className="text-xl font-semibold text-gray-800">Files</h2>
            <div className="w-12 h-12 rounded-full bg-purple-50 flex items-center justify-center">
              <FileText className="w-6 h-6 text-purple-500" />
            </div>
          </div>
          <div className="mt-4">
            <p className="text-3xl font-bold">{stats.files.total}</p>
            <p className="text-sm text-gray-500 mt-1">
              {formatBytes(stats.files.totalSize)} total storage used
            </p>
          </div>
        </div>
        
        {/* Teams Stats Card */}
        <div className="bg-white rounded-lg shadow-sm p-6">
          <div className="flex items-center justify-between">
            <h2 className="text-xl font-semibold text-gray-800">Teams</h2>
            <div className="w-12 h-12 rounded-full bg-green-50 flex items-center justify-center">
              <Briefcase className="w-6 h-6 text-green-500" />
            </div>
          </div>
          <div className="mt-4">
            <p className="text-3xl font-bold">{stats.teams.total}</p>
            <p className="text-sm text-gray-500 mt-1">
              Active collaboration groups
            </p>
          </div>
        </div>
      </div>
      
      {/* Recent Activity Section */}
      <div className="bg-white rounded-lg shadow-sm p-6 mb-8">
        <h2 className="text-xl font-semibold text-gray-800 mb-4">Recent System Activity</h2>
        {activities.length > 0 ? (
          <div className="space-y-4">
            {activities.map((activity, index) => (
              <div key={index} className="flex items-start border-b border-gray-100 pb-4">
                <div className="w-10 h-10 rounded-full bg-blue-50 flex items-center justify-center mr-4 flex-shrink-0">
                  <Activity className="w-5 h-5 text-blue-500" />
                </div>
                <div>
                  <div className="flex items-center mb-1">
                    <span className="font-medium text-gray-800">{activity.User?.username || 'User'}</span> 
                    <span className="text-gray-500 text-sm mx-2">•</span>
                    <span className="text-gray-500 text-sm">{format(new Date(activity.timestamp), 'MMM d, yyyy HH:mm')}</span>
                  </div>
                  <p className="text-gray-600">{activity.details || activity.action}</p> 
                </div>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-gray-500 text-center py-4">No recent activity found</p>
        )}
      </div>
      
      {/* System Health Section */}
      <div className="bg-white rounded-lg shadow-sm p-6">
        <h2 className="text-xl font-semibold text-gray-800 mb-4">System Health</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="border border-gray-100 rounded-lg p-4">
            <div className="flex items-center mb-2">
              <Server className="w-5 h-5 text-gray-500 mr-2" />
              <h3 className="font-medium">Server Status</h3>
            </div>
            <div className="flex items-center">
              <div className="w-3 h-3 rounded-full bg-green-500 mr-2"></div>
              <span className="text-gray-600">Operational</span>
            </div>
          </div>
          
          <div className="border border-gray-100 rounded-lg p-4">
            <div className="flex items-center mb-2">
              <Calendar className="w-5 h-5 text-gray-500 mr-2" />
              <h3 className="font-medium">Last Backup</h3>
            </div>
            <span className="text-gray-600">{format(new Date(), 'MMM d, yyyy HH:mm')}</span>
          </div>
        </div>
      </div>
    </Layout>
  );
}