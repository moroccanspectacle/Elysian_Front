import React from 'react';
import { Upload, Download, Share2, Trash2, Activity, User as UserIcon, Settings, UserPlus } from 'lucide-react';

const actionIcons: { [key: string]: React.ElementType } = {
  upload: Upload,
  download: Download,
  share: Share2,
  delete: Trash2,
  admin_delete_file: Trash2,
  login: Activity,
  update_system_settings: Settings,
  create_user: UserPlus,
  update_user: UserIcon,
};

interface DisplayActivityLog {
  id: string;
  timestamp: Date | string;
  action: string;
  username?: string;
  fileName?: string;
  details?: any;
}

interface ActivityTableProps {
  logs: DisplayActivityLog[];
  totalPages: number;
  currentPage: number;
  onPageChange: (page: number) => void;
  isLoading?: boolean;
  error?: string | null;
}

export function ActivityTable({
  logs,
  totalPages,
  currentPage,
  onPageChange,
  isLoading = false,
  error = null,
}: ActivityTableProps) {
  return (
    <div className="bg-white rounded-xl shadow-sm overflow-hidden">
      {isLoading ? (
        <div className="flex justify-center items-center p-16">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-500"></div>
        </div>
      ) : error ? (
        <div className="p-6 text-center text-red-600">{error}</div>
      ) : logs.length === 0 ? (
        <div className="p-16 text-center text-neutral-500">
          <Activity className="mx-auto h-8 w-8 text-neutral-400 mb-2" />
          <p>No activity logs found for the selected criteria</p>
        </div>
      ) : (
        <>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="bg-neutral-50 text-neutral-500 text-sm">
                  <th className="px-6 py-3 text-left font-medium">Timestamp</th>
                  <th className="px-6 py-3 text-left font-medium">User</th>
                  <th className="px-6 py-3 text-left font-medium">Action</th>
                  <th className="px-6 py-3 text-left font-medium">Details</th>
                </tr>
              </thead>
              <tbody>
                {logs.map((log) => {
                  const Icon = actionIcons[log.action] || Activity;
                  return (
                    <tr key={log.id} className="border-b border-neutral-100 hover:bg-neutral-50 transition-colors">
                      <td className="px-6 py-4 text-sm text-neutral-500">
                        {log.timestamp instanceof Date ? log.timestamp.toLocaleString() : String(log.timestamp)}
                      </td>
                      <td className="px-6 py-4 text-sm font-medium flex items-center">
                        <UserIcon className="w-4 h-4 mr-2 text-gray-400" />
                        {log.username || 'System'}
                      </td>
                      <td className="px-6 py-4">
                        <span className="flex items-center text-sm">
                          <Icon
                            className={`w-4 h-4 mr-2 ${
                              log.action.includes('delete')
                                ? 'text-red-500'
                                : log.action === 'upload'
                                ? 'text-green-500'
                                : log.action === 'share'
                                ? 'text-purple-500'
                                : 'text-primary-500'
                            }`}
                          />
                          {log.action.replace(/_/g, ' ').replace(/\b\w/g, (l) => l.toUpperCase())}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-sm text-neutral-600 break-words max-w-xs">
                        {log.fileName || (typeof log.details === 'string' ? log.details : JSON.stringify(log.details)) || 'N/A'}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {totalPages > 1 && (
            <div className="p-4 flex justify-between items-center border-t border-neutral-100">
              <button
                className="px-3 py-1.5 text-sm bg-white border border-neutral-200 rounded-md hover:bg-neutral-50 disabled:opacity-50 transition-colors"
                onClick={() => onPageChange(Math.max(1, currentPage - 1))}
                disabled={currentPage === 1}
              >
                Previous
              </button>
              <span className="text-sm text-neutral-500">
                Page {currentPage} of {totalPages}
              </span>
              <button
                className="px-3 py-1.5 text-sm bg-white border border-neutral-200 rounded-md hover:bg-neutral-50 disabled:opacity-50 transition-colors"
                onClick={() => onPageChange(Math.min(totalPages, currentPage + 1))}
                disabled={currentPage === totalPages}
              >
                Next
              </button>
            </div>
          )}
        </>
      )}
    </div>
  );
}