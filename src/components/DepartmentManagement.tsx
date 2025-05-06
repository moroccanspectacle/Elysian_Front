import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { Shield, Edit, Trash2, Plus, Users, HardDrive, AlertCircle, Search } from 'lucide-react';
import { DepartmentFormModal } from './DepartmentFormModal';
import { ConfirmationModal } from './ConfirmationModal';

interface Department {
  id: number;
  name: string;
  description: string;
  vaultAccess: boolean;
  vaultQuotaBonus: number;
  requireMfa: boolean;
  securityClearanceLevel: number;
  userCount?: number;
}

export function DepartmentManagement() {
  const [departments, setDepartments] = useState<Department[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [editDepartment, setEditDepartment] = useState<Department | null>(null);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchDepartments();
  }, []);

  const fetchDepartments = async () => {
    try {
      setLoading(true);
      const data = await api.admin.getDepartments();
      setDepartments(data);
      setError(null);
    } catch (err: any) {
      console.error('Failed to fetch departments:', err);
      setError('Failed to load departments');
    } finally {
      setLoading(false);
    }
  };

  const filteredDepartments = departments.filter(dept => 
    dept.name.toLowerCase().includes(searchTerm.toLowerCase()) || 
    dept.description.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const formatQuotaBonus = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const handleDelete = async (id: number) => {
    try {
      await api.admin.deleteDepartment(id);
      await fetchDepartments();
      setShowDeleteConfirm(null);
      setError(null);
    } catch (err: any) {
      console.error('Failed to delete department:', err);
      if (err.response?.data?.userCount) {
        setError(`Cannot delete department with ${err.response.data.userCount} assigned users. Reassign users first.`);
      } else {
        setError('Failed to delete department');
      }
    }
  };

  return (
    <div>
      <div className="flex justify-between items-center mb-6">
        <h2 className="text-2xl font-semibold">Department Management</h2>
        <div className="flex space-x-2">
          <div className="relative">
            <Search className="w-5 h-5 absolute left-3 top-1/2 transform -translate-y-1/2 text-[#8ca4ac]" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search departments..."
              className="pl-10 pr-4 py-2 rounded-lg border border-[#8ca4ac] focus:outline-none focus:ring-2 focus:ring-[#217eaa]"
            />
          </div>
          <button
            onClick={() => setShowCreateModal(true)}
            className="bg-primary-600 text-white px-4 py-2 rounded-lg hover:bg-primary-700 flex items-center"
          >
            <Plus className="w-4 h-4 mr-2" />
            Create Department
          </button>
        </div>
      </div>

      {error && (
        <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg mb-4 flex items-center">
          <AlertCircle className="w-5 h-5 mr-2" />
          {error}
        </div>
      )}

      <div className="bg-white rounded-lg shadow-sm overflow-hidden">
        {loading ? (
          <div className="p-6 flex justify-center">
            <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-[#217eaa]"></div>
          </div>
        ) : (
          filteredDepartments.length === 0 ? (
            <div className="p-6 text-center text-gray-500">
              No departments found
            </div>
          ) : (
            <table className="w-full">
              <thead>
                <tr className="bg-[#f2f2f3] text-[#8ca4ac] text-sm">
                  <th className="px-6 py-3 text-left">Department</th>
                  <th className="px-6 py-3 text-left">Members</th>
                  <th className="px-6 py-3 text-left">Storage Bonus</th>
                  <th className="px-6 py-3 text-left">Security Level</th>
                  <th className="px-6 py-3 text-left">Vault Access</th>
                  <th className="px-6 py-3 text-left">MFA Required</th>
                  <th className="px-6 py-3 text-left">Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredDepartments.map((dept) => (
                  <tr key={dept.id} className="border-b border-[#f2f2f3]">
                    <td className="px-6 py-4">
                      <div className="flex items-center">
                        <div className="w-8 h-8 rounded bg-blue-100 flex items-center justify-center mr-3">
                          <Shield className="w-4 h-4 text-blue-600" />
                        </div>
                        <div>
                          <div className="font-medium">{dept.name}</div>
                          <div className="text-sm text-gray-500">{dept.description}</div>
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex items-center">
                        <Users className="w-4 h-4 text-gray-500 mr-2" />
                        {dept.userCount || 0}
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex items-center">
                        <HardDrive className="w-4 h-4 text-gray-500 mr-2" />
                        {formatQuotaBonus(dept.vaultQuotaBonus)}
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex">
                        {[...Array(5)].map((_, i) => (
                          <div 
                            key={i} 
                            className={`w-2 h-5 mx-0.5 rounded-sm ${i < dept.securityClearanceLevel ? 'bg-blue-600' : 'bg-gray-200'}`}
                          />
                        ))}
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      {dept.vaultAccess ? (
                        <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                          Enabled
                        </span>
                      ) : (
                        <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800">
                          Disabled
                        </span>
                      )}
                    </td>
                    <td className="px-6 py-4">
                      {dept.requireMfa ? (
                        <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                          Required
                        </span>
                      ) : (
                        <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-800">
                          Optional
                        </span>
                      )}
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex space-x-2">
                        <button
                          onClick={() => setEditDepartment(dept)}
                          className="p-1 rounded-md text-gray-400 hover:text-blue-600 hover:bg-blue-50"
                          title="Edit Department"
                        >
                          <Edit className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => setShowDeleteConfirm(dept.id)}
                          className="p-1 rounded-md text-gray-400 hover:text-red-600 hover:bg-red-50"
                          title="Delete Department"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )
        )}
      </div>

      {showCreateModal && (
        <DepartmentFormModal
          onClose={() => setShowCreateModal(false)}
          onSave={async (deptData) => {
            try {
              await api.admin.createDepartment(deptData);
              fetchDepartments();
              setShowCreateModal(false);
            } catch (err) {
              console.error('Failed to create department:', err);
              setError('Failed to create department');
            }
          }}
        />
      )}

      {editDepartment && (
        <DepartmentFormModal
          department={editDepartment}
          onClose={() => setEditDepartment(null)}
          onSave={async (deptData) => {
            try {
              await api.admin.updateDepartment(editDepartment.id, deptData);
              fetchDepartments();
              setEditDepartment(null);
            } catch (err) {
              console.error('Failed to update department:', err);
              setError('Failed to update department');
            }
          }}
        />
      )}

      {showDeleteConfirm !== null && (
        <ConfirmationModal
          title="Delete Department"
          message="Are you sure you want to delete this department? This action cannot be undone."
          confirmLabel="Delete"
          confirmVariant="danger"
          onConfirm={() => handleDelete(showDeleteConfirm)}
          onCancel={() => setShowDeleteConfirm(null)}
        />
      )}
    </div>
  );
}