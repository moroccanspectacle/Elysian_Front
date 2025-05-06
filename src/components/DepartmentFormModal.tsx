import React, { useState, useEffect } from 'react';
import { X } from 'lucide-react';

interface DepartmentFormData {
  name: string;
  description: string;
  vaultAccess: boolean;
  vaultQuotaBonus: number;
  requireMfa: boolean;
  securityClearanceLevel: number;
}

interface DepartmentFormModalProps {
  department?: DepartmentFormData;
  onClose: () => void;
  onSave: (department: DepartmentFormData) => void;
}

export function DepartmentFormModal({ department, onClose, onSave }: DepartmentFormModalProps) {
  const isEdit = !!department;
  
  const [formData, setFormData] = useState<DepartmentFormData>({
    name: department?.name || '',
    description: department?.description || '',
    vaultAccess: department?.vaultAccess ?? true,
    vaultQuotaBonus: department?.vaultQuotaBonus ?? 0,
    requireMfa: department?.requireMfa ?? false,
    securityClearanceLevel: department?.securityClearanceLevel ?? 1
  });
  
  const [errors, setErrors] = useState<{[key: string]: string}>({});
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [quotaGb, setQuotaGb] = useState(Math.round(formData.vaultQuotaBonus / (1024 * 1024 * 1024)));

  useEffect(() => {
    // Convert bytes to GB for display
    setQuotaGb(Math.round(formData.vaultQuotaBonus / (1024 * 1024 * 1024)));
  }, [formData.vaultQuotaBonus]);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => {
    const { name, value, type } = e.target;
    
    if (type === 'checkbox') {
      const checked = (e.target as HTMLInputElement).checked;
      setFormData({ ...formData, [name]: checked });
    } else {
      setFormData({ ...formData, [name]: value });
    }
    
    // Clear error for this field
    if (errors[name]) {
      setErrors({ ...errors, [name]: '' });
    }
  };

  const handleQuotaChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const gbValue = parseInt(e.target.value) || 0;
    setQuotaGb(gbValue);
    // Convert GB to bytes
    setFormData({ 
      ...formData, 
      vaultQuotaBonus: gbValue * 1024 * 1024 * 1024 
    });
  };

  const validate = (): boolean => {
    const newErrors: {[key: string]: string} = {};
    
    if (!formData.name.trim()) {
      newErrors.name = 'Name is required';
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
      await onSave(formData);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50">
      <div className="bg-white rounded-lg shadow-xl w-full max-w-md">
        <div className="flex justify-between items-center border-b border-gray-200 px-6 py-4">
          <h3 className="text-lg font-medium">
            {isEdit ? 'Edit Department' : 'Create Department'}
          </h3>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-500"
          >
            <X className="w-5 h-5" />
          </button>
        </div>
        
        <form onSubmit={handleSubmit} className="p-6">
          <div className="space-y-4">
            <div>
              <label htmlFor="name" className="block text-sm font-medium text-gray-700">
                Department Name*
              </label>
              <input
                type="text"
                id="name"
                name="name"
                value={formData.name}
                onChange={handleChange}
                className={`mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-primary-500 focus:ring-primary-500 sm:text-sm ${
                  errors.name ? 'border-red-300' : ''
                }`}
              />
              {errors.name && (
                <p className="mt-1 text-sm text-red-600">{errors.name}</p>
              )}
            </div>
            
            <div>
              <label htmlFor="description" className="block text-sm font-medium text-gray-700">
                Description
              </label>
              <textarea
                id="description"
                name="description"
                value={formData.description}
                onChange={handleChange}
                rows={3}
                className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-primary-500 focus:ring-primary-500 sm:text-sm"
              ></textarea>
            </div>
            
            <div>
              <label htmlFor="vaultQuotaBonus" className="block text-sm font-medium text-gray-700">
                Additional Vault Storage (GB)
              </label>
              <input
                type="number"
                id="vaultQuotaBonus"
                name="vaultQuotaBonus"
                value={quotaGb}
                onChange={handleQuotaChange}
                min="0"
                max="10000"
                className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-primary-500 focus:ring-primary-500 sm:text-sm"
              />
              <p className="mt-1 text-xs text-gray-500">
                Additional storage allocation on top of role-based quota
              </p>
            </div>
            
            <div>
              <label htmlFor="securityClearanceLevel" className="block text-sm font-medium text-gray-700">
                Security Clearance Level
              </label>
              <select
                id="securityClearanceLevel"
                name="securityClearanceLevel"
                value={formData.securityClearanceLevel}
                onChange={handleChange}
                className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-primary-500 focus:ring-primary-500 sm:text-sm"
              >
                <option value={1}>Level 1 - Basic</option>
                <option value={2}>Level 2 - Standard</option>
                <option value={3}>Level 3 - Enhanced</option>
                <option value={4}>Level 4 - Advanced</option>
                <option value={5}>Level 5 - Maximum</option>
              </select>
            </div>
            
            <div className="flex items-start space-x-4">
              <div className="flex items-center h-5">
                <input
                  id="vaultAccess"
                  name="vaultAccess"
                  type="checkbox"
                  checked={formData.vaultAccess}
                  onChange={handleChange}
                  className="focus:ring-primary-500 h-4 w-4 text-primary-600 border-gray-300 rounded"
                />
              </div>
              <div className="ml-3 text-sm">
                <label htmlFor="vaultAccess" className="font-medium text-gray-700">
                  Vault Access
                </label>
                <p className="text-gray-500">Allow this department to access the Confidential Vault</p>
              </div>
            </div>
            
            <div className="flex items-start space-x-4">
              <div className="flex items-center h-5">
                <input
                  id="requireMfa"
                  name="requireMfa"
                  type="checkbox"
                  checked={formData.requireMfa}
                  onChange={handleChange}
                  className="focus:ring-primary-500 h-4 w-4 text-primary-600 border-gray-300 rounded"
                />
              </div>
              <div className="ml-3 text-sm">
                <label htmlFor="requireMfa" className="font-medium text-gray-700">
                  Require MFA
                </label>
                <p className="text-gray-500">Force members of this department to use two-factor authentication</p>
              </div>
            </div>
          </div>
          
          <div className="mt-6 flex justify-end space-x-3">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isSubmitting}
              className={`px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-primary-600 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 ${
                isSubmitting ? 'opacity-70 cursor-not-allowed' : ''
              }`}
            >
              {isSubmitting ? 'Saving...' : isEdit ? 'Update' : 'Create'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}