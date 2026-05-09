import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '../lib/api';
import { Role, Permission } from '../types';

// --- Types ---

interface RoleFormData {
  name: string;
  description: string;
  permissions: string[];
  inherits_from?: string;
}

// --- Components ---

export const PermissionMatrix: React.FC<{
  selectedPermissions: string[];
  onToggle: (permId: string) => void;
}> = ({ selectedPermissions, onToggle }) => {
  const { data: permissions } = useQuery({
    queryKey: ['permissions'],
    queryFn: () => api.get('/admin/v2/rbac/permissions').then(res => res.data),
  });

  if (!permissions) return <div>Loading permissions...</div>;

  // Group by category
  const categories = permissions.reduce((acc: any, p: Permission) => {
    if (!acc[p.category]) acc[p.category] = [];
    acc[p.category].push(p);
    return acc;
  }, {});

  return (
    <div className="space-y-6">
      {Object.entries(categories).map(([category, perms]: [string, any]) => (
        <div key={category} className="border rounded-lg p-4 bg-white">
          <h3 className="text-lg font-semibold text-gray-800 capitalize mb-3">{category}</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {perms.map((perm: Permission) => (
              <label
                key={perm.id}
                className={`flex items-start space-x-3 p-3 rounded-md cursor-pointer transition-colors ${
                  selectedPermissions.includes(perm.id)
                    ? 'bg-blue-50 border-blue-200 border'
                    : 'bg-gray-50 hover:bg-gray-100 border border-transparent'
                }`}
              >
                <input
                  type="checkbox"
                  checked={selectedPermissions.includes(perm.id)}
                  onChange={() => onToggle(perm.id)}
                  className="mt-1 h-4 w-4 text-blue-600 rounded focus:ring-blue-500"
                />
                <div>
                  <p className="font-medium text-sm text-gray-900">{perm.name}</p>
                  <p className="text-xs text-gray-500">{perm.description}</p>
                </div>
              </label>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
};

export const RoleManager: React.FC = () => {
  const [isCreating, setIsCreating] = useState(false);
  const [editingRole, setEditingRole] = useState<Role | null>(null);
  const [formData, setFormData] = useState<RoleFormData>({
    name: '',
    description: '',
    permissions: [],
  });

  const queryClient = useQueryClient();

  const { data: roles, isLoading } = useQuery({
    queryKey: ['roles'],
    queryFn: () => api.get('/admin/v2/rbac/roles').then(res => res.data),
  });

  const createMutation = useMutation({
    mutationFn: (data: RoleFormData) => api.post('/admin/v2/rbac/roles', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['roles'] });
      setIsCreating(false);
      resetForm();
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: RoleFormData }) =>
      api.put(`/admin/v2/rbac/roles/${id}`, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['roles'] });
      setEditingRole(null);
      resetForm();
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/admin/v2/rbac/roles/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['roles'] });
    },
  });

  const resetForm = () => {
    setFormData({ name: '', description: '', permissions: [] });
  };

  const handleTogglePermission = (permId: string) => {
    setFormData(prev => ({
      ...prev,
      permissions: prev.permissions.includes(permId)
        ? prev.permissions.filter(p => p !== permId)
        : [...prev.permissions, permId],
    }));
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (editingRole) {
      updateMutation.mutate({ id: editingRole.id, data: formData });
    } else {
      createMutation.mutate(formData);
    }
  };

  const startEdit = (role: Role) => {
    setEditingRole(role);
    setFormData({
      name: role.name,
      description: role.description,
      permissions: role.permissions,
    });
    setIsCreating(false);
  };

  if (isLoading) return <div>Loading roles...</div>;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <h2 className="text-2xl font-bold text-gray-900">Roles & Permissions</h2>
        <button
          onClick={() => {
            setIsCreating(true);
            setEditingRole(null);
            resetForm();
          }}
          className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors"
        >
          Create New Role
        </button>
      </div>

      {/* Form Modal/Panel */}
      {(isCreating || editingRole) && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg shadow-xl max-w-4xl w-full max-h-[90vh] overflow-y-auto m-4">
            <div className="p-6">
              <h3 className="text-xl font-bold mb-4">
                {editingRole ? 'Edit Role' : 'Create New Role'}
              </h3>
              
              <form onSubmit={handleSubmit} className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Role Name</label>
                  <input
                    type="text"
                    value={formData.name}
                    onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                    className="w-full px-3 py-2 border rounded-md focus:ring-blue-500 focus:border-blue-500"
                    required
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Description</label>
                  <textarea
                    value={formData.description}
                    onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                    rows={3}
                    className="w-full px-3 py-2 border rounded-md focus:ring-blue-500 focus:border-blue-500"
                    required
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">Permissions</label>
                  <PermissionMatrix
                    selectedPermissions={formData.permissions}
                    onToggle={handleTogglePermission}
                  />
                </div>

                <div className="flex justify-end space-x-3 pt-4 border-t">
                  <button
                    type="button"
                    onClick={() => {
                      setIsCreating(false);
                      setEditingRole(null);
                      resetForm();
                    }}
                    className="px-4 py-2 text-gray-700 bg-gray-100 rounded-md hover:bg-gray-200"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={createMutation.isPending || updateMutation.isPending}
                    className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50"
                  >
                    {createMutation.isPending || updateMutation.isPending ? 'Saving...' : 'Save Role'}
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      )}

      {/* Roles Table */}
      <div className="bg-white rounded-lg shadow overflow-hidden">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Role</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Description</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Permissions</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Type</th>
              <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {roles?.map((role: Role) => (
              <tr key={role.id} className="hover:bg-gray-50">
                <td className="px-6 py-4 whitespace-nowrap">
                  <div className="text-sm font-medium text-gray-900">{role.name}</div>
                  {role.inherits_from && (
                    <div className="text-xs text-gray-500">Inherits: {role.inherits_from}</div>
                  )}
                </td>
                <td className="px-6 py-4">
                  <div className="text-sm text-gray-500">{role.description}</div>
                </td>
                <td className="px-6 py-4">
                  <span className="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-blue-100 text-blue-800">
                    {role.permissions.length} permissions
                  </span>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  {role.is_system ? (
                    <span className="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-red-100 text-red-800">
                      System
                    </span>
                  ) : (
                    <span className="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800">
                      Custom
                    </span>
                  )}
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                  {!role.is_system && (
                    <>
                      <button
                        onClick={() => startEdit(role)}
                        className="text-blue-600 hover:text-blue-900 mr-3"
                      >
                        Edit
                      </button>
                      <button
                        onClick={() => {
                          if (confirm(`Delete role "${role.name}"?`)) {
                            deleteMutation.mutate(role.id);
                          }
                        }}
                        className="text-red-600 hover:text-red-900"
                      >
                        Delete
                      </button>
                    </>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export const RoleAssignments: React.FC<{ userId: string }> = ({ userId }) => {
  const { data: roles } = useQuery({
    queryKey: ['user-roles', userId],
    queryFn: () =>
      api.get(`/admin/v2/rbac/users/${userId}/roles`).then(res => res.data),
  });

  return (
    <div className="mt-6">
      <h3 className="text-lg font-semibold mb-3">Assigned Roles</h3>
      {roles?.length === 0 ? (
        <p className="text-gray-500 text-sm">No roles assigned</p>
      ) : (
        <div className="space-y-2">
          {roles?.map((role: Role) => (
            <div
              key={role.id}
              className="flex items-center justify-between p-3 bg-gray-50 rounded-md"
            >
              <div>
                <p className="font-medium">{role.name}</p>
                <p className="text-xs text-gray-500">
                  {role.description}
                </p>
              </div>
              <span className="text-xs text-gray-400">
                {role.is_system ? 'System Role' : 'Custom Role'}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
