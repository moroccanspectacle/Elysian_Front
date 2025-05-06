import React from 'react';
import { LucideIcon } from 'lucide-react';

interface EmptyStateProps {
  icon: LucideIcon;
  title: string;
  description: string;
  action?: React.ReactNode; // Add this line to accept an optional action prop
}

export function EmptyState({ icon: Icon, title, description, action }: EmptyStateProps) {
  return (
    <div className="flex flex-col items-center justify-center h-64 p-6">
      <Icon className="w-12 h-12 text-neutral-400 mb-4" />
      <h3 className="text-lg font-medium text-neutral-700 mb-1">{title}</h3>
      <p className="text-neutral-500 text-center max-w-md mb-4">{description}</p>
      {action && action} {/* Render the action if it's provided */}
    </div>
  );
}