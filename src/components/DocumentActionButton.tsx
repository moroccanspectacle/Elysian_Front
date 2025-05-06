import React from 'react';
import { LucideIcon } from 'lucide-react';

interface DocumentActionButtonProps {
  icon: LucideIcon;
  label: string;
  onClick: () => void;
  variant?: 'primary' | 'secondary';
}

export function DocumentActionButton({ 
  icon: Icon, 
  label, 
  onClick, 
  variant = 'primary' 
}: DocumentActionButtonProps) {
  return (
    <button
      onClick={onClick}
      className={`px-4 py-2 rounded-lg transition-colors flex items-center ${
        variant === 'primary'
          ? 'bg-[#217eaa] text-white hover:bg-[#1a6389]'
          : 'bg-white border border-[#217eaa] text-[#217eaa] hover:bg-[#f0f7fc]'
      }`}
    >
      <Icon className="w-4 h-4 mr-2" />
      {label}
    </button>
  );
}