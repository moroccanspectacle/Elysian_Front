import React from 'react';

interface TabProps {
  active: boolean;
  onClick: () => void;
  label: string;
}

export function Tab({ active, onClick, label }: TabProps) {
  return (
    <button
      onClick={onClick}
      className={`py-2 px-4 ${
        active
          ? 'text-[#217eaa] font-medium border-b-2 border-[#217eaa]'
          : 'text-gray-600 hover:text-gray-800'
      }`}
    >
      {label}
    </button>
  );
}

export function Tabs({ children }: { children: React.ReactNode }) {
  return (
    <div className="border-b border-gray-200">
      <div className="flex space-x-4">
        {children}
      </div>
    </div>
  );
}