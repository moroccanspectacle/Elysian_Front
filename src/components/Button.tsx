import React from 'react';
import { motion } from 'framer-motion';
import { LoadingSpinner } from './LoadingSpinner';

interface ButtonProps {
  children: React.ReactNode;
  variant?: 'primary' | 'secondary' | 'outline' | 'danger';
  size?: 'sm' | 'md' | 'lg';
  isLoading?: boolean;
  disabled?: boolean;
  icon?: React.ReactNode;
  fullWidth?: boolean;
  onClick?: () => void;
  type?: 'button' | 'submit' | 'reset';
}

export function Button({
  children,
  variant = 'primary',
  size = 'md',
  isLoading = false,
  disabled = false,
  icon,
  fullWidth = false,
  onClick,
  type = 'button'
}: ButtonProps) {
  const baseClasses = "rounded-lg font-medium flex items-center justify-center transition-all";
  
  const variantClasses = {
    primary: "bg-gradient-to-r from-primary-500 to-secondary-500 hover:from-primary-600 hover:to-secondary-600 text-white shadow-sm hover:shadow-md",
    secondary: "bg-white text-primary-600 border border-primary-200 hover:border-primary-300 hover:bg-neutral-50 shadow-sm",
    outline: "bg-transparent text-primary-600 border border-primary-200 hover:bg-primary-50",
    danger: "bg-red-500 text-white hover:bg-red-600"
  };
  
  const sizeClasses = {
    sm: "text-sm px-3 py-1.5",
    md: "px-4 py-2",
    lg: "text-lg px-6 py-3"
  };
  
  return (
    <motion.button
      type={type}
      onClick={onClick}
      disabled={disabled || isLoading}
      className={`
        ${baseClasses}
        ${variantClasses[variant]}
        ${sizeClasses[size]}
        ${fullWidth ? 'w-full' : ''}
        ${disabled ? 'opacity-50 cursor-not-allowed' : ''}
      `}
      whileTap={{ scale: disabled || isLoading ? 1 : 0.95 }}
      whileHover={disabled || isLoading ? {} : { y: -2, boxShadow: "0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)" }}
    >
      {isLoading ? (
        <>
          <LoadingSpinner size="sm" color={variant === 'primary' || variant === 'danger' ? 'white' : 'primary'} />
          <span className="ml-2">{children}</span>
        </>
      ) : (
        <>
          {icon && <span className="mr-2">{icon}</span>}
          {children}
        </>
      )}
    </motion.button>
  );
}