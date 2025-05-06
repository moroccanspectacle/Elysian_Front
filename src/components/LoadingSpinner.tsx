import { motion } from 'framer-motion';

interface LoadingSpinnerProps {
  size?: 'sm' | 'md' | 'lg';
  color?: 'primary' | 'white' | 'secondary';
}

export function LoadingSpinner({ size = 'md', color = 'primary' }: LoadingSpinnerProps) {
  const sizeMap = {
    sm: 'h-4 w-4',
    md: 'h-8 w-8',
    lg: 'h-12 w-12'
  };
  
  const colorMap = {
    primary: 'border-primary-500',
    white: 'border-white',
    secondary: 'border-secondary-500'
  };
  
  return (
    <motion.div 
      className={`rounded-full border-2 border-t-transparent ${sizeMap[size]} ${colorMap[color]}`}
      animate={{ rotate: 360 }}
      transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
    ></motion.div>
  );
}