export const validatePassword = (password: string): { valid: boolean; errors: string[] } => {
  const errors: string[] = [];
  
  // Check minimum length
  if (password.length < 8) {
    errors.push('Password must be at least 8 characters long');
  }
  
  // Check maximum length
  if (password.length > 100) {
    errors.push('Password cannot exceed 100 characters');
  }
  
  // Check for uppercase letter
  if (!/[A-Z]/.test(password)) {
    errors.push('Password must include at least one uppercase letter');
  }
  
  // Check for lowercase letter
  if (!/[a-z]/.test(password)) {
    errors.push('Password must include at least one lowercase letter');
  }
  
  // Check for a number
  if (!/\d/.test(password)) {
    errors.push('Password must include at least one number');
  }
  
  // Check for a special character
  if (!/[@$!%*?&]/.test(password)) {
    errors.push('Password must include at least one special character (@$!%*?&)');
  }
  
  return {
    valid: errors.length === 0,
    errors
  };
};

export const getPasswordStrength = (password: string): { 
  score: number; 
  label: string;
  color: string;
} => {
  if (!password) {
    return { score: 0, label: 'No Password', color: 'bg-gray-200' };
  }
  
  let score = 0;
  
  // Length
  if (password.length >= 8) score += 1;
  if (password.length >= 12) score += 1;
  
  // Complexity
  if (/[A-Z]/.test(password)) score += 1;
  if (/[a-z]/.test(password)) score += 1;
  if (/\d/.test(password)) score += 1;
  if (/[@$!%*?&]/.test(password)) score += 1;
  
  // Normalize to 0-5 scale
  score = Math.min(5, score);
  
  // Map score to label and color
  const strengthMap = [
    { label: 'Very Weak', color: 'bg-red-500' },
    { label: 'Weak', color: 'bg-orange-500' },
    { label: 'Fair', color: 'bg-yellow-500' },
    { label: 'Good', color: 'bg-blue-500' },
    { label: 'Strong', color: 'bg-green-500' },
    { label: 'Very Strong', color: 'bg-green-700' }
  ];
  
  return { 
    score, 
    ...strengthMap[score]
  };
};