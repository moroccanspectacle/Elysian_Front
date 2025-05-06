import React, { useState, useEffect, useRef } from 'react';
import { X, AlertCircle } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

interface PinEntryModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (pin: string, selfDestruct?: boolean, destructAfter?: Date | null) => Promise<void>; // Update onSubmit signature
  title: string;
  description: string;
  errorMessage?: string | null;
}

export function PinEntryModal({
  isOpen,
  onClose,
  onSubmit,
  title,
  description,
  errorMessage,
}: PinEntryModalProps) {
  const [pin, setPin] = useState<string[]>(Array(6).fill(''));
  const [localError, setLocalError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  // --- Add state for self-destruct ---
  const [enableSelfDestruct, setEnableSelfDestruct] = useState(false);
  const [destructDate, setDestructDate] = useState<string>(''); // Store as string for input
  // --- End Add state ---
  const inputRefs = useRef<(HTMLInputElement | null)[]>([]);

  // Reset state when modal opens/closes
  useEffect(() => {
    if (isOpen) {
      setPin(Array(6).fill(''));
      setLocalError(null);
      setIsSubmitting(false);
      // --- Reset self-destruct state ---
      setEnableSelfDestruct(false);
      setDestructDate('');
      // --- End Reset ---
      inputRefs.current[0]?.focus();
    }
  }, [isOpen]);

  // Clear local error when errorMessage prop changes
  useEffect(() => {
    setLocalError(errorMessage || null);
  }, [errorMessage]);

  const handleChange = (index: number, value: string) => {
    if (value && !/^\d+$/.test(value)) return; // Allow only numbers

    const newPin = [...pin];
    newPin[index] = value;
    setPin(newPin);
    setLocalError(null); // Clear error on input change

    if (value && index < 5) {
      inputRefs.current[index + 1]?.focus();
    }
  };

  const handleKeyDown = (index: number, e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Backspace' && !pin[index] && index > 0) {
      inputRefs.current[index - 1]?.focus();
    }
  };

  const handlePaste = (e: React.ClipboardEvent<HTMLInputElement>) => {
    e.preventDefault();
    const pastedData = e.clipboardData.getData('text').trim();
    if (/^\d{6}$/.test(pastedData)) {
      const digits = pastedData.split('');
      setPin(digits);
      inputRefs.current[5]?.focus(); // Focus last input after paste
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const enteredPin = pin.join('');
    if (enteredPin.length !== 6) {
      setLocalError('PIN must be 6 digits.');
      return;
    }

    // --- Validate destruct date if self-destruct is enabled ---
    let destructDateObj: Date | null = null;
    if (enableSelfDestruct) {
      if (!destructDate) {
        setLocalError('Please select a self-destruct date and time.');
        return;
      }
      destructDateObj = new Date(destructDate);
      if (isNaN(destructDateObj.getTime()) || destructDateObj <= new Date()) {
        setLocalError('Self-destruct date must be in the future.');
        return;
      }
    }
    // --- End Validation ---

    setIsSubmitting(true);
    setLocalError(null); // Clear local error before submitting

    try {
      // Pass self-destruct options to onSubmit
      await onSubmit(enteredPin, enableSelfDestruct, destructDateObj);
      // No need to call onClose here, parent component handles it on success
    } catch (error: any) {
      setLocalError(error.message || 'An unexpected error occurred.');
    } finally {
      setIsSubmitting(false);
    }
  };

  // --- Get minimum date for date input (tomorrow) ---
  const getMinDate = () => {
    const today = new Date();
    today.setDate(today.getDate() + 1); // Start from tomorrow
    return today.toISOString().split('T')[0]; // Format as YYYY-MM-DD
  };
  // --- End Min Date ---

  if (!isOpen) return null;

  return (
    <AnimatePresence>
      {isOpen && (
        <div className="fixed inset-0 bg-black bg-opacity-60 flex items-center justify-center z-50 p-4 backdrop-blur-sm">
          <motion.div
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.9 }}
            className="bg-white rounded-lg p-6 w-full max-w-md relative shadow-xl"
          >
            <button
              onClick={onClose}
              className="absolute top-3 right-3 text-gray-400 hover:text-gray-600"
              aria-label="Close modal"
            >
              <X size={20} />
            </button>

            <h2 className="text-xl font-semibold text-gray-800 mb-2">{title}</h2>
            <p className="text-sm text-gray-600 mb-6">{description}</p>

            {localError && (
              <div className="mb-4 p-3 bg-red-50 border border-red-200 text-red-700 rounded-md flex items-center text-sm">
                <AlertCircle className="w-5 h-5 mr-2 flex-shrink-0" />
                {localError}
              </div>
            )}

            <form onSubmit={handleSubmit}>
              <label className="block text-sm font-medium text-gray-700 mb-2">Enter 6-Digit PIN</label>
              <div className="grid grid-cols-6 gap-2 mb-6">
                {pin.map((digit, index) => (
                  <input
                    key={index}
                    ref={(el) => (inputRefs.current[index] = el)}
                    type="text" // Use text to allow single digit input easily
                    inputMode="numeric"
                    maxLength={1}
                    value={digit}
                    onChange={(e) => handleChange(index, e.target.value)}
                    onKeyDown={(e) => handleKeyDown(index, e)}
                    onPaste={index === 0 ? handlePaste : undefined} // Only allow paste in the first input
                    className="w-full aspect-square rounded-lg border border-gray-300 text-center text-lg focus:outline-none focus:ring-2 focus:ring-primary-500 disabled:bg-gray-100"
                    disabled={isSubmitting}
                  />
                ))}
              </div>

              {/* --- Add Self-Destruct Controls --- */}
              <div className="mb-6 border-t pt-4">
                <label className="flex items-center space-x-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={enableSelfDestruct}
                    onChange={(e) => setEnableSelfDestruct(e.target.checked)}
                    className="rounded text-primary-600 focus:ring-primary-500"
                    disabled={isSubmitting}
                  />
                  <span className="text-sm font-medium text-gray-700">Enable Self-Destruct</span>
                </label>
                {enableSelfDestruct && (
                  <div className="mt-3">
                    <label htmlFor="destructDate" className="block text-xs text-gray-600 mb-1">
                      Destruct Date & Time
                    </label>
                    <input
                      type="datetime-local"
                      id="destructDate"
                      value={destructDate}
                      onChange={(e) => setDestructDate(e.target.value)}
                      min={getMinDate() + 'T00:00'} // Set min date and time
                      className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary-500"
                      disabled={isSubmitting}
                      required // Make required if checkbox is checked
                    />
                    <p className="text-xs text-gray-500 mt-1">The file will be permanently deleted after this time.</p>
                  </div>
                )}
              </div>
              {/* --- End Self-Destruct Controls --- */}

              <div className="flex justify-end space-x-3">
                <button
                  type="button"
                  onClick={onClose}
                  disabled={isSubmitting}
                  className="px-4 py-2 text-sm text-gray-600 hover:bg-gray-100 rounded-md disabled:opacity-50"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting || pin.join('').length !== 6}
                  className="bg-primary-600 text-white px-4 py-2 text-sm rounded-md hover:bg-primary-700 disabled:opacity-50 flex items-center justify-center min-w-[80px]"
                >
                  {isSubmitting ? (
                    <div className="animate-spin rounded-full h-4 w-4 border-t-2 border-b-2 border-white"></div>
                  ) : (
                    'Confirm'
                  )}
                </button>
              </div>
            </form>
          </motion.div>
        </div>
      )}
    </AnimatePresence>
  );
}