
import React from 'react';
import { GoogleIcon, AppleIcon, XCircleIcon } from './icons';

interface SocialAccountSelectorModalProps {
    provider: 'google' | 'apple';
    onClose: () => void;
    onSelect: (email: string, name: string) => void;
}

export const SocialAccountSelectorModal: React.FC<SocialAccountSelectorModalProps> = ({ provider, onClose, onSelect }) => {
    return (
        <div className="fixed inset-0 bg-black bg-opacity-60 flex items-center justify-center z-50 p-4 animate-in fade-in duration-200">
            <div className="bg-white rounded-xl shadow-2xl w-full max-w-md overflow-hidden transform transition-all scale-100">
                <div className="p-6">
                    <div className="flex justify-between items-center mb-6">
                        <div className="flex items-center gap-2">
                            {provider === 'google' ? <GoogleIcon /> : <AppleIcon />}
                            <span className="font-semibold text-gray-700">Sign in with {provider === 'google' ? 'Google' : 'Apple'}</span>
                        </div>
                        <button onClick={onClose} className="text-gray-400 hover:text-gray-600 transition-colors">
                            <XCircleIcon className="w-6 h-6" />
                        </button>
                    </div>

                    <div className="text-center py-8 text-gray-600">
                        <p className="mb-4">
                            Social authentication is not configured in this environment.
                        </p>
                        <p className="text-sm">
                            Please sign in using your email and password.
                        </p>
                    </div>
                </div>
            </div>
        </div>
    );
};
