import React, { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

const AuthCallback: React.FC = () => {
  const navigate = useNavigate();

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const token = params.get('token');

    if (token) {
      localStorage.setItem('vulnix_token', token);
      // Reload so AuthContext picks up the new token
      window.location.replace('/');
    } else {
      navigate('/login?error=no_token');
    }
  }, [navigate]);

  return (
    <div className="min-h-screen bg-surface-container-lowest flex items-center justify-center">
      <div className="flex flex-col items-center gap-4">
        <span className="material-symbols-outlined text-primary text-5xl animate-spin">progress_activity</span>
        <p className="text-on-surface-variant text-sm font-headline">Authentification en cours...</p>
      </div>
    </div>
  );
};

export default AuthCallback;
