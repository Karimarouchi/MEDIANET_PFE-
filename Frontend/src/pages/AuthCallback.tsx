import React, { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import { apiUrl } from '../services/api';

const AuthCallback: React.FC = () => {
  const navigate = useNavigate();

  useEffect(() => {
    // Session cookies are set by the backend OAuth callback (HttpOnly).
    axios
      .get(apiUrl('/api/auth/me'), { withCredentials: true })
      .then(() => {
        window.location.replace('/');
      })
      .catch(async () => {
        try {
          await axios.post(apiUrl('/api/auth/refresh'), null, {
            withCredentials: true,
          });
          await axios.get(apiUrl('/api/auth/me'), { withCredentials: true });
          window.location.replace('/');
        } catch {
          navigate('/login?error=oauth_failed');
        }
      });
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
