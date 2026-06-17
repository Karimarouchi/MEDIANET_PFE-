import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import Layout from './components/Layout';
import Dashboard from './pages/Dashboard';
import Repositories from './pages/Repositories';
import Scans from './pages/Scans';
import Vulnerabilities from './pages/Vulnerabilities';
import SSLAnalysis from './pages/SSLAnalysis';
import ServerConfig from './pages/ServerConfig';
import ServerConfigDetail from './pages/ServerConfigDetail';
import Pipeline from './pages/PipelinePage';
import PipelineFormPage from './pages/PipelineFormPage';
import PipelineRunInspectorPage from './pages/PipelineRunInspectorPage';
import Login from './pages/Login';
import AuthCallback from './pages/AuthCallback';
import Profile from './pages/Profile';
import AdminPanel from './pages/AdminPanel';
import ClientDetail from './pages/ClientDetail';
import AdminUsersPage from './pages/admin/AdminUsersPage';
import AdminRolesPage from './pages/admin/AdminRolesPage';
import AdminProjectsPage from './pages/admin/AdminProjectsPage';
import { getFirstAllowedRoute } from './constants/access';

/** Protects all app routes — redirects to /login if not authenticated */
const ProtectedLayout: React.FC = () => {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen bg-surface-container-lowest flex items-center justify-center">
        <span className="material-symbols-outlined text-primary text-5xl animate-spin">progress_activity</span>
      </div>
    );
  }

  if (!user) return <Navigate to="/login" replace />;
  return <Layout />;
};

const RequirePermission: React.FC<{ permission: string; children: React.ReactElement }> = ({ permission, children }) => {
  const { user, loading, hasPermission } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen bg-surface-container-lowest flex items-center justify-center">
        <span className="material-symbols-outlined text-primary text-5xl animate-spin">progress_activity</span>
      </div>
    );
  }

  if (!user) return <Navigate to="/login" replace />;
  if (!hasPermission(permission)) {
    return <Navigate to={getFirstAllowedRoute(user.permissions)} replace />;
  }
  return children;
};

function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          {/* Public routes */}
          <Route path="/login" element={<Login />} />
          <Route path="/auth/callback" element={<AuthCallback />} />

          {/* Protected routes */}
          <Route element={<ProtectedLayout />}>
            <Route path="/" element={<RequirePermission permission="DASHBOARD"><Dashboard /></RequirePermission>} />
            <Route path="/repositories" element={<RequirePermission permission="REPOSITORIES"><Repositories /></RequirePermission>} />
            <Route path="/scans" element={<RequirePermission permission="SCANS"><Scans /></RequirePermission>} />
            <Route path="/vulnerabilities" element={<RequirePermission permission="VULNERABILITIES"><Vulnerabilities /></RequirePermission>} />
            <Route path="/ssl-analysis" element={<RequirePermission permission="SSL_ANALYSIS"><SSLAnalysis /></RequirePermission>} />
            <Route path="/server-config" element={<RequirePermission permission="SERVER_CONFIG"><ServerConfig /></RequirePermission>} />
            <Route path="/server-config/:id" element={<RequirePermission permission="SERVER_CONFIG"><ServerConfigDetail /></RequirePermission>} />
            <Route path="/pipeline" element={<RequirePermission permission="PIPELINE"><Pipeline /></RequirePermission>} />
            <Route path="/pipeline/new" element={<RequirePermission permission="PIPELINE"><PipelineFormPage /></RequirePermission>} />
            <Route path="/pipeline/:id/inspector" element={<RequirePermission permission="PIPELINE"><PipelineRunInspectorPage /></RequirePermission>} />
            <Route path="/profile" element={<RequirePermission permission="PROFILE"><Profile /></RequirePermission>} />
            <Route path="/admin" element={<AdminPanel />}>
              <Route index element={<Navigate to="projects" replace />} />
              <Route path="users" element={<AdminUsersPage />} />
              <Route path="roles" element={<AdminRolesPage />} />
              <Route path="projects" element={<AdminProjectsPage />} />
            </Route>
            <Route path="/admin/clients/:id" element={<ClientDetail />} />
          </Route>
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
}

export default App;
