import { Navigate, Route, Routes } from 'react-router-dom';
import Layout from './components/Layout';
import { useAuth } from './lib/auth';
import Account from './pages/Account';
import Finder from './pages/Finder';
import Login from './pages/Login';
import Security from './pages/Security';

/** Post-login landing: admins go to the security dashboard, everyone else to their account. */
function AfterLogin() {
  const { me, loading } = useAuth();
  if (loading) return null;
  return <Navigate to={me?.user.role === 'admin' ? '/security' : me ? '/account' : '/login'} replace />;
}

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Finder />} />
        <Route path="security" element={<Security />} />
        <Route path="account" element={<Account />} />
        <Route path="login" element={<Login />} />
        <Route path="dashboard" element={<AfterLogin />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}
