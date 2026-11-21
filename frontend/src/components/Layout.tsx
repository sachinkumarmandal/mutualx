import { NavLink, Outlet } from 'react-router-dom';
import { useAuth } from '../lib/auth';

const link = ({ isActive }: { isActive: boolean }) =>
  `rounded-full px-4 py-2 text-sm font-semibold transition duration-200 ${isActive ? 'bg-navy-800 text-white shadow-md shadow-navy-900/20' : 'text-navy-800/70 hover:bg-white/70 hover:text-navy-800'}`;

function Logo() {
  return (
    <span className="flex items-center gap-2.5">
      <svg width="30" height="30" viewBox="0 0 32 32" aria-hidden="true">
        <rect width="32" height="32" rx="9" fill="#0f1f3d" />
        <circle cx="12.5" cy="16" r="6.5" fill="none" stroke="#34d399" strokeWidth="2.6" />
        <circle cx="19.5" cy="16" r="6.5" fill="none" stroke="#a7f3d0" strokeWidth="2.6" />
      </svg>
      <span className="font-display text-2xl tracking-tight">MutualX</span>
    </span>
  );
}

export default function Layout() {
  const { me } = useAuth();
  return (
    <div className="mx-auto flex min-h-screen w-full max-w-6xl flex-col px-4 pb-16 pt-5 sm:px-6">
      <header className="glass sticky top-3 z-20 mb-8 flex flex-wrap items-center justify-between gap-3 px-4 py-3 sm:px-5">
        <NavLink to="/" aria-label="MutualX home"><Logo /></NavLink>
        <nav aria-label="Main" className="flex items-center gap-1">
          <NavLink to="/" end className={link}>Mutuals</NavLink>
          {me?.user.role === 'admin' && <NavLink to="/security" className={link}>Security</NavLink>}
          <NavLink to="/account" className={link}>{me ? `@${me.user.username}` : 'Account'}</NavLink>
        </nav>
      </header>
      <main className="flex-1 animate-rise"><Outlet /></main>
      <footer className="mt-12 text-center text-xs text-navy-800/60">
        MutualX is not affiliated with Instagram or Meta. It never asks for your password and never scrapes.
      </footer>
    </div>
  );
}
