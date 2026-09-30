import { useEffect, useState } from 'react';
import { NavLink, Navigate, Route, Routes, useLocation } from 'react-router-dom';
import { api, setCsrfToken, signOut } from './api';
import { ErrorBanner, messageOf } from './components';
import { Icon, type IconName } from './icons';
import { SessionContext } from './session';
import type { Me } from './types';
import { Overview } from './pages/Overview';
import { People } from './pages/People';
import { Person } from './pages/Person';
import { Apps } from './pages/Apps';
import { AppDetail } from './pages/AppDetail';
import { Jobs } from './pages/Jobs';
import { Admins } from './pages/Admins';
import { Audit } from './pages/Audit';
import { Connection } from './pages/Connection';
import { Groups } from './pages/Groups';
import { AsgardeoRoles } from './pages/AsgardeoRoles';
import { AsgardeoApps } from './pages/AsgardeoApps';
import { Policies } from './pages/Policies';
import { CapabilitiesContext, useCapabilitiesLoader } from './asgardeo';

interface NavItem {
  to: string;
  label: string;
  icon: IconName;
  end?: boolean;
}

const sections: { heading: string; items: NavItem[] }[] = [
  {
    heading: 'Directory',
    items: [
      { to: '/', label: 'Overview', icon: 'overview', end: true },
      { to: '/people', label: 'People', icon: 'people' },
    ],
  },
  {
    heading: 'Access',
    items: [
      { to: '/apps', label: 'Applications', icon: 'apps' },
      { to: '/provisioning', label: 'Provisioning', icon: 'sync' },
    ],
  },
  {
    heading: 'Asgardeo',
    items: [
      { to: '/asgardeo', label: 'Connection', icon: 'link', end: true },
      { to: '/asgardeo/groups', label: 'Groups', icon: 'people' },
      { to: '/asgardeo/roles', label: 'Roles', icon: 'key' },
      { to: '/asgardeo/applications', label: 'Sign-in apps', icon: 'apps' },
      { to: '/asgardeo/security', label: 'Login & security', icon: 'lock' },
    ],
  },
  {
    heading: 'Governance',
    items: [
      { to: '/admins', label: 'Hub admins', icon: 'shield' },
      { to: '/audit', label: 'Audit log', icon: 'audit' },
    ],
  },
];

/** The section the current page belongs to, for the top bar. */
function currentSection(path: string): NavItem {
  const all = sections.flatMap((s) => s.items);
  // The longest match wins, so /asgardeo/groups is Groups, not Connection.
  const matches = all.filter((n) => (n.end ? path === n.to : path.startsWith(n.to)));
  return matches.sort((a, b) => b.to.length - a.to.length)[0] ?? all[0]!;
}

export function App() {
  const [me, setMe] = useState<Me | null>(null);
  const [error, setError] = useState('');
  const [menuOpen, setMenuOpen] = useState(false);
  const location = useLocation();
  const capabilities = useCapabilitiesLoader();

  useEffect(() => {
    api
      .get<Me>('/api/me')
      .then((m) => {
        setCsrfToken(m.csrfToken);
        setMe(m);
      })
      .catch((e) => setError(messageOf(e)));
  }, []);

  useEffect(() => {
    setMenuOpen(false);
    window.scrollTo(0, 0);
  }, [location.pathname]);

  if (!me) {
    return (
      <div className="boot">
        {error ? (
          <ErrorBanner message={error} onRetry={() => window.location.reload()} />
        ) : (
          <div className="boot-mark">
            <img src="/logo.png" alt="ZEIT26" width={220} height={36} />
            <span className="spinner" aria-hidden="true" />
          </div>
        )}
      </div>
    );
  }

  const section = currentSection(location.pathname);
  const initials = (me.name || me.email)
    .split(/[\s@.]+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((w) => w[0]!.toUpperCase())
    .join('');

  return (
    <SessionContext.Provider value={me}>
      <CapabilitiesContext.Provider value={capabilities}>
      <div className="shell">
        <aside className={menuOpen ? 'sidebar open' : 'sidebar'}>
          <div className="brand">
            <div className="brand-text">
              <img src="/logo.png" alt="ZEIT26" width={164} height={27} />
              <span>Identity Hub</span>
            </div>
            <button className="icon-btn menu-toggle" aria-label="Menu" onClick={() => setMenuOpen(!menuOpen)}>
              <Icon name={menuOpen ? 'x' : 'menu'} size={20} />
            </button>
          </div>
          <nav className="nav">
            {sections.map((section) => (
              <div className="nav-section" key={section.heading}>
                <span className="nav-heading">{section.heading}</span>
                {section.items.map((n) => (
                  <NavLink key={n.to} to={n.to} end={n.end}>
                    <Icon name={n.icon} />
                    {n.label}
                  </NavLink>
                ))}
              </div>
            ))}
          </nav>
          <div className="sidebar-foot">
            <div className="org">
              <Icon name="building" size={16} />
              <span>
                Asgardeo organization
                <strong>{me.organization}</strong>
              </span>
            </div>
          </div>
        </aside>

        <div className="main">
          <header className="topbar">
            <div className="topbar-title">
              <Icon name={section.icon} size={18} />
              <span>{section.label}</span>
            </div>
            <div className="topbar-user">
              <span className="org-pill" title="The Asgardeo organization this Hub manages">
                <span className="dot" aria-hidden="true" />
                {me.organization}
              </span>
              <span className="avatar avatar-sm" aria-hidden="true">
                {initials}
              </span>
              <span className="topbar-who">
                <strong>{me.name || me.email}</strong>
                <span>{me.role === 'owner' ? 'Organization owner' : 'Hub admin'}</span>
              </span>
              <button
                className="btn btn-ghost btn-small"
                onClick={() => signOut().catch((e) => setError(messageOf(e)))}
                title="Sign out"
              >
                <Icon name="logout" size={16} />
                <span className="hide-sm">Sign out</span>
              </button>
            </div>
          </header>
          <main className="content">
            <ErrorBanner message={error} />
            <Routes>
              <Route path="/" element={<Overview />} />
              <Route path="/people" element={<People />} />
              <Route path="/people/:id" element={<Person />} />
              <Route path="/apps" element={<Apps />} />
              <Route path="/apps/:id" element={<AppDetail />} />
              <Route path="/provisioning" element={<Jobs />} />
              <Route path="/admins" element={<Admins />} />
              <Route path="/audit" element={<Audit />} />
              <Route path="/asgardeo" element={<Connection />} />
              <Route path="/asgardeo/groups" element={<Groups />} />
              <Route path="/asgardeo/roles" element={<AsgardeoRoles />} />
              <Route path="/asgardeo/applications" element={<AsgardeoApps />} />
              <Route path="/asgardeo/security" element={<Policies />} />
              <Route path="/users" element={<Navigate to="/people" replace />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </main>
        </div>
      </div>
      </CapabilitiesContext.Provider>
    </SessionContext.Provider>
  );
}
