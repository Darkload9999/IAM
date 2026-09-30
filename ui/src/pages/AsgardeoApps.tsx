import { useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api';
import { RequiresAsgardeo } from '../asgardeo';
import { Badge, Empty, ErrorBanner, Loading, Modal, PageHeader, SearchBox, Section, useLoad } from '../components';
import { Icon } from '../icons';
import type { ConsoleApp } from '../types';

export function AsgardeoApps() {
  return (
    <RequiresAsgardeo module="applications">
      <AppList />
    </RequiresAsgardeo>
  );
}

function AppList() {
  const apps = useLoad(() => api.get<{ applications: ConsoleApp[] }>('/api/asgardeo/applications'), []);
  const [search, setSearch] = useState('');
  const [open, setOpen] = useState<string | null>(null);
  const shown = (apps.data?.applications ?? []).filter((a) => a.name.toLowerCase().includes(search.trim().toLowerCase()));

  return (
    <>
      <PageHeader
        title="Sign-in applications"
        subtitle="Applications registered in Asgardeo for single sign-on. Access to them is given under Applications."
      />
      <ErrorBanner message={apps.error} onRetry={apps.reload} />
      <div className="filters">
        <SearchBox value={search} onChange={setSearch} placeholder="Search applications" />
      </div>
      {!apps.data && apps.loading && <Loading />}
      {apps.data && (
        <Section title={`${shown.length} application${shown.length === 1 ? '' : 's'}`}>
          {shown.length === 0 ? (
            <Empty icon="apps">No applications match.</Empty>
          ) : (
            <div className="app-grid">
              {shown.map((a) => (
                <button key={a.id} className="card card-pad app-card clickable" onClick={() => setOpen(a.id)}>
                  <div className="app-card-head">
                    <span className="app-mark" aria-hidden="true">
                      {a.name.slice(0, 1).toUpperCase()}
                    </span>
                    <strong>{a.name}</strong>
                  </div>
                  <p className="muted small ellipsis">{a.accessUrl || a.description || 'No access URL'}</p>
                  {a.hubAppId ? <Badge tone="success">Managed in the Hub</Badge> : <Badge tone="neutral">Sign-in only</Badge>}
                </button>
              ))}
            </div>
          )}
        </Section>
      )}
      {open && <AppDialog id={open} onClose={() => setOpen(null)} />}
    </>
  );
}

function AppDialog({ id, onClose }: { id: string; onClose: () => void }) {
  const app = useLoad(() => api.get<{ application: ConsoleApp }>(`/api/asgardeo/applications/${id}`), [id]);
  const a = app.data?.application;
  return (
    <Modal title={a ? a.name : 'Application'} onClose={onClose} wide>
      <ErrorBanner message={app.error} onRetry={app.reload} />
      {!a && <Loading />}
      {a && (
        <>
          <dl className="facts">
            <dt>Access URL</dt>
            <dd>
              {a.accessUrl ? (
                <a href={a.accessUrl} target="_blank" rel="noreferrer">
                  {a.accessUrl} <Icon name="external" size={14} />
                </a>
              ) : (
                '—'
              )}
            </dd>
            <dt>Client ID</dt>
            <dd className="mono">{a.clientId || '—'}</dd>
            <dt>Type</dt>
            <dd>{a.publicClient ? 'Public client' : a.clientId ? 'Confidential client' : '—'}</dd>
            <dt>Grant types</dt>
            <dd>{a.grantTypes?.length ? a.grantTypes.join(', ') : '—'}</dd>
            <dt>Redirect URLs</dt>
            <dd>
              {a.redirectUrls?.length ? (
                <ul className="plain-list mono small">
                  {a.redirectUrls.map((u) => (
                    <li key={u}>{u}</li>
                  ))}
                </ul>
              ) : (
                '—'
              )}
            </dd>
            {!!a.allowedOrigins?.length && (
              <>
                <dt>Allowed origins</dt>
                <dd className="mono small">{a.allowedOrigins.join(', ')}</dd>
              </>
            )}
          </dl>
          <p className="muted small">
            {a.hubAppId ? (
              <>
                Access, roles and permissions for this application are managed in the Hub:{' '}
                <Link to={`/apps/${a.hubAppId}`}>open it</Link>.
              </>
            ) : (
              <>
                The Hub does not manage access to this application yet. Register it under{' '}
                <Link to="/apps">Applications</Link> to give people access with roles and permissions.
              </>
            )}{' '}
            Its sign-in settings are changed in the Asgardeo console.
          </p>
        </>
      )}
    </Modal>
  );
}
