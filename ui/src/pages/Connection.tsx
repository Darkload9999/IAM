import { Link } from 'react-router-dom';
import { checkAgain, useCapabilities } from '../asgardeo';
import { Badge, ErrorBanner, Loading, PageHeader, Section } from '../components';
import { Icon, type IconName } from '../icons';
import { useMe } from '../session';

const pages: Record<string, { to: string; icon: IconName; what: string }> = {
  users: { to: '/people', icon: 'people', what: 'Onboard, edit, suspend and offboard people; invitations.' },
  groups: { to: '/asgardeo/groups', icon: 'people', what: 'Create groups and manage their members.' },
  roles: { to: '/asgardeo/roles', icon: 'key', what: 'Organization and application roles, and who holds them.' },
  applications: { to: '/asgardeo/applications', icon: 'apps', what: 'Applications registered for sign-in: client ids, redirect URLs.' },
  sessions: { to: '/people', icon: 'clock', what: "See and end people's sign-in sessions (on each person's page)." },
  security: { to: '/asgardeo/security', icon: 'lock', what: 'Password rules, account locking and other login policies.' },
};

export function Connection() {
  const me = useMe();
  const caps = useCapabilities();
  const modules = caps.data?.modules ?? [];
  const enabled = modules.filter((m) => m.enabled).length;

  return (
    <>
      <PageHeader
        title="Asgardeo"
        subtitle={
          <>
            Everything the Hub manages in the <strong>{me.organization}</strong> organization, through its M2M application.
          </>
        }
        actions={
          <button className="btn" onClick={() => checkAgain(caps.reload)} disabled={caps.loading}>
            <Icon name="sync" size={16} />
            Check permissions again
          </button>
        }
      />
      <ErrorBanner message={caps.error} onRetry={caps.reload} />
      {!caps.data && caps.loading && <Loading />}
      {caps.data && (
        <Section title={`${enabled} of ${modules.length} areas available`}>
          <div className="module-grid">
            {modules.map((m) => {
              const page = pages[m.key];
              return (
                <div key={m.key} className={m.enabled ? 'module' : 'module module-off'}>
                  <div className="module-head">
                    <span className="module-icon" aria-hidden="true">
                      <Icon name={page?.icon ?? 'apps'} size={18} />
                    </span>
                    <strong>{m.name}</strong>
                    {m.enabled ? <Badge tone="success">Available</Badge> : <Badge tone="warning">Needs permission</Badge>}
                  </div>
                  <p className="muted small">{page?.what}</p>
                  <p className="small">
                    <span className="muted">Asgardeo API:</span> {m.api}
                  </p>
                  {m.enabled ? (
                    page && (
                      <Link className="card-link" to={page.to}>
                        Open <Icon name="chevron" size={14} />
                      </Link>
                    )
                  ) : (
                    <div className="small">
                      <span className="muted">Authorize the M2M application for {m.api} with:</span>
                      <div className="chips">
                        {m.missing.map((s) => (
                          <code key={s} className="chip mono">
                            {s}
                          </code>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </Section>
      )}
    </>
  );
}
