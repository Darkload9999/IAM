import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api';
import { Empty, ErrorBanner, Loading, PageHeader, When, formatDate, useAction, useLoad } from '../components';
import { Icon, type IconName } from '../icons';
import { useMe } from '../session';
import type { AuditEvent, Job, Stats } from '../types';

interface OverviewData {
  stats: Stats;
  failedJobs: Job[];
  recentActivity: AuditEvent[];
}

export function Overview() {
  const me = useMe();
  const { data, error, loading, reload } = useLoad(() => api.get<OverviewData>('/api/overview'), []);
  const sync = useAction();

  const syncNow = async () => {
    if (await sync.run(() => api.post('/api/sync'))) reload();
  };

  const firstName = (me.name || me.email).split(/[\s@]/)[0];

  return (
    <>
      <PageHeader
        title={`Welcome back, ${firstName}`}
        subtitle={
          data ? (
            <>
              Identity and access for <strong>{me.organization}</strong> · last synced with Asgardeo{' '}
              <When at={data.stats.lastSyncedAt} />
            </>
          ) : (
            'Identity and access across ZEIT26'
          )
        }
        actions={
          <>
            <Link className="btn" to="/apps">
              <Icon name="apps" size={16} />
              Applications
            </Link>
            <button className="btn btn-primary" onClick={syncNow} disabled={sync.busy}>
              <Icon name="sync" size={16} className={sync.busy ? 'spin' : undefined} />
              {sync.busy ? 'Syncing…' : 'Sync with Asgardeo'}
            </button>
          </>
        }
      />
      <ErrorBanner message={error || sync.error} onRetry={error ? reload : undefined} />
      {loading && !data && <Loading />}
      {data && <Dashboard data={data} />}
    </>
  );
}

function Dashboard({ data }: { data: OverviewData }) {
  const { stats, failedJobs, recentActivity } = data;
  const active = Math.max(0, stats.users - stats.pending - stats.locked);

  return (
    <>
      <div className="kpis">
        <Kpi
          icon="people"
          label="People"
          value={stats.users}
          to="/people"
          foot={
            <>
              <span>{active} active</span>
              <span>{stats.pending} invited</span>
              <span className={stats.locked ? 'kpi-bad' : undefined}>{stats.locked} suspended</span>
            </>
          }
        />
        <Kpi
          icon="apps"
          label="Applications"
          value={stats.applications}
          to="/apps"
          foot={<span>Connected to the Hub</span>}
        />
        <Kpi
          icon="key"
          label="Access grants"
          value={stats.grants}
          foot={<span>People × applications</span>}
        />
        <Kpi
          icon="sync"
          label="Provisioning"
          value={stats.jobsFailed > 0 ? stats.jobsFailed : stats.jobsPending}
          valueTone={stats.jobsFailed > 0 ? 'bad' : undefined}
          valueSuffix={stats.jobsFailed > 0 ? 'failed' : 'waiting'}
          to={stats.jobsFailed > 0 ? '/provisioning?status=failed' : '/provisioning'}
          foot={
            stats.jobsFailed > 0 ? (
              <span className="kpi-bad">Needs a look</span>
            ) : stats.jobsPending > 0 ? (
              <span>Pushing now</span>
            ) : (
              <span className="kpi-good">Everything in sync</span>
            )
          }
        />
      </div>

      <div className="overview-grid">
        <section className="card card-flush">
          <div className="card-header card-header-pad">
            <h2>Recent activity</h2>
            <Link className="card-link" to="/audit">
              View audit log <Icon name="chevron" size={14} />
            </Link>
          </div>
          {recentActivity.length === 0 ? (
            <div className="card-pad">
              <Empty icon="audit">Nothing yet.</Empty>
            </div>
          ) : (
            <ul className="feed">
              {recentActivity.map((e) => (
                <li key={e.id}>
                  <span className="feed-icon">
                    <Icon name={activityIcon(e.action)} size={16} />
                  </span>
                  <div className="feed-body">
                    <div className="feed-summary">{e.summary}</div>
                    <div className="feed-meta">{e.actor}</div>
                  </div>
                  <span className="feed-time">
                    <When at={e.createdAt} />
                  </span>
                </li>
              ))}
            </ul>
          )}
        </section>

        <div className="overview-side">
          <section className="card">
            <div className="card-header">
              <h2>Needs attention</h2>
            </div>
            <ul className="checklist">
              <Check
                ok={stats.jobsFailed === 0}
                okText="No failed pushes"
                badText={`${stats.jobsFailed} push${stats.jobsFailed === 1 ? '' : 'es'} failed`}
                to="/provisioning?status=failed"
              />
              <Check
                ok={stats.pending === 0}
                okText="Everyone has set a password"
                badText={`${stats.pending} invitation${stats.pending === 1 ? '' : 's'} not accepted yet`}
                to="/people?status=pending"
                warn
              />
              <Check
                ok={stats.locked === 0}
                okText="No suspended accounts"
                badText={`${stats.locked} account${stats.locked === 1 ? '' : 's'} suspended`}
                to="/people?status=locked"
                warn
              />
            </ul>
            {failedJobs.length > 0 && (
              <ul className="mini-list">
                {failedJobs.slice(0, 4).map((j) => (
                  <li key={j.id}>
                    <Link to={`/people/${j.userId}`}>{j.userEmail}</Link>
                    <span className="muted"> → {j.appKey}</span>
                    <div className="error-text small">{j.lastError}</div>
                  </li>
                ))}
              </ul>
            )}
          </section>

          <section className="card">
            <div className="card-header">
              <h2>Organization</h2>
            </div>
            <dl className="props">
              <dt>Asgardeo organization</dt>
              <dd>
                <span className="dot" aria-hidden="true" /> Connected
              </dd>
              <dt>Owner</dt>
              <dd className="ellipsis">{stats.organizationOwner || '—'}</dd>
              <dt>Last sync</dt>
              <dd title={formatDate(stats.lastSyncedAt)}>
                <When at={stats.lastSyncedAt} />
              </dd>
              <dt>Access groups</dt>
              <dd>
                {stats.groupsEnabled ? (
                  'On'
                ) : (
                  <span className="muted" title="Authorize the Hub's M2M application for the SCIM2 Groups API in the Asgardeo console (Management APIs) to turn them on.">
                    Off · optional
                  </span>
                )}
              </dd>
            </dl>
          </section>
        </div>
      </div>
    </>
  );
}

function Kpi({
  icon,
  label,
  value,
  valueTone,
  valueSuffix,
  to,
  foot,
}: {
  icon: IconName;
  label: string;
  value: number;
  valueTone?: 'bad';
  valueSuffix?: string;
  to?: string;
  foot: ReactNode;
}) {
  const body = (
    <>
      <div className="kpi-head">
        <span className="kpi-label">{label}</span>
        <span className="kpi-icon">
          <Icon name={icon} size={16} />
        </span>
      </div>
      <div className={valueTone ? 'kpi-value kpi-bad' : 'kpi-value'}>
        {value}
        {valueSuffix && <span className="kpi-suffix">{valueSuffix}</span>}
      </div>
      <div className="kpi-foot">{foot}</div>
    </>
  );
  return to ? (
    <Link className="kpi" to={to}>
      {body}
    </Link>
  ) : (
    <div className="kpi">{body}</div>
  );
}

function Check({
  ok,
  okText,
  badText,
  to,
  warn,
}: {
  ok: boolean;
  okText: string;
  badText: string;
  to: string;
  warn?: boolean;
}) {
  return (
    <li className={ok ? 'check-ok' : warn ? 'check-warn' : 'check-bad'}>
      <Icon name={ok ? 'check' : 'alert'} size={16} />
      {ok ? <span>{okText}</span> : <Link to={to}>{badText}</Link>}
    </li>
  );
}

function activityIcon(action: string): IconName {
  const kind = action.split('.')[0];
  switch (kind) {
    case 'user':
      return 'people';
    case 'access':
    case 'permission':
    case 'role':
      return 'key';
    case 'app':
      return 'apps';
    case 'admin':
      return 'shield';
    case 'auth':
      return action === 'auth.denied' ? 'alert' : 'logout';
    case 'sync':
      return 'sync';
    case 'job':
      return 'clock';
    default:
      return 'audit';
  }
}

export function ActivityList({ events }: { events: AuditEvent[] }) {
  if (events.length === 0) return <Empty icon="audit">Nothing yet.</Empty>;
  return (
    <ul className="list">
      {events.map((e) => (
        <li key={e.id}>
          <div>
            <div>{e.summary}</div>
            <div className="muted small">{e.actor}</div>
          </div>
          <When at={e.createdAt} />
        </li>
      ))}
    </ul>
  );
}
