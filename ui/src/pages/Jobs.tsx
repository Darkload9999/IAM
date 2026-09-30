import { useEffect } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { api } from '../api';
import { Badge, Empty, ErrorBanner, Loading, PageHeader, When, useAction, useLoad } from '../components';
import type { Job } from '../types';

const tones: Record<string, string> = { pending: 'warning', running: 'info', done: 'success', failed: 'danger' };

export function Jobs() {
  const [params, setParams] = useSearchParams();
  const status = params.get('status') ?? '';
  const jobs = useLoad(() => api.get<{ jobs: Job[] }>(`/api/jobs?status=${status}`), [status]);
  const retry = useAction();
  const { reload } = jobs;

  // Pushes finish within seconds; keep the list current while it is open.
  useEffect(() => {
    const timer = setInterval(reload, 5000);
    return () => clearInterval(timer);
  }, [reload]);

  return (
    <>
      <PageHeader
        title="Provisioning"
        subtitle="Every push to an application. Failures are retried with growing delays; those refused outright wait here for you."
      />
      <div className="tabs" role="tablist">
        {['', 'pending', 'failed', 'done'].map((s) => (
          <button
            key={s}
            role="tab"
            aria-selected={status === s}
            className={status === s ? 'tab active' : 'tab'}
            onClick={() => setParams(s ? { status: s } : {}, { replace: true })}
          >
            {s === '' ? 'All' : s[0].toUpperCase() + s.slice(1)}
          </button>
        ))}
      </div>
      <ErrorBanner message={jobs.error || retry.error} onRetry={jobs.error ? reload : undefined} />
      {jobs.loading && !jobs.data && <Loading />}
      {jobs.data &&
        (jobs.data.jobs.length === 0 ? (
          <Empty>No jobs here.</Empty>
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Person</th>
                  <th>Application</th>
                  <th>Push</th>
                  <th>Status</th>
                  <th>Attempts</th>
                  <th>Updated</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {jobs.data.jobs.map((j) => (
                  <tr key={j.id}>
                    <td>
                      <Link to={`/people/${j.userId}`}>{j.userEmail}</Link>
                    </td>
                    <td>
                      <Link to={`/apps/${j.appId}`} className="mono">
                        {j.appKey}
                      </Link>
                    </td>
                    <td>{j.operation === 'upsert' ? 'Create or update' : 'Deactivate'}</td>
                    <td>
                      <Badge tone={tones[j.status]}>{j.status}</Badge>
                      {j.lastError && <div className="muted small error-text">{j.lastError}</div>}
                      {j.status === 'pending' && j.attempts > 0 && (
                        <div className="muted small">
                          next try <When at={j.nextRunAt} />
                        </div>
                      )}
                    </td>
                    <td>{j.attempts}</td>
                    <td>
                      <When at={j.updatedAt} />
                    </td>
                    <td className="row-actions">
                      {j.status === 'failed' && (
                        <button
                          className="btn btn-small"
                          disabled={retry.busy}
                          onClick={() => retry.run(() => api.post(`/api/jobs/${j.id}/retry`)).then(reload)}
                        >
                          Retry
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ))}
    </>
  );
}
