import { useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api';
import { Empty, ErrorBanner, Loading, PageHeader, SearchBox, formatDate, useLoad } from '../components';
import type { AuditEvent } from '../types';

export function Audit() {
  const events = useLoad(() => api.get<{ events: AuditEvent[] }>('/api/audit?limit=1000'), []);
  const [filter, setFilter] = useState('');
  const [open, setOpen] = useState<number | null>(null);

  const needle = filter.trim().toLowerCase();
  const shown = (events.data?.events ?? []).filter(
    (e) => !needle || [e.actor, e.action, e.summary].some((v) => v.toLowerCase().includes(needle)),
  );

  return (
    <>
      <PageHeader title="Audit log" subtitle="Who did what, to whom. Entries are never changed or removed." />
      <div className="filters">
        <SearchBox placeholder="Filter by person, action or text" value={filter} onChange={setFilter} />
      </div>
      <ErrorBanner message={events.error} onRetry={events.reload} />
      {events.loading && !events.data && <Loading />}
      {events.data &&
        (shown.length === 0 ? (
          <Empty>No entries.</Empty>
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>When</th>
                  <th>Who</th>
                  <th>What</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {shown.map((e) => (
                  <tr key={e.id} className="clickable" onClick={() => setOpen(open === e.id ? null : e.id)}>
                    <td className="nowrap">{formatDate(e.createdAt)}</td>
                    <td>{e.actor}</td>
                    <td>
                      {e.targetType === 'user' && e.targetId ? (
                        <Link to={`/people/${e.targetId}`} onClick={(ev) => ev.stopPropagation()}>
                          {e.summary}
                        </Link>
                      ) : e.targetType === 'application' && e.targetId ? (
                        <Link to={`/apps/${e.targetId}`} onClick={(ev) => ev.stopPropagation()}>
                          {e.summary}
                        </Link>
                      ) : (
                        e.summary
                      )}
                      {open === e.id && Object.keys(e.details).length > 0 && (
                        <pre className="details">{JSON.stringify(e.details, null, 2)}</pre>
                      )}
                    </td>
                    <td>
                      <code>{e.action}</code>
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
