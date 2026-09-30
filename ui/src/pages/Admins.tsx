import { useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api';
import { Confirm, Empty, ErrorBanner, Loading, Notice, PageHeader, Section, When, useAction, useLoad } from '../components';
import { useMe } from '../session';
import type { HubAdmin } from '../types';

export function Admins() {
  const me = useMe();
  const isOwner = me.role === 'owner';
  const admins = useLoad(() => api.get<{ owner: string; admins: HubAdmin[] }>('/api/admins'), []);
  const [email, setEmail] = useState('');
  const [removing, setRemoving] = useState<HubAdmin | null>(null);
  const add = useAction();

  return (
    <>
      <PageHeader title="Hub admins" subtitle="Who can use this dashboard." />
      <ErrorBanner message={admins.error} onRetry={admins.reload} />
      {!isOwner && <Notice kind="info">Only the organization owner can appoint or remove Hub admins.</Notice>}
      {admins.loading && !admins.data && <Loading />}
      {admins.data && (
        <>
          <Section title="Organization owner">
            <p>
              <strong>{admins.data.owner || 'Not synced yet'}</strong> — always a Hub admin, with every power, including
              appointing others. Ownership is changed in Asgardeo.
            </p>
          </Section>
          <Section title={`Appointed admins (${admins.data.admins.length})`}>
            {isOwner && (
              <form
                className="inline-form"
                onSubmit={(e) => {
                  e.preventDefault();
                  add.run(() => api.post('/api/admins', { email })).then((ok) => ok && (setEmail(''), admins.reload()));
                }}
              >
                <input
                  type="email"
                  required
                  placeholder="Email of someone in the organization"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  aria-label="Email"
                />
                <button className="btn btn-primary" disabled={add.busy}>
                  {add.busy ? 'Adding…' : 'Make Hub admin'}
                </button>
              </form>
            )}
            <ErrorBanner message={add.error} />
            {admins.data.admins.length === 0 ? (
              <Empty>No one besides the owner.</Empty>
            ) : (
              <table className="table table-compact">
                <tbody>
                  {admins.data.admins.map((a) => (
                    <tr key={a.userId}>
                      <td>
                        <Link to={`/people/${a.userId}`}>{a.name || a.email}</Link>
                        <div className="muted small">{a.email}</div>
                      </td>
                      <td className="muted small">
                        appointed by {a.addedBy} <When at={a.createdAt} />
                      </td>
                      <td className="row-actions">
                        {isOwner && (
                          <button className="btn btn-small btn-danger-quiet" onClick={() => setRemoving(a)}>
                            Remove
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Section>
        </>
      )}
      {removing && (
        <Confirm
          title={`Remove ${removing.email} as a Hub admin?`}
          message="They lose access to this dashboard at once. Their account and application access are not touched."
          confirmLabel="Remove"
          danger
          onConfirm={() => api.del(`/api/admins/${removing.userId}`).then(admins.reload)}
          onClose={() => setRemoving(null)}
        />
      )}
    </>
  );
}
