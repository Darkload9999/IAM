import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api';
import { RequiresAsgardeo, useCapability } from '../asgardeo';
import {
  Badge, Confirm, Empty, ErrorBanner, Loading, Modal, Notice, PageHeader, SearchBox, Section, useAction, useLoad,
} from '../components';
import { Icon } from '../icons';
import { useMe } from '../session';
import type { ConsoleGroup, ConsoleRole, User } from '../types';
import { NameDialog } from './Groups';

export function AsgardeoRoles() {
  return (
    <RequiresAsgardeo module="roles">
      <RoleList />
    </RequiresAsgardeo>
  );
}

function RoleList() {
  const me = useMe();
  const isOwner = me.role === 'owner';
  const roles = useLoad(() => api.get<{ roles: ConsoleRole[] }>('/api/asgardeo/roles'), []);
  const [search, setSearch] = useState('');
  const [audience, setAudience] = useState('');
  const [open, setOpen] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);

  const shown = (roles.data?.roles ?? []).filter(
    (r) => r.name.toLowerCase().includes(search.trim().toLowerCase()) && (!audience || r.audience === audience),
  );

  return (
    <>
      <PageHeader
        title="Roles"
        subtitle="Asgardeo roles: sets of permissions to Asgardeo and to the organization's APIs."
        actions={
          isOwner && (
            <button className="btn btn-primary" onClick={() => setCreating(true)}>
              <Icon name="plus" size={16} />
              New role
            </button>
          )
        }
      />
      {!isOwner && <Notice kind="info">Only the organization owner can create roles or change who holds them.</Notice>}
      <ErrorBanner message={roles.error} onRetry={roles.reload} />
      <div className="filters">
        <SearchBox value={search} onChange={setSearch} placeholder="Search roles" />
        <select value={audience} onChange={(e) => setAudience(e.target.value)} aria-label="Audience">
          <option value="">Every audience</option>
          <option value="organization">Organization roles</option>
          <option value="application">Application roles</option>
        </select>
      </div>
      {!roles.data && roles.loading && <Loading />}
      {roles.data && (
        <Section title={`${shown.length} role${shown.length === 1 ? '' : 's'}`}>
          {shown.length === 0 ? (
            <Empty icon="key">No roles match.</Empty>
          ) : (
            <table className="table">
              <thead>
                <tr>
                  <th>Role</th>
                  <th>Audience</th>
                  <th>Permissions</th>
                  <th>Held by</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {shown.map((r) => (
                  <tr key={r.id} className="clickable" onClick={() => setOpen(r.id)}>
                    <td>
                      <strong>{r.name}</strong> {r.system && <Badge tone="neutral">Asgardeo</Badge>}
                    </td>
                    <td>
                      {r.audience === 'application' ? (
                        <Badge tone="info">App: {r.audienceOf || 'application'}</Badge>
                      ) : (
                        <Badge tone="accent">Organization</Badge>
                      )}
                    </td>
                    <td className="muted">{r.permissions.length}</td>
                    <td className="muted">
                      {r.users.length} people · {r.groups.length} groups
                    </td>
                    <td className="row-actions">
                      <Icon name="chevron" size={16} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Section>
      )}
      {creating && (
        <NameDialog
          title="New organization role"
          label="Role name"
          onClose={() => setCreating(false)}
          onSave={(name) =>
            api.post<{ role: ConsoleRole }>('/api/asgardeo/roles', { name }).then((r) => {
              roles.reload();
              setOpen(r.role.id);
            })
          }
        />
      )}
      {open && <RoleDialog id={open} onClose={() => setOpen(null)} onChanged={roles.reload} />}
    </>
  );
}

function RoleDialog({ id, onClose, onChanged }: { id: string; onClose: () => void; onChanged: () => void }) {
  const me = useMe();
  const isOwner = me.role === 'owner';
  const groupsOn = useCapability('groups')?.enabled;
  const role = useLoad(() => api.get<{ role: ConsoleRole }>(`/api/asgardeo/roles/${id}`), [id]);
  const people = useLoad(() => api.get<{ users: User[] }>('/api/users'), []);
  const groups = useLoad(
    () => (groupsOn ? api.get<{ groups: ConsoleGroup[] }>('/api/asgardeo/groups') : Promise.resolve({ groups: [] })),
    [groupsOn],
  );
  const [person, setPerson] = useState('');
  const [group, setGroup] = useState('');
  const [deleting, setDeleting] = useState(false);
  const act = useAction();

  const r = role.data?.role;
  const everyone = r?.system && r.name.toLowerCase() === 'everyone';
  const editable = isOwner && !everyone;
  const personCandidates = useMemo(
    () =>
      (people.data?.users ?? []).filter(
        (u) => !u.locked && u.username.startsWith('DEFAULT/') && !r?.users.some((m) => m.asgardeoId === u.asgardeoId),
      ),
    [people.data, r],
  );
  const groupCandidates = (groups.data?.groups ?? []).filter((g) => !r?.groups.some((x) => x.id === g.id));
  const change = (action: () => Promise<unknown>) =>
    act.run(action).then((ok) => {
      if (ok) {
        role.reload();
        onChanged();
      }
      return ok;
    });

  return (
    <Modal title={r ? r.name : 'Role'} onClose={onClose} wide>
      <ErrorBanner message={role.error || act.error} onRetry={role.error ? role.reload : undefined} />
      {!r && <Loading />}
      {r && (
        <>
          <p className="muted">
            {r.audience === 'application'
              ? `An application role of ${r.audienceOf || 'an application'}.`
              : 'An organization role.'}{' '}
            {everyone && 'Everybody in the organization holds it.'}
          </p>
          <div className="grid-2">
            <div>
              <h3 className="pick-heading">People ({r.users.length})</h3>
              {editable && (
                <div className="member-bar">
                  <select value={person} onChange={(e) => setPerson(e.target.value)} aria-label="Give to" disabled={act.busy}>
                    <option value="">Give to a person…</option>
                    {personCandidates.map((u) => (
                      <option key={u.id} value={u.id}>
                        {[u.givenName, u.familyName].filter(Boolean).join(' ') || u.email} — {u.email}
                      </option>
                    ))}
                  </select>
                  <button
                    className="btn btn-primary"
                    disabled={!person || act.busy}
                    onClick={() => change(() => api.put(`/api/asgardeo/roles/${id}/users/${person}`)).then(() => setPerson(''))}
                  >
                    Give
                  </button>
                </div>
              )}
              {r.users.length === 0 ? (
                <Empty>Nobody directly.</Empty>
              ) : (
                <ul className="mini-list row-list">
                  {r.users.map((u) => (
                    <li key={u.asgardeoId}>
                      <span>
                        {u.userId ? <Link to={`/people/${u.userId}`}>{u.name || u.email}</Link> : u.name}
                        <span className="muted small"> {u.email !== u.name ? u.email : ''}</span>
                      </span>
                      {editable && u.userId && (
                        <button
                          className="btn btn-small btn-danger-quiet"
                          disabled={act.busy}
                          onClick={() => change(() => api.del(`/api/asgardeo/roles/${id}/users/${u.userId}`))}
                        >
                          Take away
                        </button>
                      )}
                    </li>
                  ))}
                </ul>
              )}

              <h3 className="pick-heading">Groups ({r.groups.length})</h3>
              {editable && groupsOn && (
                <div className="member-bar">
                  <select value={group} onChange={(e) => setGroup(e.target.value)} aria-label="Give to group" disabled={act.busy}>
                    <option value="">Give to a group…</option>
                    {groupCandidates.map((g) => (
                      <option key={g.id} value={g.id}>
                        {g.name}
                      </option>
                    ))}
                  </select>
                  <button
                    className="btn btn-primary"
                    disabled={!group || act.busy}
                    onClick={() => change(() => api.put(`/api/asgardeo/roles/${id}/groups/${group}`)).then(() => setGroup(''))}
                  >
                    Give
                  </button>
                </div>
              )}
              {r.groups.length === 0 ? (
                <Empty>No groups.</Empty>
              ) : (
                <ul className="mini-list row-list">
                  {r.groups.map((g) => (
                    <li key={g.id}>
                      <span>{g.display}</span>
                      {editable && (
                        <button
                          className="btn btn-small btn-danger-quiet"
                          disabled={act.busy}
                          onClick={() => change(() => api.del(`/api/asgardeo/roles/${id}/groups/${g.id}`))}
                        >
                          Take away
                        </button>
                      )}
                    </li>
                  ))}
                </ul>
              )}
            </div>
            <div>
              <h3 className="pick-heading">Permissions ({r.permissions.length})</h3>
              {r.permissions.length === 0 ? (
                <Empty>No permissions yet. Add them to the role in the Asgardeo console.</Empty>
              ) : (
                <div className="chips">
                  {r.permissions.map((p) => (
                    <code key={p.id} className="chip mono" title={p.id}>
                      {p.display || p.id}
                    </code>
                  ))}
                </div>
              )}
            </div>
          </div>
          {isOwner && !r.system && (
            <div className="button-row">
              <button className="btn btn-danger-quiet" onClick={() => setDeleting(true)}>
                <Icon name="trash" size={16} />
                Delete role
              </button>
            </div>
          )}
        </>
      )}
      {deleting && r && (
        <Confirm
          title={`Delete ${r.name}?`}
          message="The role is deleted in Asgardeo, and everyone who held it loses its permissions."
          confirmLabel="Delete role"
          danger
          onConfirm={() => api.del(`/api/asgardeo/roles/${id}`).then(() => (onChanged(), onClose()))}
          onClose={() => setDeleting(false)}
        />
      )}
    </Modal>
  );
}
