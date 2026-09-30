import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api';
import { RequiresAsgardeo } from '../asgardeo';
import {
  Badge, Confirm, Empty, ErrorBanner, Field, Loading, Modal, Notice, PageHeader, SearchBox, Section, useAction, useLoad,
} from '../components';
import { Icon } from '../icons';
import type { ConsoleGroup, User } from '../types';

export function Groups() {
  return (
    <RequiresAsgardeo module="groups">
      <GroupList />
    </RequiresAsgardeo>
  );
}

function GroupList() {
  const groups = useLoad(() => api.get<{ groups: ConsoleGroup[] }>('/api/asgardeo/groups'), []);
  const [search, setSearch] = useState('');
  const [open, setOpen] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);

  const shown = (groups.data?.groups ?? []).filter((g) => g.name.toLowerCase().includes(search.trim().toLowerCase()));

  return (
    <>
      <PageHeader
        title="Groups"
        subtitle="Asgardeo groups: give roles to many people at once, or use them in login rules."
        actions={
          <button className="btn btn-primary" onClick={() => setCreating(true)}>
            <Icon name="plus" size={16} />
            New group
          </button>
        }
      />
      <ErrorBanner message={groups.error} onRetry={groups.reload} />
      <div className="filters">
        <SearchBox value={search} onChange={setSearch} placeholder="Search groups" />
      </div>
      {!groups.data && groups.loading && <Loading />}
      {groups.data && (
        <Section title={`${shown.length} group${shown.length === 1 ? '' : 's'}`}>
          {shown.length === 0 ? (
            <Empty icon="people">No groups{search ? ' match' : ' yet'}.</Empty>
          ) : (
            <table className="table">
              <thead>
                <tr>
                  <th>Group</th>
                  <th>Members</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {shown.map((g) => (
                  <tr key={g.id} className="clickable" onClick={() => setOpen(g.id)}>
                    <td>
                      <strong>{g.name}</strong>{' '}
                      {g.appName && <Badge tone="info">Access to {g.appName}</Badge>}
                    </td>
                    <td className="muted">
                      {g.members.length === 0
                        ? '—'
                        : g.members
                            .slice(0, 3)
                            .map((m) => m.name || m.email)
                            .join(', ') + (g.members.length > 3 ? ` +${g.members.length - 3}` : '')}
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
          title="New group"
          label="Group name"
          onClose={() => setCreating(false)}
          onSave={(name) =>
            api.post<{ group: ConsoleGroup }>('/api/asgardeo/groups', { name }).then((r) => {
              groups.reload();
              setOpen(r.group.id);
            })
          }
        />
      )}
      {open && <GroupDialog id={open} onClose={() => setOpen(null)} onChanged={groups.reload} />}
    </>
  );
}

function GroupDialog({ id, onClose, onChanged }: { id: string; onClose: () => void; onChanged: () => void }) {
  const group = useLoad(() => api.get<{ group: ConsoleGroup }>(`/api/asgardeo/groups/${id}`), [id]);
  const people = useLoad(() => api.get<{ users: User[] }>('/api/users'), []);
  const [adding, setAdding] = useState('');
  const [renaming, setRenaming] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const act = useAction();

  const g = group.data?.group;
  const candidates = useMemo(
    () =>
      (people.data?.users ?? []).filter(
        (u) => !u.locked && u.username.startsWith('DEFAULT/') && !g?.members.some((m) => m.asgardeoId === u.asgardeoId),
      ),
    [people.data, g],
  );
  const change = (action: () => Promise<unknown>) =>
    act.run(action).then((ok) => {
      if (ok) {
        group.reload();
        onChanged();
      }
    });

  return (
    <Modal title={g ? g.name : 'Group'} onClose={onClose} wide>
      <ErrorBanner message={group.error || act.error} onRetry={group.error ? group.reload : undefined} />
      {!g && <Loading />}
      {g && (
        <>
          {g.appId ? (
            <Notice kind="info">
              This is the access group of <Link to={`/apps/${g.appId}`}>{g.appName}</Link>. Its members follow the access
              given in the Hub: change them on each person's page.
            </Notice>
          ) : (
            <div className="member-bar">
              <select
                value={adding}
                onChange={(e) => setAdding(e.target.value)}
                aria-label="Add a member"
                disabled={act.busy}
              >
                <option value="">Add a member…</option>
                {candidates.map((u) => (
                  <option key={u.id} value={u.id}>
                    {[u.givenName, u.familyName].filter(Boolean).join(' ') || u.email} — {u.email}
                  </option>
                ))}
              </select>
              <button
                className="btn btn-primary"
                disabled={!adding || act.busy}
                onClick={() => change(() => api.put(`/api/asgardeo/groups/${id}/members/${adding}`)).then(() => setAdding(''))}
              >
                Add
              </button>
              <span className="spacer" />
              <button className="btn" onClick={() => setRenaming(true)}>
                <Icon name="edit" size={16} />
                Rename
              </button>
              <button className="btn btn-danger-quiet" onClick={() => setDeleting(true)}>
                <Icon name="trash" size={16} />
                Delete
              </button>
            </div>
          )}
          {g.members.length === 0 ? (
            <Empty>No members.</Empty>
          ) : (
            <table className="table table-compact">
              <tbody>
                {g.members.map((m) => (
                  <tr key={m.asgardeoId}>
                    <td>
                      {m.userId ? <Link to={`/people/${m.userId}`}>{m.name || m.email}</Link> : m.name}
                      <div className="muted small">{m.email}</div>
                    </td>
                    <td className="row-actions">
                      {!g.appId && m.userId && (
                        <button
                          className="btn btn-small btn-danger-quiet"
                          disabled={act.busy}
                          onClick={() => change(() => api.del(`/api/asgardeo/groups/${id}/members/${m.userId}`))}
                        >
                          Remove
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </>
      )}
      {renaming && g && (
        <NameDialog
          title="Rename group"
          label="Group name"
          initial={g.name}
          onClose={() => setRenaming(false)}
          onSave={(name) => api.patch(`/api/asgardeo/groups/${id}`, { name }).then(() => (group.reload(), onChanged()))}
        />
      )}
      {deleting && g && (
        <Confirm
          title={`Delete ${g.name}?`}
          message="The group is deleted in Asgardeo. Its members keep their accounts, but lose any role the group gave them."
          confirmLabel="Delete group"
          danger
          onConfirm={() => api.del(`/api/asgardeo/groups/${id}`).then(() => (onChanged(), onClose()))}
          onClose={() => setDeleting(false)}
        />
      )}
    </Modal>
  );
}

/** A one-field dialog: a name to create or rename something with. */
export function NameDialog({
  title,
  label,
  initial = '',
  onSave,
  onClose,
}: {
  title: string;
  label: string;
  initial?: string;
  onSave: (name: string) => Promise<unknown>;
  onClose: () => void;
}) {
  const [name, setName] = useState(initial);
  const { busy, error, run } = useAction();
  return (
    <Modal
      title={title}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose} disabled={busy}>
            Cancel
          </button>
          <button className="btn btn-primary" type="submit" form="name-dialog" disabled={busy || !name.trim()}>
            {busy ? 'Saving…' : 'Save'}
          </button>
        </>
      }
    >
      <form
        id="name-dialog"
        className="form"
        onSubmit={(e) => {
          e.preventDefault();
          run(() => onSave(name.trim())).then((ok) => ok && onClose());
        }}
      >
        <ErrorBanner message={error} />
        <Field label={label}>
          <input value={name} onChange={(e) => setName(e.target.value)} maxLength={100} required autoFocus />
        </Field>
      </form>
    </Modal>
  );
}
