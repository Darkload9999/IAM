import { useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { api } from '../api';
import {
  AccountTypeBadge, Avatar, Checkbox, Empty, ErrorBanner, Field, Loading, Modal, Notice, PageHeader,
  SearchBox, UserStatusBadge, displayName, toggle, useAction, useLoad,
} from '../components';
import { Icon } from '../icons';
import { AccessDialog } from './AccessEditor';
import type { CatalogApp, User } from '../types';

export function People() {
  const [params, setParams] = useSearchParams();
  const search = params.get('search') ?? '';
  const status = params.get('status') ?? '';
  const app = params.get('app') ?? '';
  const [draft, setDraft] = useState(search);
  const [onboarding, setOnboarding] = useState(false);
  const [managing, setManaging] = useState<User | null>(null);

  const query = new URLSearchParams({ search, status, app }).toString();
  const users = useLoad(() => api.get<{ users: User[] }>('/api/users?' + query), [query]);
  const catalog = useLoad(() => api.get<{ apps: CatalogApp[] }>('/api/catalog'), []);

  const setParam = (key: string, value: string) => {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    setParams(next, { replace: true });
  };

  return (
    <>
      <PageHeader
        title="People"
        subtitle="Every account in the Asgardeo organization, and what each can use."
        actions={
          <button className="btn btn-primary" onClick={() => setOnboarding(true)}>
            <Icon name="plus" size={16} />
            Onboard a person
          </button>
        }
      />
      <form
        className="filters"
        onSubmit={(e) => {
          e.preventDefault();
          setParam('search', draft.trim());
        }}
      >
        <SearchBox
          placeholder="Search by name or email"
          value={draft}
          onChange={setDraft}
          onCommit={() => draft.trim() !== search && setParam('search', draft.trim())}
        />
        <select value={status} onChange={(e) => setParam('status', e.target.value)} aria-label="Status">
          <option value="">Current accounts</option>
          <option value="active">Active</option>
          <option value="pending">Invited</option>
          <option value="locked">Suspended</option>
          <option value="removed">Removed</option>
          <option value="all">Everyone, ever</option>
        </select>
        <select value={app} onChange={(e) => setParam('app', e.target.value)} aria-label="Application">
          <option value="">Any application</option>
          {catalog.data?.apps.map((a) => (
            <option key={a.id} value={a.id}>
              Has {a.name}
            </option>
          ))}
        </select>
      </form>

      <ErrorBanner message={users.error} onRetry={users.reload} />
      {users.loading && !users.data && <Loading />}
      {users.data &&
        (users.data.users.length === 0 ? (
          <Empty icon="search">No one matches these filters.</Empty>
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Person</th>
                  <th>Status</th>
                  <th>Department</th>
                  <th>Applications</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {users.data.users.map((u) => (
                  <tr key={u.id}>
                    <td>
                      <Link className="person" to={`/people/${u.id}`}>
                        <Avatar user={u} />
                        <span>
                          <span className="person-name">
                            {displayName(u)} <AccountTypeBadge type={u.accountType} />
                          </span>
                          <span className="muted small">{u.email}</span>
                        </span>
                      </Link>
                    </td>
                    <td>
                      <UserStatusBadge user={u} />
                    </td>
                    <td>{u.department || <span className="muted">—</span>}</td>
                    <td>
                      <div className="chips">
                        {(u.apps ?? []).map((k) => (
                          <span className="chip" key={k}>
                            {k}
                          </span>
                        ))}
                        {(u.apps ?? []).length === 0 && <span className="muted">None</span>}
                      </div>
                    </td>
                    <td className="row-actions">
                      {!u.removedAt && (
                        <button className="btn btn-small" onClick={() => setManaging(u)}>
                          <Icon name="key" size={14} />
                          Manage access
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ))}

      {onboarding && <OnboardDialog apps={catalog.data?.apps ?? []} onClose={() => setOnboarding(false)} />}
      {managing && (
        <AccessDialog
          user={managing}
          apps={catalog.data?.apps ?? []}
          onClose={() => {
            setManaging(null);
            users.reload();
          }}
        />
      )}
    </>
  );
}

interface AccessChoice {
  appId: string;
  roleIds: string[];
  permissionIds: string[];
}

function OnboardDialog({ apps, onClose }: { apps: CatalogApp[]; onClose: () => void }) {
  const navigate = useNavigate();
  const [form, setForm] = useState({ givenName: '', familyName: '', email: '', department: '' });
  const [access, setAccess] = useState<AccessChoice[]>([]);
  const [result, setResult] = useState<{ user: User; invitation: string; warning?: string } | null>(null);
  const { busy, error, run } = useAction();

  const set = (key: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement>) =>
    setForm({ ...form, [key]: e.target.value });
  const choice = (appId: string) => access.find((a) => a.appId === appId);

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    run(async () => {
      const r = await api.post<{ user: User; invitation: string; warning?: string }>('/api/users', {
        ...form,
        access: access.map((a) => ({ appId: a.appId, roleIds: a.roleIds, permissionIds: a.permissionIds })),
      });
      setResult(r);
    });
  };

  if (result) {
    return (
      <Modal
        title="Person onboarded"
        onClose={onClose}
        footer={
          <button className="btn btn-primary" onClick={() => navigate(`/people/${result.user.id}`)}>
            Open {displayName(result.user)}
          </button>
        }
      >
        {result.invitation === 'SENT' ? (
          <Notice kind="success">
            Asgardeo emailed <strong>{result.user.email}</strong> a link to set their password.
          </Notice>
        ) : (
          <Notice kind="info">
            Asgardeo already had an account for <strong>{result.user.email}</strong>, so no invitation was sent. The
            Hub is now managing that account.
          </Notice>
        )}
        {result.warning && <Notice kind="warning">{result.warning}</Notice>}
        {access.length > 0 && <p>Their access is being pushed to the applications now.</p>}
      </Modal>
    );
  }

  return (
    <Modal
      title="Onboard a person"
      onClose={onClose}
      wide
      footer={
        <>
          <button className="btn" type="button" onClick={onClose} disabled={busy}>
            Cancel
          </button>
          <button className="btn btn-primary" type="submit" form="onboard" disabled={busy}>
            {busy ? 'Creating…' : 'Create account and invite'}
          </button>
        </>
      }
    >
      <form id="onboard" onSubmit={submit} className="form">
        <ErrorBanner message={error} />
        <div className="form-row">
          <Field label="First name">
            <input required value={form.givenName} onChange={set('givenName')} autoFocus />
          </Field>
          <Field label="Last name">
            <input value={form.familyName} onChange={set('familyName')} />
          </Field>
        </div>
        <Field label="Work email" hint="Asgardeo sends the invitation here; it is also their username.">
          <input type="email" required value={form.email} onChange={set('email')} />
        </Field>
        <Field label="Department">
          <input value={form.department} onChange={set('department')} />
        </Field>

        <fieldset className="fieldset">
          <legend>Access</legend>
          {apps.length === 0 && <p className="muted">No applications registered yet. You can give access later.</p>}
          {apps.map((app) => {
            const c = choice(app.id);
            return (
              <div key={app.id} className="access-pick">
                <Checkbox
                  checked={!!c}
                  onChange={(on) =>
                    setAccess(
                      on
                        ? [...access, { appId: app.id, roleIds: [], permissionIds: [] }]
                        : access.filter((a) => a.appId !== app.id),
                    )
                  }
                  label={app.name}
                  description={app.description}
                />
                {c && app.roles.length > 0 && (
                  <div className="access-roles">
                    <h4 className="pick-heading">Roles</h4>
                    {app.roles.map((r) => (
                      <Checkbox
                        key={r.id}
                        checked={c.roleIds.includes(r.id)}
                        onChange={(on) =>
                          setAccess(
                            access.map((a) => (a.appId === app.id ? { ...a, roleIds: toggle(a.roleIds, r.id, on) } : a)),
                          )
                        }
                        label={r.name}
                        description={r.key}
                      />
                    ))}
                  </div>
                )}
                {c && app.permissions.length > 0 && (
                  <div className="access-roles">
                    <h4 className="pick-heading">Extra permissions</h4>
                    {app.permissions.map((p) => {
                      const viaRole = app.roles.some((r) => c.roleIds.includes(r.id) && r.permissionIds.includes(p.id));
                      return (
                        <Checkbox
                          key={p.id}
                          checked={viaRole || c.permissionIds.includes(p.id)}
                          disabled={viaRole}
                          onChange={(on) =>
                            setAccess(
                              access.map((a) =>
                                a.appId === app.id ? { ...a, permissionIds: toggle(a.permissionIds, p.id, on) } : a,
                              ),
                            )
                          }
                          label={<code>{p.key}</code>}
                          description={viaRole ? `${p.name} — through a role` : p.name}
                        />
                      );
                    })}
                  </div>
                )}
              </div>
            );
          })}
        </fieldset>
      </form>
    </Modal>
  );
}
