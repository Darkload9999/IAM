import { useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { api } from '../api';
import {
  Checkbox, Confirm, Empty, ErrorBanner, Field, Loading, Modal, Notice, PageHeader, SecretReveal, Section,
  SyncBadge, When, displayName, toggle, useAction, useLoad,
} from '../components';
import { Icon } from '../icons';
import type { AppRole, Application, Grant, Permission, User } from '../types';

interface AppData {
  app: Application;
  permissions: Permission[];
  roles: AppRole[];
  users: User[];
  grants: Grant[];
  groupsEnabled: boolean;
}

export function AppDetail() {
  const { id = '' } = useParams();
  const navigate = useNavigate();
  const data = useLoad(() => api.get<AppData>(`/api/apps/${id}`), [id]);
  const [editing, setEditing] = useState(false);
  const [permission, setPermission] = useState<Permission | 'new' | null>(null);
  const [role, setRole] = useState<AppRole | 'new' | null>(null);
  const [removing, setRemoving] = useState<{ kind: 'app' | 'permission' | 'role'; id: string; label: string } | null>(null);
  const [token, setToken] = useState('');
  const [rotating, setRotating] = useState(false);
  const group = useAction();
  const check = useAction();
  const imported = useAction();
  const [checked, setChecked] = useState(false);
  const [importResult, setImportResult] = useState('');

  if (data.error && !data.data) return <ErrorBanner message={data.error} onRetry={data.reload} />;
  if (!data.data) return <Loading />;
  const { app, permissions, roles, users, grants, groupsEnabled } = data.data;
  const permissionKey = (pid: string) => permissions.find((p) => p.id === pid)?.key ?? '?';

  return (
    <>
      <p className="crumbs">
        <Link to="/apps">Applications</Link> /
      </p>
      <PageHeader
        title={app.name}
        subtitle={
          <>
            <span className="mono">{app.key}</span>
            {app.url && (
              <>
                {' · '}
                <a href={app.url} target="_blank" rel="noreferrer">
                  {app.url}
                </a>
              </>
            )}
          </>
        }
        actions={
          <>
            <button className="btn" onClick={() => setEditing(true)}>
              Settings
            </button>
            <button
              className="btn btn-danger"
              onClick={() => setRemoving({ kind: 'app', id: app.id, label: app.name })}
              disabled={app.userCount > 0}
              title={app.userCount > 0 ? 'Remove everybody’s access first' : undefined}
            >
              Remove
            </button>
          </>
        }
      />
      {app.description && <p className="lead">{app.description}</p>}
      <ErrorBanner message={data.error || group.error} />

      <div className="grid-2">
        <Section title="Provisioning">
          {app.scimUrl ? (
            <>
              <p>
                People, roles and permissions are pushed to <code className="wrap">{app.scimUrl}</code>.
              </p>
              {token && <SecretReveal label="New SCIM token" value={token} />}
              <div className="button-row">
                <button
                  className="btn btn-small"
                  disabled={check.busy}
                  onClick={async () => {
                    setChecked(false);
                    setChecked(await check.run(() => api.post(`/api/apps/${app.id}/test`)));
                  }}
                >
                  <Icon name="link" size={14} />
                  {check.busy ? 'Testing…' : 'Test connection'}
                </button>
                <button
                  className="btn btn-small"
                  disabled={imported.busy}
                  onClick={async () => {
                    setImportResult('');
                    await imported.run(async () => {
                      const r = await api.post<{ permissionsAdded: number; rolesAdded: number; rolesUpdated: number }>(
                        `/api/apps/${app.id}/import`,
                      );
                      setImportResult(
                        `Imported: ${r.permissionsAdded} new permission${r.permissionsAdded === 1 ? '' : 's'}, ` +
                          `${r.rolesAdded} new role${r.rolesAdded === 1 ? '' : 's'}, ${r.rolesUpdated} updated.`,
                      );
                      data.reload();
                    });
                  }}
                >
                  <Icon name="sync" size={14} className={imported.busy ? 'spin' : undefined} />
                  {imported.busy ? 'Importing…' : 'Import roles & permissions'}
                </button>
                {!token && (
                  <button className="btn btn-small" onClick={() => setRotating(true)}>
                    <Icon name="key" size={14} />
                    New token
                  </button>
                )}
              </div>
              {checked && !check.busy && (
                <p className="inline-result ok">
                  <Icon name="check" size={14} /> Connected: {app.name} accepts the Hub.
                </p>
              )}
              {check.error && (
                <p className="inline-result bad">
                  <Icon name="alert" size={14} /> {check.error}
                </p>
              )}
              {importResult && (
                <p className="inline-result ok">
                  <Icon name="check" size={14} /> {importResult}
                </p>
              )}
              {imported.error && (
                <p className="inline-result bad">
                  <Icon name="alert" size={14} /> {imported.error}
                </p>
              )}
            </>
          ) : (
            <p className="muted">
              Sign-in only: nothing is pushed. Add a provisioning endpoint in Settings to provision people.
            </p>
          )}
        </Section>
        <Section title="Asgardeo access group">
          {app.asgardeoGroupId ? (
            <p>
              Everybody with access is kept in the Asgardeo group <strong>{app.asgardeoGroupName}</strong>. Use it in
              Asgardeo to allow only them to sign in to {app.name}.
            </p>
          ) : groupsEnabled ? (
            <>
              <p className="muted">
                Optional: a group in Asgardeo holding everybody with access, for a sign-in policy on {app.name}.
              </p>
              <button
                className="btn btn-small"
                disabled={group.busy}
                onClick={() => group.run(() => api.post(`/api/apps/${app.id}/group`)).then((ok) => ok && data.reload())}
              >
                {group.busy ? 'Creating…' : `Create group app-${app.key}`}
              </button>
            </>
          ) : (
            <p className="muted">
              Not available: the Hub's M2M application is not authorized for the SCIM2 Groups API in Asgardeo.
            </p>
          )}
        </Section>
      </div>

      <Section
        title={`Permissions (${permissions.length})`}
        actions={
          <button className="btn btn-small" onClick={() => setPermission('new')}>
            Add permission
          </button>
        }
      >
        {permissions.length === 0 ? (
          <Empty>What can people do in {app.name}? Define it here, like projects:create or reports.view.</Empty>
        ) : (
          <table className="table table-compact">
            <tbody>
              {permissions.map((p) => (
                <tr key={p.id}>
                  <td>
                    <code>{p.key}</code>
                  </td>
                  <td>
                    {p.name}
                    {p.description && <div className="muted small">{p.description}</div>}
                  </td>
                  <td className="row-actions">
                    <button className="btn btn-small" onClick={() => setPermission(p)}>
                      Edit
                    </button>
                    <button
                      className="btn btn-small btn-danger-quiet"
                      onClick={() => setRemoving({ kind: 'permission', id: p.id, label: p.key })}
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Section>

      <Section
        title={`Roles (${roles.length})`}
        actions={
          <button className="btn btn-small" onClick={() => setRole('new')}>
            Add role
          </button>
        }
      >
        {roles.length === 0 ? (
          <Empty>Roles bundle permissions, like DEVELOPER or PROJECT_MANAGER.</Empty>
        ) : (
          <table className="table table-compact">
            <tbody>
              {roles.map((r) => (
                <tr key={r.id}>
                  <td>
                    <code>{r.key}</code>
                  </td>
                  <td>
                    {r.name}
                    <div className="chips">
                      {r.permissionIds.map((pid) => (
                        <span className="chip mono" key={pid}>
                          {permissionKey(pid)}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="row-actions">
                    <button className="btn btn-small" onClick={() => setRole(r)}>
                      Edit
                    </button>
                    <button
                      className="btn btn-small btn-danger-quiet"
                      onClick={() => setRemoving({ kind: 'role', id: r.id, label: r.key })}
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Section>

      <Section title={`People with access (${users.length})`}>
        {users.length === 0 ? (
          <Empty>No one yet. Give access from a person’s page.</Empty>
        ) : (
          <table className="table table-compact">
            <tbody>
              {users.map((u) => {
                const g = grants.find((x) => x.userId === u.id);
                return (
                  <tr key={u.id}>
                    <td>
                      <Link to={`/people/${u.id}`}>{displayName(u)}</Link>
                      <div className="muted small">{u.email}</div>
                    </td>
                    <td>
                      <div className="chips">
                        {g?.roleIds.map((rid) => (
                          <span className="chip mono" key={rid}>
                            {roles.find((r) => r.id === rid)?.key}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td>{g && <SyncBadge status={g.syncStatus} />}</td>
                    <td className="muted small">{g?.lastSyncedAt ? <>pushed <When at={g.lastSyncedAt} /></> : null}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </Section>

      {editing && <SettingsDialog app={app} onClose={() => setEditing(false)} onSaved={data.reload} />}
      {permission && (
        <PermissionDialog
          appId={app.id}
          permission={permission === 'new' ? null : permission}
          users={users.length}
          onClose={() => setPermission(null)}
          onSaved={data.reload}
        />
      )}
      {role && (
        <RoleDialog
          appId={app.id}
          role={role === 'new' ? null : role}
          permissions={permissions}
          users={users.length}
          onClose={() => setRole(null)}
          onSaved={data.reload}
        />
      )}
      {rotating && (
        <Confirm
          title="Issue a new SCIM token?"
          message={`The current token stops being sent at once. Pushes to ${app.name} fail until it is configured with the new one.`}
          confirmLabel="Issue new token"
          onConfirm={async () => setToken((await api.post<{ scimToken: string }>(`/api/apps/${app.id}/scim-token`)).scimToken)}
          onClose={() => setRotating(false)}
        />
      )}
      {removing && (
        <Confirm
          title={`Delete ${removing.label}?`}
          message={
            removing.kind === 'app'
              ? `${app.name} and its permissions and roles are removed from the Hub. Nothing changes in the application itself.`
              : `Everybody who has it through ${app.name} loses it, and the change is pushed to ${app.name}.`
          }
          confirmLabel="Delete"
          danger
          onConfirm={() =>
            removing.kind === 'app'
              ? api.del(`/api/apps/${app.id}`).then(() => navigate('/apps'))
              : api.del(`/api/apps/${app.id}/${removing.kind}s/${removing.id}`).then(data.reload)
          }
          onClose={() => setRemoving(null)}
        />
      )}
    </>
  );
}

function SettingsDialog({ app, onClose, onSaved }: { app: Application; onClose: () => void; onSaved: () => void }) {
  const [form, setForm] = useState({
    key: app.key, name: app.name, description: app.description, url: app.url, scimUrl: app.scimUrl, scimToken: '',
  });
  const { busy, error, run } = useAction();
  const set = (key: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) =>
    setForm({ ...form, [key]: e.target.value });
  return (
    <Modal
      title={`${app.name} settings`}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose} disabled={busy}>
            Cancel
          </button>
          <button className="btn btn-primary" type="submit" form="app-settings" disabled={busy}>
            {busy ? 'Saving…' : 'Save'}
          </button>
        </>
      }
    >
      <form
        id="app-settings"
        className="form"
        onSubmit={(e) => {
          e.preventDefault();
          run(() => api.patch(`/api/apps/${app.id}`, form)).then((ok) => ok && (onSaved(), onClose()));
        }}
      >
        <ErrorBanner message={error} />
        <Field label="Name">
          <input required value={form.name} onChange={set('name')} />
        </Field>
        <Field label="Description">
          <textarea rows={2} value={form.description} onChange={set('description')} />
        </Field>
        <Field label="Address people open">
          <input type="url" value={form.url} onChange={set('url')} />
        </Field>
        <Field label="Provisioning endpoint (SCIM 2.0)" hint="Changing it pushes everybody with access to the new endpoint.">
          <input type="url" value={form.scimUrl} onChange={set('scimUrl')} />
        </Field>
        {form.scimUrl && (
          <Field
            label="Replace the token (optional)"
            hint="Paste a token the application issued for the Hub. Leave empty to keep the current one."
          >
            <input type="password" autoComplete="off" value={form.scimToken} onChange={set('scimToken')} />
          </Field>
        )}
        {!app.hasScimToken && form.scimUrl && !form.scimToken && (
          <Notice kind="warning">This application has no token yet: paste one here, or create one after saving.</Notice>
        )}
      </form>
    </Modal>
  );
}

function PermissionDialog({
  appId, permission, users, onClose, onSaved,
}: {
  appId: string;
  permission: Permission | null;
  users: number;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [form, setForm] = useState({
    key: permission?.key ?? '', name: permission?.name ?? '', description: permission?.description ?? '',
  });
  const { busy, error, run } = useAction();
  const set = (key: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement>) => setForm({ ...form, [key]: e.target.value });
  const save = () =>
    permission
      ? api.patch(`/api/apps/${appId}/permissions/${permission.id}`, form)
      : api.post(`/api/apps/${appId}/permissions`, form);
  return (
    <Modal
      title={permission ? `Edit ${permission.key}` : 'Add a permission'}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose} disabled={busy}>
            Cancel
          </button>
          <button className="btn btn-primary" type="submit" form="permission" disabled={busy}>
            {busy ? 'Saving…' : 'Save'}
          </button>
        </>
      }
    >
      <form
        id="permission"
        className="form"
        onSubmit={(e) => {
          e.preventDefault();
          run(save).then((ok) => ok && (onSaved(), onClose()));
        }}
      >
        <ErrorBanner message={error} />
        <Field label="Key" hint={permission ? 'The key cannot change: applications rely on it.' : 'Lowercase, like projects:create.'}>
          <input required value={form.key} onChange={set('key')} disabled={!!permission} autoFocus={!permission} />
        </Field>
        <Field label="Name">
          <input required value={form.name} onChange={set('name')} />
        </Field>
        <Field label="Description">
          <input value={form.description} onChange={set('description')} />
        </Field>
        {users > 0 && <p className="muted small">Saving pushes {users} {users === 1 ? 'person' : 'people'} again.</p>}
      </form>
    </Modal>
  );
}

function RoleDialog({
  appId, role, permissions, users, onClose, onSaved,
}: {
  appId: string;
  role: AppRole | null;
  permissions: Permission[];
  users: number;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [form, setForm] = useState({ key: role?.key ?? '', name: role?.name ?? '', description: role?.description ?? '' });
  const [permissionIds, setPermissionIds] = useState(role?.permissionIds ?? []);
  const { busy, error, run } = useAction();
  const set = (key: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement>) => setForm({ ...form, [key]: e.target.value });
  const save = () => {
    const body = { ...form, permissionIds };
    return role ? api.patch(`/api/apps/${appId}/roles/${role.id}`, body) : api.post(`/api/apps/${appId}/roles`, body);
  };
  return (
    <Modal
      title={role ? `Edit ${role.key}` : 'Add a role'}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose} disabled={busy}>
            Cancel
          </button>
          <button className="btn btn-primary" type="submit" form="role" disabled={busy}>
            {busy ? 'Saving…' : 'Save'}
          </button>
        </>
      }
    >
      <form
        id="role"
        className="form"
        onSubmit={(e) => {
          e.preventDefault();
          run(save).then((ok) => ok && (onSaved(), onClose()));
        }}
      >
        <ErrorBanner message={error} />
        <div className="form-row">
          <Field label="Key" hint={role ? 'Fixed.' : 'Like DEVELOPER.'}>
            <input required value={form.key} onChange={set('key')} disabled={!!role} autoFocus={!role} />
          </Field>
          <Field label="Name">
            <input required value={form.name} onChange={set('name')} />
          </Field>
        </div>
        <Field label="Description">
          <input value={form.description} onChange={set('description')} />
        </Field>
        <fieldset className="fieldset">
          <legend>Permissions</legend>
          {permissions.length === 0 && <p className="muted">Add permissions to the application first.</p>}
          {permissions.map((p) => (
            <Checkbox
              key={p.id}
              checked={permissionIds.includes(p.id)}
              onChange={(on) => setPermissionIds(toggle(permissionIds, p.id, on))}
              label={<code>{p.key}</code>}
              description={p.name}
            />
          ))}
        </fieldset>
        {users > 0 && <p className="muted small">Saving pushes the change to everybody who holds this role.</p>}
      </form>
    </Modal>
  );
}
