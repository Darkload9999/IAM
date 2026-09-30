import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api';
import {
  Badge, Checkbox, Confirm, Empty, ErrorBanner, Loading, Modal, SyncBadge, When, displayName, toggle,
  useAction, useLoad,
} from '../components';
import type { CatalogApp, Grant, User } from '../types';

/** One application's access for a person: roles, extra permissions, status. */
export function AccessEditor({
  userId,
  app,
  grant,
  readOnly,
  onDone,
}: {
  userId: string;
  app: CatalogApp;
  grant?: Grant;
  readOnly?: boolean;
  onDone: () => void;
}) {
  const [roleIds, setRoleIds] = useState(grant?.roleIds ?? []);
  const [permissionIds, setPermissionIds] = useState(grant?.permissionIds ?? []);
  const [revoking, setRevoking] = useState(false);
  const { busy, error, run } = useAction();
  const isNew = !grant;
  const dirty =
    isNew ||
    [...roleIds].sort().join() !== [...grant.roleIds].sort().join() ||
    [...permissionIds].sort().join() !== [...grant.permissionIds].sort().join();
  const leaving = grant?.syncStatus === 'revoking';

  // Permissions the chosen roles already carry.
  const fromRoles = new Set(app.roles.filter((r) => roleIds.includes(r.id)).flatMap((r) => r.permissionIds));

  const save = () =>
    run(() => api.put(`/api/users/${userId}/access/${app.id}`, { roleIds, permissionIds })).then(
      (ok) => ok && onDone(),
    );

  return (
    <div className={isNew ? 'access access-new' : 'access'}>
      <div className="access-head">
        <div>
          <Link to={`/apps/${app.id}`} className="access-app">
            {app.name}
          </Link>
          {grant && (
            <span className="muted small">
              {' '}
              · given by {grant.grantedBy} <When at={grant.createdAt} />
            </span>
          )}
        </div>
        {grant ? <SyncBadge status={grant.syncStatus} /> : <Badge tone="info">New</Badge>}
      </div>
      {grant?.lastError && <div className="access-error">{grant.lastError}</div>}
      <ErrorBanner message={error} />

      {app.roles.length === 0 && app.permissions.length === 0 && (
        <p className="muted small">
          {app.name} has no roles or permissions defined; access means an account there and nothing more.
        </p>
      )}
      {app.roles.length > 0 && (
        <div className="access-group">
          <h4>Roles</h4>
          {app.roles.map((r) => (
            <Checkbox
              key={r.id}
              checked={roleIds.includes(r.id)}
              disabled={readOnly || leaving}
              onChange={(on) => setRoleIds(toggle(roleIds, r.id, on))}
              label={r.name}
              description={`${r.key} · ${r.permissionIds.length} permission${r.permissionIds.length === 1 ? '' : 's'}`}
            />
          ))}
        </div>
      )}
      {app.permissions.length > 0 && (
        <div className="access-group">
          <h4>Permissions</h4>
          {app.permissions.map((p) => {
            const viaRole = fromRoles.has(p.id);
            return (
              <Checkbox
                key={p.id}
                checked={viaRole || permissionIds.includes(p.id)}
                disabled={readOnly || leaving || viaRole}
                onChange={(on) => setPermissionIds(toggle(permissionIds, p.id, on))}
                label={<code>{p.key}</code>}
                description={viaRole ? `${p.name} — through a role` : p.name}
              />
            );
          })}
        </div>
      )}

      {!readOnly && (
        <div className="access-actions">
          {grant && !leaving && (
            <button className="btn btn-small btn-danger-quiet" onClick={() => setRevoking(true)} disabled={busy}>
              Remove access
            </button>
          )}
          {isNew && (
            <button className="btn btn-small" onClick={onDone} disabled={busy}>
              Cancel
            </button>
          )}
          {!leaving && (
            <button className="btn btn-small btn-primary" onClick={save} disabled={busy || !dirty}>
              {busy ? 'Saving…' : isNew ? `Give access to ${app.name}` : 'Save changes'}
            </button>
          )}
        </div>
      )}

      {revoking && (
        <Confirm
          title={`Remove access to ${app.name}?`}
          message={`The account in ${app.name} is deactivated (not deleted), and they leave its Asgardeo access group if it has one.`}
          confirmLabel="Remove access"
          danger
          onConfirm={() => api.del(`/api/users/${userId}/access/${app.id}`).then(onDone)}
          onClose={() => setRevoking(false)}
        />
      )}
    </div>
  );
}

/**
 * A person's access to every application, from the People list: the same
 * editor as on their page.
 */
export function AccessDialog({ user, apps, onClose }: { user: User; apps: CatalogApp[]; onClose: () => void }) {
  const data = useLoad(() => api.get<{ grants: Grant[] }>(`/api/users/${user.id}`), [user.id]);
  const [adding, setAdding] = useState('');
  const grants = data.data?.grants ?? [];
  const available = apps.filter((a) => !grants.some((g) => g.appId === a.id));
  const removed = !!user.removedAt;

  // While a push is on its way, follow it until it lands.
  const inFlight = grants.some((g) => g.syncStatus === 'pending' || g.syncStatus === 'revoking');
  const { reload } = data;
  useEffect(() => {
    if (!inFlight) return;
    const timer = setInterval(reload, 2000);
    return () => clearInterval(timer);
  }, [inFlight, reload]);

  return (
    <Modal
      wide
      title={`Access for ${displayName(user)}`}
      onClose={onClose}
      footer={
        <>
          <Link className="btn" to={`/people/${user.id}`}>
            Open profile
          </Link>
          <button className="btn btn-primary" onClick={onClose}>
            Done
          </button>
        </>
      }
    >
      <p className="muted">
        {user.email} · roles and permissions in each application. Changes are pushed to the application at once.
      </p>
      <ErrorBanner message={data.error} onRetry={reload} />
      {data.loading && !data.data && <Loading />}
      {data.data && (
        <>
          {!removed && available.length > 0 && (
            <div className="dialog-toolbar">
              <select value="" onChange={(e) => setAdding(e.target.value)} aria-label="Give access to">
                <option value="">Give access to an application…</option>
                {available.map((a) => (
                  <option key={a.id} value={a.id}>
                    {a.name}
                  </option>
                ))}
              </select>
            </div>
          )}
          {grants.length === 0 && !adding && <Empty icon="key">No application access yet.</Empty>}
          {adding && (
            <AccessEditor
              key={'new-' + adding}
              userId={user.id}
              app={apps.find((a) => a.id === adding)!}
              onDone={() => {
                setAdding('');
                reload();
              }}
            />
          )}
          {grants.map((g) => {
            const app = apps.find((a) => a.id === g.appId);
            return app ? (
              <AccessEditor
                key={g.id + g.roleIds.join() + g.permissionIds.join() + g.syncStatus}
                userId={user.id}
                app={app}
                grant={g}
                readOnly={removed}
                onDone={reload}
              />
            ) : null;
          })}
        </>
      )}
    </Modal>
  );
}
