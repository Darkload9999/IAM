import { useEffect, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { api } from '../api';
import {
  AccountTypeBadge, Avatar, Badge, Confirm, Empty, ErrorBanner, Field, Loading, Modal, Notice,
  PageHeader, Section, UserStatusBadge, When, displayName, formatDate, useAction, useLoad,
} from '../components';
import { useMe } from '../session';
import type { AuditEvent, CatalogApp, Grant, User } from '../types';
import { ActivityList } from './Overview';
import { AccessEditor } from './AccessEditor';
import { Sessions } from './Sessions';

interface PersonData {
  user: User;
  grants: Grant[];
  activity: AuditEvent[];
  hubAdmin: boolean;
  ownerAccount: boolean;
}

export function Person() {
  const { id = '' } = useParams();
  const me = useMe();
  const navigate = useNavigate();
  const person = useLoad(() => api.get<PersonData>(`/api/users/${id}`), [id]);
  const catalog = useLoad(() => api.get<{ apps: CatalogApp[] }>('/api/catalog'), []);
  const [dialog, setDialog] = useState<'' | 'edit' | 'lock' | 'unlock' | 'delete' | 'reset'>('');
  const [notice, setNotice] = useState('');
  const [adding, setAdding] = useState('');

  // While a push is on its way, follow it until it lands.
  const inFlight = person.data?.grants.some((g) => g.syncStatus === 'pending' || g.syncStatus === 'revoking');
  const { reload } = person;
  useEffect(() => {
    if (!inFlight) return;
    const timer = setInterval(reload, 2000);
    return () => clearInterval(timer);
  }, [inFlight, reload]);

  if (person.error && !person.data) return <ErrorBanner message={person.error} onRetry={person.reload} />;
  if (!person.data) return <Loading />;

  const { user, grants, activity, hubAdmin, ownerAccount } = person.data;
  const apps = catalog.data?.apps ?? [];
  const managed = user.accountType === 'Customer' && !ownerAccount;
  const removed = !!user.removedAt;
  const self = user.id === me.userId;
  const available = apps.filter((a) => !grants.some((g) => g.appId === a.id));

  return (
    <>
      <p className="crumbs">
        <Link to="/people">People</Link> /
      </p>
      <PageHeader
        title={
          <span className="person-title">
            <Avatar user={user} /> {displayName(user)}
          </span>
        }
        subtitle={
          <>
            {user.email} · <UserStatusBadge user={user} />{' '}
            <AccountTypeBadge type={ownerAccount ? 'Owner' : user.accountType} />{' '}
            {hubAdmin && !ownerAccount && <Badge tone="accent">Hub admin</Badge>}
          </>
        }
        actions={
          managed &&
          !removed && (
            <>
              <button className="btn" onClick={() => setDialog('edit')}>
                Edit
              </button>
              {!user.locked && user.accountState !== 'PENDING_AP' && (
                <button className="btn" onClick={() => setDialog('reset')} disabled={self}>
                  Reset password
                </button>
              )}
              {user.locked ? (
                <button className="btn" onClick={() => setDialog('unlock')}>
                  Restore
                </button>
              ) : (
                <button className="btn" onClick={() => setDialog('lock')} disabled={self}>
                  Suspend
                </button>
              )}
              <button className="btn btn-danger" onClick={() => setDialog('delete')} disabled={self}>
                Offboard
              </button>
            </>
          )
        }
      />
      <ErrorBanner message={person.error} onRetry={person.reload} />
      {notice && <Notice kind="success">{notice}</Notice>}
      {!managed && (
        <Notice kind="info">
          {ownerAccount ? 'The organization owner' : 'Console administrators'} can be given application access here, but
          their account itself is managed in the Asgardeo console.
        </Notice>
      )}
      {removed && (
        <Notice kind="warning">
          This account was removed from Asgardeo {formatDate(user.removedAt)}. Its record stays for the audit trail.
        </Notice>
      )}
      {user.accountState === 'PENDING_AP' && !removed && (
        <Notice kind="info">Invited — they have not set a password yet.</Notice>
      )}

      <div className="grid-main">
        <div>
          <Section
            title="Access"
            actions={
              !removed &&
              available.length > 0 && (
                <select value="" onChange={(e) => setAdding(e.target.value)} aria-label="Give access to">
                  <option value="">Give access to…</option>
                  {available.map((a) => (
                    <option key={a.id} value={a.id}>
                      {a.name}
                    </option>
                  ))}
                </select>
              )
            }
          >
            {grants.length === 0 && !adding && <Empty>No application access.</Empty>}
            {adding && (
              <AccessEditor
                key={'new-' + adding}
                userId={user.id}
                app={apps.find((a) => a.id === adding)!}
                onDone={() => {
                  setAdding('');
                  person.reload();
                }}
              />
            )}
            {grants.map((g) => {
              const app = apps.find((a) => a.id === g.appId);
              return app ? (
                <AccessEditor
                  key={g.id + g.roleIds.join() + g.permissionIds.join()}
                  userId={user.id}
                  app={app}
                  grant={g}
                  readOnly={removed}
                  onDone={person.reload}
                />
              ) : null;
            })}
          </Section>
        </div>
        <div>
          <Section title="Profile">
            <dl className="facts">
              <dt>Department</dt>
              <dd>{user.department || '—'}</dd>
              <dt>Asgardeo username</dt>
              <dd className="mono">{user.username}</dd>
              <dt>Asgardeo id</dt>
              <dd className="mono">{user.asgardeoId}</dd>
              <dt>In Asgardeo since</dt>
              <dd>{formatDate(user.asgardeoCreatedAt)}</dd>
              <dt>Onboarded through the Hub</dt>
              <dd>{user.createdViaHub ? 'Yes' : 'No'}</dd>
              <dt>Last synced</dt>
              <dd>
                <When at={user.syncedAt} />
              </dd>
            </dl>
          </Section>
          {!removed && <Sessions userId={user.id} protectedAccount={ownerAccount && !self} />}
          <Section title="Activity">
            <ActivityList events={activity} />
          </Section>
        </div>
      </div>

      {dialog === 'edit' && <EditDialog user={user} onClose={() => setDialog('')} onSaved={person.reload} />}
      {(dialog === 'lock' || dialog === 'unlock') && (
        <Confirm
          title={dialog === 'lock' ? `Suspend ${displayName(user)}?` : `Restore ${displayName(user)}?`}
          message={
            dialog === 'lock'
              ? 'Their Asgardeo account is locked, so they cannot sign in anywhere, and every application marks them inactive. Nothing is deleted.'
              : 'Their Asgardeo account is unlocked and they become active again in every application they have access to.'
          }
          confirmLabel={dialog === 'lock' ? 'Suspend' : 'Restore'}
          danger={dialog === 'lock'}
          onConfirm={() => api.post(`/api/users/${user.id}/${dialog}`).then(person.reload)}
          onClose={() => setDialog('')}
        />
      )}
      {dialog === 'reset' && (
        <Confirm
          title={`Reset ${displayName(user)}'s password?`}
          message={
            <p>
              Asgardeo emails <strong>{user.email}</strong> a link to choose a new password. The password they have
              stops working at once.
            </p>
          }
          confirmLabel="Send reset link"
          onConfirm={() =>
            api.post(`/api/users/${user.id}/reset-password`).then(() => {
              setNotice(`Asgardeo has emailed ${user.email} a link to set a new password.`);
              person.reload();
            })
          }
          onClose={() => setDialog('')}
        />
      )}
      {dialog === 'delete' && (
        <Confirm
          title={`Offboard ${displayName(user)}?`}
          message={
            <>
              <p>
                Their account is <strong>deleted from Asgardeo</strong> and deactivated in {grants.length}{' '}
                application{grants.length === 1 ? '' : 's'} (their work there stays). This cannot be undone: to bring
                them back, onboard them again.
              </p>
            </>
          }
          confirmLabel="Offboard"
          danger
          onConfirm={() => api.del(`/api/users/${user.id}`).then(() => navigate('/people'))}
          onClose={() => setDialog('')}
        />
      )}
    </>
  );
}

function EditDialog({ user, onClose, onSaved }: { user: User; onClose: () => void; onSaved: () => void }) {
  const [form, setForm] = useState({ givenName: user.givenName, familyName: user.familyName, department: user.department });
  const { busy, error, run } = useAction();
  const set = (key: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement>) =>
    setForm({ ...form, [key]: e.target.value });

  return (
    <Modal
      title={`Edit ${displayName(user)}`}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose} disabled={busy}>
            Cancel
          </button>
          <button className="btn btn-primary" type="submit" form="edit-user" disabled={busy}>
            {busy ? 'Saving…' : 'Save'}
          </button>
        </>
      }
    >
      <form
        id="edit-user"
        className="form"
        onSubmit={(e) => {
          e.preventDefault();
          run(() => api.patch(`/api/users/${user.id}`, form)).then((ok) => ok && (onSaved(), onClose()));
        }}
      >
        <ErrorBanner message={error} />
        <div className="form-row">
          <Field label="First name">
            <input required value={form.givenName} onChange={set('givenName')} autoFocus />
          </Field>
          <Field label="Last name">
            <input value={form.familyName} onChange={set('familyName')} />
          </Field>
        </div>
        <Field label="Department">
          <input value={form.department} onChange={set('department')} />
        </Field>
        <p className="muted small">The name changes in Asgardeo and in every application they use.</p>
      </form>
    </Modal>
  );
}
