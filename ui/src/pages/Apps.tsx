import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { api } from '../api';
import { Badge, Empty, ErrorBanner, Field, Loading, Modal, PageHeader, SecretReveal, useAction, useLoad } from '../components';
import { Icon } from '../icons';
import type { Application } from '../types';

export function Apps() {
  const apps = useLoad(() => api.get<{ apps: Application[]; groupsEnabled: boolean }>('/api/apps'), []);
  const [registering, setRegistering] = useState(false);

  return (
    <>
      <PageHeader
        title="Applications"
        subtitle="The company's internal applications, and how the Hub gives people access to them."
        actions={
          <button className="btn btn-primary" onClick={() => setRegistering(true)}>
            <Icon name="plus" size={16} />
            Register an application
          </button>
        }
      />
      <ErrorBanner message={apps.error} onRetry={apps.reload} />
      {apps.loading && !apps.data && <Loading />}
      {apps.data &&
        (apps.data.apps.length === 0 ? (
          <Empty icon="apps">No applications yet. Register the first one to start giving access.</Empty>
        ) : (
          <div className="app-grid">
            {apps.data.apps.map((a) => (
              <Link key={a.id} to={`/apps/${a.id}`} className="app-card">
                <div className="app-card-head">
                  <span className="app-mark" aria-hidden="true">
                    {a.name.slice(0, 2).toUpperCase()}
                  </span>
                  <span>
                    <strong>{a.name}</strong>
                    <span className="mono muted small">{a.key}</span>
                  </span>
                </div>
                <p className="muted">{a.description || 'No description.'}</p>
                <div className="chips">
                  <Badge tone="neutral">
                    {a.userCount} {a.userCount === 1 ? 'person' : 'people'}
                  </Badge>
                  {a.scimUrl ? <Badge tone="success">Provisioned (SCIM)</Badge> : <Badge tone="neutral">Sign-in only</Badge>}
                  {a.asgardeoGroupName && <Badge tone="info">Group {a.asgardeoGroupName}</Badge>}
                </div>
              </Link>
            ))}
          </div>
        ))}
      {registering && <RegisterDialog onClose={() => setRegistering(false)} />}
    </>
  );
}

function RegisterDialog({ onClose }: { onClose: () => void }) {
  const navigate = useNavigate();
  const [form, setForm] = useState({ key: '', name: '', description: '', url: '', scimUrl: '', scimToken: '' });
  const [created, setCreated] = useState<{ app: Application; scimToken: string } | null>(null);
  const { busy, error, run } = useAction();
  const set = (key: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) =>
    setForm({ ...form, [key]: e.target.value });

  if (created) {
    return (
      <Modal
        title={`${created.app.name} registered`}
        onClose={() => navigate(`/apps/${created.app.id}`)}
        footer={
          <button className="btn btn-primary" onClick={() => navigate(`/apps/${created.app.id}`)}>
            Set up permissions and roles
          </button>
        }
      >
        {created.scimToken ? (
          <>
            <SecretReveal label="SCIM token" value={created.scimToken} />
            <p className="muted">
              Configure {created.app.name}'s SCIM endpoint to accept this bearer token. Until it does, pushes to it fail
              and are retried.
            </p>
          </>
        ) : created.app.scimUrl ? (
          <p>
            The Hub will send the token {created.app.name} gave you. Open the application next to test the connection
            and import its roles and permissions.
          </p>
        ) : (
          <p>No provisioning endpoint was given, so access to {created.app.name} is sign-in only: nothing is pushed to it.</p>
        )}
      </Modal>
    );
  }

  return (
    <Modal
      title="Register an application"
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose} disabled={busy}>
            Cancel
          </button>
          <button className="btn btn-primary" type="submit" form="register-app" disabled={busy}>
            {busy ? 'Registering…' : 'Register'}
          </button>
        </>
      }
    >
      <form
        id="register-app"
        className="form"
        onSubmit={(e) => {
          e.preventDefault();
          run(async () => setCreated(await api.post('/api/apps', form)));
        }}
      >
        <ErrorBanner message={error} />
        <div className="form-row">
          <Field label="Name">
            <input required value={form.name} onChange={set('name')} autoFocus placeholder="PM Tool" />
          </Field>
          <Field label="Key" hint="Lowercase, fixed once set.">
            <input required value={form.key} onChange={set('key')} pattern="[a-z][a-z0-9\-]{1,39}" placeholder="pm-tool" />
          </Field>
        </div>
        <Field label="Description">
          <textarea rows={2} value={form.description} onChange={set('description')} />
        </Field>
        <Field label="Address people open">
          <input type="url" value={form.url} onChange={set('url')} placeholder="https://pm.zeit26.com" />
        </Field>
        <Field
          label="Provisioning endpoint (SCIM 2.0)"
          hint="Where the Hub pushes people, roles and permissions, e.g. https://pm.zeit26.com/api/v1/scim/v2. Leave empty for an application that only needs sign-in."
        >
          <input type="url" value={form.scimUrl} onChange={set('scimUrl')} />
        </Field>
        {form.scimUrl && (
          <Field
            label="Token from the application (optional)"
            hint="If the application issued a token for the Hub (the PM tool's SCIM_BEARER_TOKEN), paste it. Leave empty and the Hub creates one for you to give the application."
          >
            <input type="password" autoComplete="off" value={form.scimToken} onChange={set('scimToken')} />
          </Field>
        )}
      </form>
    </Modal>
  );
}
