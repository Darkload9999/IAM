import { useMemo, useState } from 'react';
import { api } from '../api';
import { RequiresAsgardeo } from '../asgardeo';
import { Badge, Empty, ErrorBanner, Loading, Notice, PageHeader, SearchBox, Section, useAction, useLoad } from '../components';
import { useMe } from '../session';
import type { Policy } from '../types';

export function Policies() {
  return (
    <RequiresAsgardeo module="security">
      <PolicyList />
    </RequiresAsgardeo>
  );
}

function PolicyList() {
  const me = useMe();
  const policies = useLoad(() => api.get<{ policies: Policy[] }>('/api/asgardeo/policies'), []);
  const [search, setSearch] = useState('');

  const byCategory = useMemo(() => {
    const term = search.trim().toLowerCase();
    const groups = new Map<string, Policy[]>();
    for (const p of policies.data?.policies ?? []) {
      const hit =
        !term ||
        p.name.toLowerCase().includes(term) ||
        p.categoryName.toLowerCase().includes(term) ||
        p.properties.some((x) => (x.displayName || x.name).toLowerCase().includes(term));
      if (!hit) continue;
      groups.set(p.categoryName, [...(groups.get(p.categoryName) ?? []), p]);
    }
    return [...groups.entries()];
  }, [policies.data, search]);

  return (
    <>
      <PageHeader
        title="Login & security"
        subtitle="The organization's password rules, account locking, recovery and other login policies in Asgardeo."
      />
      {me.role !== 'owner' && <Notice kind="info">Only the organization owner can change these policies.</Notice>}
      <ErrorBanner message={policies.error} onRetry={policies.reload} />
      <div className="filters">
        <SearchBox value={search} onChange={setSearch} placeholder="Search policies and settings" />
      </div>
      {!policies.data && policies.loading && <Loading />}
      {policies.data && byCategory.length === 0 && <Empty icon="lock">Nothing matches.</Empty>}
      {byCategory.map(([category, list]) => (
        <Section key={category} title={category}>
          {list.map((p) => (
            <PolicyCard key={p.categoryId + p.id} policy={p} editable={me.role === 'owner'} onSaved={policies.reload} />
          ))}
        </Section>
      ))}
    </>
  );
}

const isBool = (v: string) => v === 'true' || v === 'false';

function PolicyCard({ policy, editable, onSaved }: { policy: Policy; editable: boolean; onSaved: () => void }) {
  const initial = useMemo(() => Object.fromEntries(policy.properties.map((p) => [p.name, p.value])), [policy]);
  const [values, setValues] = useState<Record<string, string>>(initial);
  const [saved, setSaved] = useState(false);
  const { busy, error, run } = useAction();
  const changed = Object.fromEntries(Object.entries(values).filter(([k, v]) => v !== initial[k]));
  const dirty = Object.keys(changed).length > 0;
  const enabled = policy.properties.find((p) => /\.enable(d)?$/i.test(p.name) && isBool(p.value));

  return (
    <div className="policy">
      <div className="policy-head">
        <strong>{policy.name}</strong>
        {enabled && (values[enabled.name] === 'true' ? <Badge tone="success">On</Badge> : <Badge tone="neutral">Off</Badge>)}
      </div>
      <ErrorBanner message={error} />
      {policy.properties.length === 0 ? (
        <p className="muted small">No settings.</p>
      ) : (
        <div className="policy-props">
          {policy.properties.map((prop) => (
            <label key={prop.name} className={isBool(initial[prop.name] ?? '') ? 'policy-prop policy-bool' : 'policy-prop'}>
              {isBool(initial[prop.name] ?? '') ? (
                <input
                  type="checkbox"
                  checked={values[prop.name] === 'true'}
                  disabled={!editable || busy}
                  onChange={(e) => setValues({ ...values, [prop.name]: String(e.target.checked) })}
                />
              ) : null}
              <span className="policy-label">
                {prop.displayName || prop.name}
                {prop.description && <span className="muted small">{prop.description}</span>}
              </span>
              {!isBool(initial[prop.name] ?? '') && (
                <input
                  value={values[prop.name] ?? ''}
                  disabled={!editable || busy}
                  onChange={(e) => setValues({ ...values, [prop.name]: e.target.value })}
                />
              )}
            </label>
          ))}
        </div>
      )}
      {editable && (dirty || saved) && (
        <div className="button-row">
          {saved && !dirty && <span className="muted small">Saved in Asgardeo.</span>}
          {dirty && (
            <>
              <button className="btn" disabled={busy} onClick={() => setValues(initial)}>
                Undo
              </button>
              <button
                className="btn btn-primary"
                disabled={busy}
                onClick={() =>
                  run(() => api.patch(`/api/asgardeo/policies/${policy.categoryId}/${policy.id}`, { values: changed })).then(
                    (ok) => ok && (setSaved(true), onSaved()),
                  )
                }
              >
                {busy ? 'Saving…' : 'Save'}
              </button>
            </>
          )}
        </div>
      )}
    </div>
  );
}
