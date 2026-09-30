import { useState } from 'react';
import { api } from '../api';
import { useCapability } from '../asgardeo';
import { Confirm, Empty, ErrorBanner, Loading, Section, When, useLoad } from '../components';
import type { LoginSession } from '../types';

/** A person's active sign-in sessions in Asgardeo, and ending them. */
export function Sessions({ userId, protectedAccount }: { userId: string; protectedAccount: boolean }) {
  const cap = useCapability('sessions');
  if (!cap?.enabled) {
    return (
      <Section title="Sign-in sessions">
        <p className="muted small">
          To see and end sessions here, authorize the Hub's M2M application for the <strong>{cap?.api ?? 'Session Management API'}</strong>{' '}
          in Asgardeo (see the Asgardeo page).
        </p>
      </Section>
    );
  }
  return <SessionList userId={userId} protectedAccount={protectedAccount} />;
}

function SessionList({ userId, protectedAccount }: { userId: string; protectedAccount: boolean }) {
  const sessions = useLoad(() => api.get<{ sessions: LoginSession[] }>(`/api/users/${userId}/sessions`), [userId]);
  const [ending, setEnding] = useState<'all' | LoginSession | null>(null);
  const list = sessions.data?.sessions ?? [];

  return (
    <Section
      title={`Sign-in sessions${sessions.data ? ` (${list.length})` : ''}`}
      actions={
        list.length > 0 &&
        !protectedAccount && (
          <button className="btn btn-small btn-danger-quiet" onClick={() => setEnding('all')}>
            Sign out everywhere
          </button>
        )
      }
    >
      <ErrorBanner message={sessions.error} onRetry={sessions.reload} />
      {!sessions.data && sessions.loading && <Loading />}
      {sessions.data && list.length === 0 && <Empty>Not signed in anywhere.</Empty>}
      {list.length > 0 && (
        <ul className="mini-list row-list">
          {list.map((s) => (
            <li key={s.id}>
              <span>
                <strong>{s.applications.join(', ') || 'Asgardeo'}</strong>
                <span className="muted small">
                  {' '}
                  {browserOf(s.userAgent)} · {s.ip || 'unknown address'} · signed in <When at={s.loginTime} />
                </span>
              </span>
              {!protectedAccount && (
                <button className="btn btn-small btn-danger-quiet" onClick={() => setEnding(s)}>
                  End
                </button>
              )}
            </li>
          ))}
        </ul>
      )}
      {ending && (
        <Confirm
          title={ending === 'all' ? 'Sign out of every session?' : 'End this session?'}
          message="They have to sign in again. Their account and access are not changed."
          confirmLabel={ending === 'all' ? 'Sign out everywhere' : 'End session'}
          danger
          onConfirm={() =>
            api.del(`/api/users/${userId}/sessions${ending === 'all' ? '' : '/' + ending.id}`).then(sessions.reload)
          }
          onClose={() => setEnding(null)}
        />
      )}
    </Section>
  );
}

/** "Chrome on Windows", read loosely from a user agent. */
function browserOf(agent: string): string {
  if (!agent) return 'Unknown browser';
  const browser = /Edg\//.test(agent)
    ? 'Edge'
    : /Chrome\//.test(agent)
      ? 'Chrome'
      : /Firefox\//.test(agent)
        ? 'Firefox'
        : /Safari\//.test(agent)
          ? 'Safari'
          : 'A browser';
  const os = /Windows/.test(agent)
    ? 'Windows'
    : /Mac OS X/.test(agent)
      ? 'macOS'
      : /Android/.test(agent)
        ? 'Android'
        : /iPhone|iPad/.test(agent)
          ? 'iOS'
          : /Linux/.test(agent)
            ? 'Linux'
            : '';
  return os ? `${browser} on ${os}` : browser;
}
