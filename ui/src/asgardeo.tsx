// What the Hub may manage in Asgardeo, and what to do when it may not.

import { createContext, useContext, type ReactNode } from 'react';
import { api } from './api';
import { ErrorBanner, Loading, useLoad, type Loaded } from './components';
import { Icon } from './icons';
import type { Capability } from './types';

export const CapabilitiesContext = createContext<Loaded<{ modules: Capability[] }> | null>(null);

/** Loads the capabilities once for the whole dashboard. */
export function useCapabilitiesLoader() {
  return useLoad(() => api.get<{ modules: Capability[] }>('/api/asgardeo/capabilities'), []);
}

export function useCapabilities() {
  const loaded = useContext(CapabilitiesContext);
  if (!loaded) throw new Error('useCapabilities outside the dashboard');
  return loaded;
}

export function useCapability(key: string): Capability | undefined {
  return useCapabilities().data?.modules.find((m) => m.key === key);
}

/**
 * Renders the page when the Hub may use this part of Asgardeo; otherwise
 * says exactly what to authorize in the Asgardeo console.
 */
export function RequiresAsgardeo({ module, children }: { module: string; children: ReactNode }) {
  const caps = useCapabilities();
  const cap = useCapability(module);
  if (caps.error && !caps.data) return <ErrorBanner message={caps.error} onRetry={caps.reload} />;
  if (!caps.data) return <Loading />;
  if (!cap) return <ErrorBanner message={`Unknown Asgardeo area: ${module}`} />;
  if (cap.enabled) return <>{children}</>;
  return <NotAuthorized cap={cap} onCheck={caps.reload} />;
}

export function NotAuthorized({ cap, onCheck }: { cap: Capability; onCheck: () => void }) {
  return (
    <div className="card card-pad authorize">
      <div className="authorize-head">
        <span className="authorize-icon" aria-hidden="true">
          <Icon name="lock" size={20} />
        </span>
        <div>
          <h2>{cap.name} needs one more permission in Asgardeo</h2>
          <p className="muted">
            The Hub works through its M2M application in Asgardeo, which is not yet authorized for the{' '}
            <strong>{cap.api}</strong>.
          </p>
        </div>
      </div>
      <ol className="steps">
        <li>
          In the Asgardeo console, open <strong>Applications</strong> and the Hub's <strong>M2M application</strong>.
        </li>
        <li>
          On the <strong>API Authorization</strong> tab, choose <strong>Authorize an API Resource</strong>.
        </li>
        <li>
          Pick <strong>{cap.api}</strong> under <strong>{cap.group}</strong> and tick:
          <div className="chips">
            {cap.missing.map((s) => (
              <code key={s} className="chip mono">
                {s}
              </code>
            ))}
          </div>
        </li>
        <li>
          Choose <strong>Finish</strong>, then come back here.
        </li>
      </ol>
      <button className="btn btn-primary" onClick={() => checkAgain(onCheck)}>
        <Icon name="sync" size={16} />
        Check again
      </button>
    </div>
  );
}

/** Asks the Hub to take a fresh token, so a new permission shows at once. */
export async function checkAgain(then: () => void) {
  await api.get('/api/asgardeo/capabilities?refresh=1').catch(() => undefined);
  then();
}
