import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react';
import { ApiError } from './api';
import { Icon, type IconName } from './icons';
import type { SyncStatus, User } from './types';

// ------------------------------------------------------------ data loading

export interface Loaded<T> {
  data: T | undefined;
  error: string;
  loading: boolean;
  reload: () => void;
}

/** Loads once, again whenever deps change, and on reload(). */
export function useLoad<T>(load: () => Promise<T>, deps: unknown[]): Loaded<T> {
  const [data, setData] = useState<T>();
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const [tick, setTick] = useState(0);

  useEffect(() => {
    let live = true;
    setLoading(true);
    load()
      .then((d) => live && (setData(d), setError('')))
      .catch((e) => live && setError(messageOf(e)))
      .finally(() => live && setLoading(false));
    return () => {
      live = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick]);

  const reload = useCallback(() => setTick((t) => t + 1), []);
  return { data, error, loading, reload };
}

/** Runs an action, keeping track of whether it is busy and what went wrong. */
export function useAction() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const run = useCallback(async (action: () => Promise<unknown>): Promise<boolean> => {
    setBusy(true);
    setError('');
    try {
      await action();
      return true;
    } catch (e) {
      setError(messageOf(e));
      return false;
    } finally {
      setBusy(false);
    }
  }, []);
  return { busy, error, setError, run };
}

export function messageOf(e: unknown): string {
  if (e instanceof ApiError) return e.message;
  if (e instanceof Error) return e.message;
  return 'Something went wrong';
}

// ------------------------------------------------------------ layout bits

export function PageHeader({ title, subtitle, actions }: { title: ReactNode; subtitle?: ReactNode; actions?: ReactNode }) {
  return (
    <header className="page-header">
      <div>
        <h1>{title}</h1>
        {subtitle && <p className="muted">{subtitle}</p>}
      </div>
      {actions && <div className="actions">{actions}</div>}
    </header>
  );
}

export function Section({ title, actions, children }: { title: ReactNode; actions?: ReactNode; children: ReactNode }) {
  return (
    <section className="card">
      <div className="card-header">
        <h2>{title}</h2>
        {actions && <div className="actions">{actions}</div>}
      </div>
      {children}
    </section>
  );
}

export function ErrorBanner({ message, onRetry }: { message: string; onRetry?: () => void }) {
  if (!message) return null;
  return (
    <div className="banner banner-error" role="alert">
      <Icon name="alert" size={18} />
      <span className="banner-text">{message}</span>
      {onRetry && (
        <button className="btn btn-small" onClick={onRetry}>
          Try again
        </button>
      )}
    </div>
  );
}

export function Notice({ kind = 'info', children }: { kind?: 'info' | 'warning' | 'success'; children: ReactNode }) {
  return (
    <div className={`banner banner-${kind}`}>
      <Icon name={kind === 'success' ? 'check' : 'alert'} size={18} />
      <span className="banner-text">{children}</span>
    </div>
  );
}

export function Loading() {
  return (
    <div className="loading" aria-busy="true">
      <span className="spinner" aria-hidden="true" /> Loading…
    </div>
  );
}

export function SearchBox({
  value,
  onChange,
  onCommit,
  placeholder,
}: {
  value: string;
  onChange: (v: string) => void;
  onCommit?: () => void;
  placeholder: string;
}) {
  return (
    <div className="search">
      <Icon name="search" size={16} />
      <input
        type="search"
        placeholder={placeholder}
        aria-label={placeholder}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        onBlur={onCommit}
      />
    </div>
  );
}

export function Empty({ children, icon }: { children: ReactNode; icon?: IconName }) {
  return (
    <div className="empty">
      {icon && <Icon name={icon} size={22} />}
      <span>{children}</span>
    </div>
  );
}

// ------------------------------------------------------------ badges

export function Badge({ tone = 'neutral', children }: { tone?: string; children: ReactNode }) {
  return <span className={`badge badge-${tone}`}>{children}</span>;
}

export function userStatus(u: User): { label: string; tone: string } {
  if (u.removedAt) return { label: 'Removed', tone: 'neutral' };
  if (u.locked) return { label: 'Suspended', tone: 'danger' };
  if (u.accountState === 'PENDING_AP') return { label: 'Invited', tone: 'warning' };
  return { label: 'Active', tone: 'success' };
}

export function UserStatusBadge({ user }: { user: User }) {
  const s = userStatus(user);
  return <Badge tone={s.tone}>{s.label}</Badge>;
}

export function AccountTypeBadge({ type }: { type: string }) {
  if (type === 'Owner') return <Badge tone="accent">Organization owner</Badge>;
  if (type === 'Administrator') return <Badge tone="info">Console admin</Badge>;
  return null;
}

const syncLabels: Record<string, { label: string; tone: string }> = {
  pending: { label: 'Syncing', tone: 'warning' },
  provisioned: { label: 'In sync', tone: 'success' },
  failed: { label: 'Failed', tone: 'danger' },
  revoking: { label: 'Removing', tone: 'warning' },
  not_required: { label: 'Sign-in only', tone: 'neutral' },
};

export function SyncBadge({ status }: { status: SyncStatus | string }) {
  const s = syncLabels[status] ?? { label: status, tone: 'neutral' };
  return <Badge tone={s.tone}>{s.label}</Badge>;
}

export const displayName = (u: Pick<User, 'givenName' | 'familyName' | 'email'>) =>
  `${u.givenName} ${u.familyName}`.trim() || u.email;

export function Avatar({ user }: { user: Pick<User, 'givenName' | 'familyName' | 'email'> }) {
  const initials =
    ((u) => (u.givenName?.[0] ?? '') + (u.familyName?.[0] ?? ''))(user).toUpperCase() || user.email[0]?.toUpperCase();
  return (
    <span className="avatar" aria-hidden="true">
      {initials}
    </span>
  );
}

// ------------------------------------------------------------ dialogs

export function Modal({
  title,
  onClose,
  children,
  footer,
  wide,
}: {
  title: ReactNode;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
  wide?: boolean;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const dialog = ref.current;
    dialog?.showModal();
    return () => dialog?.close();
  }, []);
  return (
    <dialog
      ref={ref}
      className={wide ? 'modal modal-wide' : 'modal'}
      onCancel={(e) => {
        e.preventDefault();
        onClose();
      }}
    >
      <div className="modal-header">
        <h2>{title}</h2>
        <button className="icon-btn" onClick={onClose} aria-label="Close">
          <Icon name="x" size={18} />
        </button>
      </div>
      <div className="modal-body">{children}</div>
      {footer && <div className="modal-footer">{footer}</div>}
    </dialog>
  );
}

/** A confirmation for something that cannot be undone. */
export function Confirm({
  title,
  message,
  confirmLabel,
  danger,
  onConfirm,
  onClose,
}: {
  title: string;
  message: ReactNode;
  confirmLabel: string;
  danger?: boolean;
  onConfirm: () => Promise<unknown>;
  onClose: () => void;
}) {
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
          <button
            className={danger ? 'btn btn-danger' : 'btn btn-primary'}
            disabled={busy}
            onClick={async () => (await run(onConfirm)) && onClose()}
          >
            {busy ? 'Working…' : confirmLabel}
          </button>
        </>
      }
    >
      <ErrorBanner message={error} />
      <div className="confirm-message">{message}</div>
    </Modal>
  );
}

/** Shows a secret once, with a copy button. */
export function SecretReveal({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="secret">
      <p>
        <strong>{label}</strong> — copy it now. The Hub keeps it encrypted and will not show it again.
      </p>
      <div className="secret-row">
        <code>{value}</code>
        <button
          className="btn btn-small"
          onClick={async () => {
            await navigator.clipboard.writeText(value);
            setCopied(true);
          }}
        >
          {copied ? 'Copied' : 'Copy'}
        </button>
      </div>
    </div>
  );
}

// ------------------------------------------------------------ forms

export function Field({ label, hint, children }: { label: string; hint?: ReactNode; children: ReactNode }) {
  return (
    <label className="field">
      <span className="field-label">{label}</span>
      {children}
      {hint && <span className="field-hint">{hint}</span>}
    </label>
  );
}

export function Checkbox({
  checked,
  onChange,
  label,
  description,
  disabled,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  label: ReactNode;
  description?: ReactNode;
  disabled?: boolean;
}) {
  return (
    <label className={disabled ? 'check check-disabled' : 'check'}>
      <input type="checkbox" checked={checked} disabled={disabled} onChange={(e) => onChange(e.target.checked)} />
      <span>
        <span className="check-label">{label}</span>
        {description && <span className="check-desc">{description}</span>}
      </span>
    </label>
  );
}

// ------------------------------------------------------------ formatting

const dateTime = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' });
const relative = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });

export function formatDate(value: string | null | undefined) {
  return value ? dateTime.format(new Date(value)) : '—';
}

export function ago(value: string | null | undefined) {
  if (!value) return 'never';
  const seconds = (new Date(value).getTime() - Date.now()) / 1000;
  const abs = Math.abs(seconds);
  if (abs < 45) return seconds < 0 ? 'just now' : 'in a moment';
  if (abs < 3600) return relative.format(Math.round(seconds / 60), 'minute');
  if (abs < 86400) return relative.format(Math.round(seconds / 3600), 'hour');
  return relative.format(Math.round(seconds / 86400), 'day');
}

export function When({ at }: { at: string | null | undefined }) {
  return <time dateTime={at ?? undefined} title={formatDate(at)}>{ago(at)}</time>;
}

export const toggle = (list: string[], id: string, on: boolean) =>
  on ? (list.includes(id) ? list : [...list, id]) : list.filter((x) => x !== id);
