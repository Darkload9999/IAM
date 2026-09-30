export type Role = 'owner' | 'admin';

export interface Me {
  userId: string;
  email: string;
  name: string;
  role: Role;
  csrfToken: string;
  expiresAt: string;
  organization: string;
}

export interface User {
  id: string;
  asgardeoId: string;
  username: string;
  email: string;
  givenName: string;
  familyName: string;
  accountType: 'Owner' | 'Administrator' | 'Customer' | string;
  accountState: string;
  locked: boolean;
  department: string;
  createdViaHub: boolean;
  asgardeoCreatedAt: string | null;
  removedAt: string | null;
  syncedAt: string;
  createdAt: string;
  apps?: string[];
}

export interface Application {
  id: string;
  key: string;
  name: string;
  description: string;
  url: string;
  scimUrl: string;
  hasScimToken: boolean;
  asgardeoGroupId: string;
  asgardeoGroupName: string;
  userCount: number;
  createdAt: string;
}

export interface Permission {
  id: string;
  appId: string;
  key: string;
  name: string;
  description: string;
}

export interface AppRole {
  id: string;
  appId: string;
  key: string;
  name: string;
  description: string;
  permissionIds: string[];
}

export interface CatalogApp extends Application {
  permissions: Permission[];
  roles: AppRole[];
}

export type SyncStatus = 'pending' | 'provisioned' | 'failed' | 'revoking' | 'not_required';

export interface Grant {
  id: string;
  userId: string;
  appId: string;
  appKey: string;
  appName: string;
  remoteId: string;
  syncStatus: SyncStatus;
  lastError: string;
  lastSyncedAt: string | null;
  grantedBy: string;
  createdAt: string;
  roleIds: string[];
  permissionIds: string[];
  effectivePermissions: string[];
}

export interface Job {
  id: string;
  userId: string;
  userEmail: string;
  appId: string;
  appKey: string;
  operation: 'upsert' | 'deprovision';
  status: 'pending' | 'running' | 'done' | 'failed';
  attempts: number;
  nextRunAt: string;
  lastError: string;
  createdAt: string;
  updatedAt: string;
}

export interface AuditEvent {
  id: number;
  actor: string;
  action: string;
  targetType: string;
  targetId: string;
  summary: string;
  details: Record<string, unknown>;
  createdAt: string;
}

export interface Stats {
  users: number;
  pending: number;
  locked: number;
  applications: number;
  grants: number;
  jobsPending: number;
  jobsFailed: number;
  lastSyncedAt: string | null;
  groupsEnabled: boolean;
  organizationOwner: string;
}

export interface HubAdmin {
  email: string;
  userId: string;
  name: string;
  addedBy: string;
  createdAt: string;
}

// ------------------------------------------------ the Asgardeo console

export interface Capability {
  key: 'users' | 'groups' | 'roles' | 'applications' | 'sessions' | 'security' | string;
  name: string;
  api: string;
  group: string;
  scopes: string[];
  enabled: boolean;
  missing: string[];
}

/** An Asgardeo member, joined to the Hub's record of the person. */
export interface PersonRef {
  asgardeoId: string;
  userId: string;
  name: string;
  email: string;
}

export interface AsgardeoRef {
  id: string;
  display: string;
}

export interface ConsoleGroup {
  id: string;
  name: string;
  members: PersonRef[];
  appId?: string;
  appName?: string;
}

export interface ConsoleRole {
  id: string;
  name: string;
  audience: string;
  audienceOf: string;
  permissions: AsgardeoRef[];
  users: PersonRef[];
  groups: AsgardeoRef[];
  system: boolean;
}

export interface ConsoleApp {
  id: string;
  name: string;
  description: string;
  clientId: string;
  accessUrl: string;
  image: string;
  template: string;
  redirectUrls?: string[];
  grantTypes?: string[];
  allowedOrigins?: string[];
  publicClient: boolean;
  hubAppId?: string;
}

export interface LoginSession {
  id: string;
  applications: string[];
  userAgent: string;
  ip: string;
  loginTime: string;
  lastAccessTime: string;
}

export interface Policy {
  categoryId: string;
  categoryName: string;
  id: string;
  name: string;
  properties: { name: string; value: string; displayName: string; description: string }[];
}
