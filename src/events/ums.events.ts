export const UMS_TOPICS = {
  USER_CREATED: 'ums.user.created',
  USER_UPDATED: 'ums.user.updated',
  USER_SUSPENDED: 'ums.user.suspended',
  ROLE_CHANGED: 'ums.role.changed',
  SESSION_REVOKED: 'ums.session.revoked',
} as const;

export type UmsTopic = (typeof UMS_TOPICS)[keyof typeof UMS_TOPICS];

export interface UmsBaseEvent {
  eventId: string;
  occurredAt: string;
  sourceService: 'ums-service';
}

export interface UmsUserCreatedPayload extends UmsBaseEvent {
  eventType: 'USER_CREATED';
  user: {
    id: string;
    email: string;
    name: string | null;
    roles: string[];
    orgs: string[];
    status: 'ACTIVE' | 'BLOCKED';
  };
}

export interface UmsUserUpdatedPayload extends UmsBaseEvent {
  eventType: 'USER_UPDATED';
  userId: string;
  changes: {
    name?: string | null;
    email?: string;
  };
}

export interface UmsUserSuspendedPayload extends UmsBaseEvent {
  eventType: 'USER_SUSPENDED';
  userId: string;
  reason?: string;
  suspendedAt: string;
}

export interface UmsRoleChangedPayload extends UmsBaseEvent {
  eventType: 'ROLE_CHANGED';
  userId: string;
  roles: string[];
  previousRoles: string[];
}

export interface UmsSessionRevokedPayload extends UmsBaseEvent {
  eventType: 'SESSION_REVOKED';
  sessionId: string;
  userId: string;
  family: string;
  reason: 'LOGOUT' | 'SECURITY_VIOLATION' | 'ADMIN_REVOKED' | 'ROTATION_REUSE';
}

export type UmsEventPayload =
  | UmsUserCreatedPayload
  | UmsUserUpdatedPayload
  | UmsUserSuspendedPayload
  | UmsRoleChangedPayload
  | UmsSessionRevokedPayload;
