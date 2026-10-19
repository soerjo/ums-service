export interface SecurityPolicyValue {
  accessTokenTtlSeconds: number;
  maxActiveSessionsPerUser: number;
  enforceMfa: boolean;
}

export type SecurityPolicyKey = keyof SecurityPolicyValue;

export const DEFAULT_SECURITY_POLICIES: SecurityPolicyValue = {
  accessTokenTtlSeconds: 900, // 15 minutes
  maxActiveSessionsPerUser: 5,
  enforceMfa: false,
};

export enum SecurityPolicyKeyEnum {
  AccessTokenTtlSeconds = 'accessTokenTtlSeconds',
  MaxActiveSessionsPerUser = 'maxActiveSessionsPerUser',
  EnforceMfa = 'enforceMfa',
}

export class UpdateSecurityPolicyDto {
  value!: unknown;
  description?: string;
}

export class CreateSecurityPolicyDto extends UpdateSecurityPolicyDto {
  key!: SecurityPolicyKeyEnum;
}
