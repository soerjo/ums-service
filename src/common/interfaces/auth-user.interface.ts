export interface AuthUser {
  id: string;
  email: string;
  name: string | null;
  avatarUrl?: string | null;
  phone?: string | null;
  roles: string[];
  orgs: string[];
  perms: string[];
  domainId?: string | null;
}
