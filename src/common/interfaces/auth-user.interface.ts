export interface AuthUser {
  id: string;
  email: string;
  name: string | null;
  roles: string[];
  orgs: string[];
  perms: string[];
  domainId?: string | null;
}
