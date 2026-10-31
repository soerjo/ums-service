import {
  BadRequestException,
  Injectable,
  NotFoundException,
  Logger,
} from '@nestjs/common';
import { randomBytes } from 'node:crypto';
import { ConfigService } from '@nestjs/config';
import { FederationRepository } from './federation.repository.js';
import { decryptSecret, encryptSecret } from '../mfa/encryption.util.js';

interface DiscoveredEndpoints {
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
}

interface PendingState {
  idpId: string;
  nonce: string;
  expiresAt: number;
  domainId?: string | null;
  redirectUri?: string | null;
}

const STATE_TTL_MS = 10 * 60 * 1000;

/**
 * OIDC federation (service-provider side), minimal viable:
 * authorization-code flow against a discovery-enabled issuer, email-based
 * account matching. Account auto-provisioning and SAML are NOT here — see
 * platform-docs ADR 0006 + docs/07-open-architecture-questions.md (Q5).
 */
@Injectable()
export class FederationService {
  private readonly logger = new Logger(FederationService.name);
  private readonly appKey: string;
  private readonly webUrl: string;
  private readonly pending = new Map<string, PendingState>();

  constructor(
    private readonly repository: FederationRepository,
    configService: ConfigService,
  ) {
    this.appKey = configService.get<string>('APP_ENCRYPTION_KEY') ?? '';
    this.webUrl = (configService.get<string>('APP_WEB_URL') ?? '').replace(
      /\/$/,
      '',
    );
  }

  private async discover(issuer: string): Promise<DiscoveredEndpoints> {
    const res = await fetch(`${issuer}/.well-known/openid-configuration`);
    if (!res.ok) {
      throw new BadRequestException(`IdP discovery failed (${res.status})`);
    }
    const doc = (await res.json()) as Partial<DiscoveredEndpoints>;
    if (
      !doc.authorization_endpoint ||
      !doc.token_endpoint ||
      !doc.userinfo_endpoint
    ) {
      throw new BadRequestException('IdP discovery document is incomplete');
    }
    return doc as DiscoveredEndpoints;
  }

  async buildAuthorizationUrl(
    idpId: string,
    options?: { domainId?: string | null; redirectUri?: string | null },
  ): Promise<string> {
    const idp = await this.repository.findActiveById(idpId);
    if (!idp) throw new NotFoundException('Identity provider not found');
    const endpoints = await this.discover(idp.issuer);
    const state = randomBytes(16).toString('base64url');
    const nonce = randomBytes(16).toString('base64url');
    this.pending.set(state, {
      idpId: idp.id,
      nonce,
      expiresAt: Date.now() + STATE_TTL_MS,
      domainId: options?.domainId ?? null,
      redirectUri: options?.redirectUri ?? null,
    });
    const url = new URL(endpoints.authorization_endpoint);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('client_id', idp.clientId);
    url.searchParams.set(
      'redirect_uri',
      `${this.webUrl}/api/auth/oidc/${idp.id}/callback`,
    );
    url.searchParams.set('scope', idp.scopes.join(' '));
    url.searchParams.set('state', state);
    url.searchParams.set('nonce', nonce);
    return url.toString();
  }

  async exchangeCallback(idpId: string, code: string, state: string) {
    const pending = this.pending.get(state);
    if (!pending || pending.expiresAt < Date.now() || pending.idpId !== idpId) {
      throw new BadRequestException('Invalid or expired OAuth state');
    }
    this.pending.delete(state);

    const idp = await this.repository.findActiveById(idpId);
    if (!idp) throw new NotFoundException('Identity provider not found');
    const endpoints = await this.discover(idp.issuer);
    const clientSecret = decryptSecret(idp.clientSecretEnc, this.appKey);

    const tokenRes = await fetch(endpoints.token_endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: `${this.webUrl}/api/auth/oidc/${idp.id}/callback`,
        client_id: idp.clientId,
        client_secret: clientSecret,
      }),
    });
    if (!tokenRes.ok) {
      throw new BadRequestException('Code exchange failed');
    }
    const tokens = (await tokenRes.json()) as { access_token?: string };
    if (!tokens.access_token) {
      throw new BadRequestException('Token response missing access_token');
    }

    // v1 trusts userinfo over TLS from the discovered endpoint; id_token
    // signature validation is the documented follow-up.
    const userinfoRes = await fetch(endpoints.userinfo_endpoint, {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });
    if (!userinfoRes.ok) {
      throw new BadRequestException('Userinfo request failed');
    }
    const userinfo = (await userinfoRes.json()) as {
      email?: string;
      name?: string;
    };
    if (!userinfo.email) {
      throw new BadRequestException('IdP did not return an email claim');
    }
    return {
      email: userinfo.email,
      name: userinfo.name,
      domainId: pending.domainId,
      redirectUri: pending.redirectUri,
    };
  }

  async create(input: {
    name: string;
    issuer: string;
    clientId: string;
    clientSecret: string;
    scopes?: string[];
    active?: boolean;
  }) {
    return this.repository.create({
      name: input.name,
      issuer: input.issuer,
      clientId: input.clientId,
      clientSecretEnc: encryptSecret(input.clientSecret, this.appKey),
      scopes: input.scopes ?? ['openid', 'email', 'profile'],
      active: input.active ?? true,
    });
  }

  async list() {
    return this.repository.list();
  }

  async update(id: string, patch: Record<string, unknown>) {
    const data = { ...patch } as Record<string, unknown>;
    if (typeof data.clientSecret === 'string') {
      data.clientSecretEnc = encryptSecret(data.clientSecret, this.appKey);
      delete data.clientSecret;
    }
    return this.repository.update(id, data);
  }

  async remove(id: string) {
    return this.repository.remove(id);
  }
}
