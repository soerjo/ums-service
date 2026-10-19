import {
  Injectable,
  OnModuleInit,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { Prisma } from '@prisma/client'; // Import Prisma for JsonValue
import { PrismaService } from '../../prisma/prisma.service.js';
import {
  DEFAULT_SECURITY_POLICIES,
  SecurityPolicyKeyEnum,
  CreateSecurityPolicyDto,
  UpdateSecurityPolicyDto,
} from './security-policies.types.js';

@Injectable()
export class SecurityPoliciesService implements OnModuleInit {
  private readonly logger = new Logger(SecurityPoliciesService.name);
  private policiesCache: Map<string, unknown> = new Map();

  constructor(private readonly prisma: PrismaService) {}

  async onModuleInit() {
    await this.loadAndSeedPolicies();
  }

  private async loadAndSeedPolicies() {
    this.logger.log('Loading and seeding security policies...');
    const existingPolicies = await this.prisma.securityPolicy.findMany();

    const existingPolicyMap = new Map(existingPolicies.map((p) => [p.key, p]));

    for (const key in DEFAULT_SECURITY_POLICIES) {
      if (!existingPolicyMap.has(key)) {
        const defaultValue =
          DEFAULT_SECURITY_POLICIES[key as SecurityPolicyKeyEnum];
        await this.prisma.securityPolicy.create({
          data: {
            key,
            value: defaultValue,
          },
        });
        this.logger.log(
          `Seeded policy: ${key} = ${JSON.stringify(defaultValue)}`,
        );
      }
    }

    // Load all policies into cache after seeding
    const allPolicies = await this.prisma.securityPolicy.findMany();
    this.policiesCache.clear();
    allPolicies.forEach((policy) =>
      this.policiesCache.set(policy.key, policy.value),
    );
    this.logger.log('Security policies loaded into cache.');
  }

  getPolicy<T>(key: SecurityPolicyKeyEnum, defaultValue: T): T {
    const cachedValue = this.policiesCache.get(key) as T | undefined;
    if (cachedValue !== undefined) {
      return cachedValue;
    }
    this.logger.warn(
      `Policy '${key}' not found in cache. Returning default value.`,
    );
    return defaultValue;
  }

  getAllPolicies(): { key: string; value: unknown }[] {
    return Array.from(this.policiesCache.entries()).map(([key, value]) => ({
      key,
      value,
    }));
  }

  async getPolicyByKey(key: string) {
    const policy = await this.prisma.securityPolicy.findUnique({
      where: { key },
    });
    if (!policy) {
      throw new NotFoundException(
        `Security policy with key "${key}" not found.`,
      );
    }
    return policy;
  }

  async setPolicy(
    key: string,
    value: unknown,
    updatedBy?: string,
    description?: string,
  ) {
    const updatedPolicy = await this.prisma.securityPolicy.upsert({
      where: { key },
      update: { value: value as Prisma.InputJsonValue, updatedBy, description },
      create: {
        key,
        value: value as Prisma.InputJsonValue,
        updatedBy,
        description,
      },
    });
    this.policiesCache.set(updatedPolicy.key, updatedPolicy.value);
    this.logger.log(
      `Policy '${key}' updated by '${updatedBy || 'system'}': ${JSON.stringify(value)}`,
    );
    // TODO: Emit audit event if available
    return updatedPolicy;
  }

  async createPolicy(dto: CreateSecurityPolicyDto, updatedBy?: string) {
    const createdPolicy = await this.prisma.securityPolicy.create({
      data: { ...dto, value: dto.value as Prisma.InputJsonValue, updatedBy },
    });
    this.policiesCache.set(createdPolicy.key, createdPolicy.value);
    this.logger.log(
      `Policy '${createdPolicy.key}' created by '${updatedBy || 'system'}': ${JSON.stringify(createdPolicy.value)}`,
    );
    return createdPolicy;
  }
  async updatePolicy(
    key: string,
    dto: UpdateSecurityPolicyDto,
    updatedBy?: string,
  ) {
    const updatedPolicy = await this.prisma.securityPolicy.update({
      where: { key },
      data: { ...dto, value: dto.value as Prisma.InputJsonValue, updatedBy },
    });
    this.policiesCache.set(updatedPolicy.key, updatedPolicy.value);
    this.logger.log(
      `Policy '${key}' updated by '${updatedBy || 'system'}': ${JSON.stringify(updatedPolicy.value)}`,
    );
    return updatedPolicy;
  }
}
