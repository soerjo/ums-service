import { Injectable } from '@nestjs/common';
import { DomainsRepository } from './domains.repository.js';
import { CreateDomainDto } from './dto/create-domain.dto.js';
import { UpdateDomainDto } from './dto/update-domain.dto.js';
import { hashPassword } from '../../common/utils/password.util.js';

@Injectable()
export class DomainsService {
  constructor(private readonly domainsRepository: DomainsRepository) {}

  async create(dto: CreateDomainDto) {
    const passwordHash = await hashPassword(dto.adminPassword);
    return this.domainsRepository.createWithAdmin(
      {
        name: dto.name,
        origin: dto.origin,
        apiKey: dto.apiKey,
      },
      {
        email: dto.adminEmail,
        passwordHash,
        name: dto.adminName,
      },
    );
  }

  async findAll() {
    return this.domainsRepository.findAll();
  }

  async findById(id: string) {
    return this.domainsRepository.findById(id);
  }

  async findByOrigin(origin: string) {
    return this.domainsRepository.findByOrigin(origin);
  }

  async findByApiKey(apiKey: string) {
    return this.domainsRepository.findByApiKey(apiKey);
  }

  async update(id: string, dto: UpdateDomainDto) {
    return this.domainsRepository.update(id, dto);
  }

  async delete(id: string) {
    return this.domainsRepository.delete(id);
  }
}
