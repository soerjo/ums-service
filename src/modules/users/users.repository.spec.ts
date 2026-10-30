import { UsersRepository } from './users.repository.js';
import { PrismaService } from '../../prisma/prisma.service.js';

describe('UsersRepository', () => {
  let repository: UsersRepository;
  let findFirst: jest.Mock;

  beforeEach(() => {
    findFirst = jest.fn();
    const prisma = {
      user: {
        findFirst,
      },
    } as unknown as PrismaService;

    repository = new UsersRepository(prisma);
  });

  describe('findByEmail', () => {
    it('queries by email only when domainId is undefined', async () => {
      findFirst.mockResolvedValue({ id: 'user-1', email: 'test@example.com' });

      const result = await repository.findByEmail('test@example.com');

      expect(findFirst).toHaveBeenCalledWith({
        where: { email: 'test@example.com' },
      });
      expect(result).toEqual({ id: 'user-1', email: 'test@example.com' });
    });

    it('queries with domainId: null when domainId is null', async () => {
      findFirst.mockResolvedValue({
        id: 'user-2',
        email: 'test@example.com',
        domainId: null,
      });

      const result = await repository.findByEmail('test@example.com', null);

      expect(findFirst).toHaveBeenCalledWith({
        where: { email: 'test@example.com', domainId: null },
      });
      expect(result).toEqual({
        id: 'user-2',
        email: 'test@example.com',
        domainId: null,
      });
    });

    it('queries with domainId when domainId is a string', async () => {
      findFirst.mockResolvedValue({
        id: 'user-3',
        email: 'test@example.com',
        domainId: 'dom-1',
      });

      const result = await repository.findByEmail('test@example.com', 'dom-1');

      expect(findFirst).toHaveBeenCalledWith({
        where: { email: 'test@example.com', domainId: 'dom-1' },
      });
      expect(result).toEqual({
        id: 'user-3',
        email: 'test@example.com',
        domainId: 'dom-1',
      });
    });
  });

  describe('findByEmailAndDomain', () => {
    it('queries with domainId: null when domainId is null', async () => {
      findFirst.mockResolvedValue({
        id: 'user-2',
        email: 'test@example.com',
        domainId: null,
      });

      const result = await repository.findByEmailAndDomain(
        'test@example.com',
        null,
      );

      expect(findFirst).toHaveBeenCalledWith({
        where: { email: 'test@example.com', domainId: null },
      });
      expect(result).toEqual({
        id: 'user-2',
        email: 'test@example.com',
        domainId: null,
      });
    });

    it('queries with domainId when domainId is a string', async () => {
      findFirst.mockResolvedValue({
        id: 'user-3',
        email: 'test@example.com',
        domainId: 'dom-1',
      });

      const result = await repository.findByEmailAndDomain(
        'test@example.com',
        'dom-1',
      );

      expect(findFirst).toHaveBeenCalledWith({
        where: { email: 'test@example.com', domainId: 'dom-1' },
      });
      expect(result).toEqual({
        id: 'user-3',
        email: 'test@example.com',
        domainId: 'dom-1',
      });
    });
  });
});
