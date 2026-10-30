import { PrismaClient, $Enums } from '@prisma/client';
import * as argon2 from 'argon2';

const prisma = new PrismaClient();

const ARGON2_OPTIONS: argon2.HashOptions = {
  type: argon2.argon2id,
  memoryCost: 19456,
  timeCost: 2,
  parallelism: 1,
};

const ADMIN_ROLE = 'ums:admin';
const DEFAULT_ORG = 'pesanggrahan';

const STARTER_PERMISSIONS = [
  { name: 'users:read', description: 'View users' },
  { name: 'users:write', description: 'Manage users' },
  { name: 'orgs:read', description: 'View organizations' },
  { name: 'orgs:write', description: 'Manage organizations' },
  { name: 'roles:read', description: 'View roles' },
  { name: 'roles:write', description: 'Manage roles' },
  { name: 'permissions:read', description: 'View permissions' },
  { name: 'permissions:write', description: 'Manage permissions' },
  { name: 'content:read', description: 'View content' },
  { name: 'content:write', description: 'Manage content' },
];

async function main() {
  const email = process.env.UMS_ADMIN_EMAIL;
  const password = process.env.UMS_ADMIN_PASSWORD;
  const name = process.env.UMS_ADMIN_NAME ?? 'UMS Admin';

  if (!email || !password) {
    throw new Error(
      'UMS_ADMIN_EMAIL and UMS_ADMIN_PASSWORD must be set to seed the initial admin.',
    );
  }

  // Hash before any write so re-runs stay idempotent yet always honour the
  // current env password.
  const passwordHash = await argon2.hash(password, ARGON2_OPTIONS);

  const adminRole = await prisma.role.upsert({
    where: { name: ADMIN_ROLE },
    create: { name: ADMIN_ROLE, description: 'UMS administrator' },
    update: {},
  });

  // Seed permissions and assign all to ums:admin
  for (const p of STARTER_PERMISSIONS) {
    const perm = await prisma.permission.upsert({
      where: { name: p.name },
      create: { name: p.name, description: p.description },
      update: { description: p.description },
    });

    await prisma.rolePermission.upsert({
      where: { roleId_permissionId: { roleId: adminRole.id, permissionId: perm.id } },
      create: { roleId: adminRole.id, permissionId: perm.id },
      update: {},
    });
  }

  const organization = await prisma.organization.upsert({
    where: { name: DEFAULT_ORG },
    create: { name: DEFAULT_ORG, description: 'Default organization' },
    update: {},
  });

  const existingUser = await prisma.user.findFirst({
    where: { email, domainId: null },
  });

  const user = existingUser
    ? await prisma.user.update({
        where: { id: existingUser.id },
        data: { passwordHash, name },
      })
    : await prisma.user.create({
        data: {
          email,
          passwordHash,
          name,
          status: $Enums.UserStatus.ACTIVE,
          emailVerifiedAt: new Date(),
        },
      });

  await prisma.userRole.upsert({
    where: { userId_roleId: { userId: user.id, roleId: adminRole.id } },
    create: { userId: user.id, roleId: adminRole.id },
    update: {},
  });

  await prisma.orgMember.upsert({
    where: { orgId_userId: { orgId: organization.id, userId: user.id } },
    create: { orgId: organization.id, userId: user.id, role: 'admin' },
    update: { role: 'admin' },
  });

  console.log(
    `Seeded admin ${email} (role ${ADMIN_ROLE}, organization ${DEFAULT_ORG}, with all permissions).`,
  );
}

main()
  .then(async () => {
    await prisma.$disconnect();
  })
  .catch(async (error: unknown) => {
    console.error('Seed failed:', error);
    await prisma.$disconnect();
    process.exit(1);
  });
