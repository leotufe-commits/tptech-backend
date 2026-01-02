import {
  PrismaClient,
  PermModule,
  PermAction,
  UserStatus,
} from "@prisma/client";
import bcrypt from "bcryptjs";

const prisma = new PrismaClient();

async function main() {
  const JEWELRY_NAME = "TPTech Demo";
  const OWNER_EMAIL = "admin@tptech.com";
  const OWNER_PASSWORD = "admin123";

  // 1) JOYERÍA (idempotente)
  let jewelry = await prisma.jewelry.findFirst({
    where: { name: JEWELRY_NAME },
  });

  if (!jewelry) {
    jewelry = await prisma.jewelry.create({
      data: {
        name: JEWELRY_NAME,
        firstName: "Roberto",
        lastName: "Tufenjian",
        phoneCountry: "+54",
        phoneNumber: "000000000",
        street: "Demo",
        number: "123",
        city: "Buenos Aires",
        province: "BA",
        postalCode: "0000",
        country: "Argentina",
      },
    });
  }

  // 2) PERMISOS (idempotente)
  const permissionsData = [];
  for (const module of Object.values(PermModule)) {
    for (const action of Object.values(PermAction)) {
      permissionsData.push({ module, action });
    }
  }

  await prisma.permission.createMany({
    data: permissionsData,
    skipDuplicates: true,
  });

  const allPermissions = await prisma.permission.findMany();

  // 3) ROL OWNER (idempotente por @@unique([jewelryId, name]))
  const ownerRole = await prisma.role.upsert({
    where: {
      jewelryId_name: {
        jewelryId: jewelry.id,
        name: "OWNER",
      },
    },
    create: {
      name: "OWNER",
      jewelryId: jewelry.id,
      isSystem: true,
    },
    update: {
      isSystem: true,
    },
  });

  // 4) ROLE PERMISSIONS (idempotente)
  await prisma.rolePermission.createMany({
    data: allPermissions.map((p) => ({
      roleId: ownerRole.id,
      permissionId: p.id,
    })),
    skipDuplicates: true,
  });

  // 5) USUARIO OWNER (idempotente por email unique)
  const passwordHash = await bcrypt.hash(OWNER_PASSWORD, 10);

  await prisma.user.upsert({
    where: { email: OWNER_EMAIL },
    create: {
      email: OWNER_EMAIL,
      passwordHash,
      firstName: "Admin",
      lastName: "TPTech",
      status: UserStatus.ACTIVE,
      jewelryId: jewelry.id,
      roleId: ownerRole.id,
    },
    update: {
      passwordHash,
      firstName: "Admin",
      lastName: "TPTech",
      status: UserStatus.ACTIVE,
      jewelryId: jewelry.id,
      roleId: ownerRole.id,
    },
  });

  console.log("✅ Seed completado");
  console.log(`🏪 Jewelry: ${JEWELRY_NAME}`);
  console.log(`👤 Owner: ${OWNER_EMAIL} / ${OWNER_PASSWORD}`);
}

main()
  .catch((e) => {
    console.error("❌ Seed error:", e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
