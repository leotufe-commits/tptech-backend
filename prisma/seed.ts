// prisma/seed.ts
import { PrismaClient, PermModule, PermAction, UserStatus } from "@prisma/client";
import bcrypt from "bcryptjs";

const prisma = new PrismaClient();

async function main() {
  const JEWELRY_NAME = "TPTech Demo";
  const OWNER_EMAIL = "admin@tptech.com";
  const OWNER_PASSWORD = "admin123";

  /* =========================
     1) JOYERÍA (idempotente)
  ========================= */
  const jewelry =
    (await prisma.jewelry.findFirst({
      where: { name: JEWELRY_NAME },
    })) ??
    (await prisma.jewelry.create({
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
    }));

  /* =========================
     2) PERMISOS (GLOBAL)
  ========================= */
  const permissionsData: { module: PermModule; action: PermAction }[] = [];

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

  const permIdByKey = new Map<string, string>();
  for (const p of allPermissions) permIdByKey.set(`${p.module}:${p.action}`, p.id);

  function pick(modules: PermModule[], actions: PermAction[]) {
    const ids: string[] = [];
    for (const m of modules) {
      for (const a of actions) {
        const id = permIdByKey.get(`${m}:${a}`);
        if (id) ids.push(id);
      }
    }
    return ids;
  }

  // ✅ perfiles
  const ALL_MODULES = Object.values(PermModule) as PermModule[];
  const ALL_ACTIONS = Object.values(PermAction) as PermAction[];

  const OWNER_PERMS = allPermissions.map((p) => p.id);

  // ADMIN: ADMIN en todos los módulos (equivale a todo), pero lo dejamos claro por perfil
  const ADMIN_PERMS = pick(ALL_MODULES, ALL_ACTIONS);

  // STAFF: VIEW + CREATE + EDIT (sin DELETE/EXPORT/ADMIN)
  const STAFF_PERMS = pick(ALL_MODULES, [PermAction.VIEW, PermAction.CREATE, PermAction.EDIT]);

  // READONLY: solo VIEW (y EXPORT si querés habilitarlo, agregá PermAction.EXPORT)
  const READONLY_PERMS = pick(ALL_MODULES, [PermAction.VIEW]);

  const rolesToCreate = [
    { name: "OWNER", isSystem: true, permIds: OWNER_PERMS },
    { name: "ADMIN", isSystem: true, permIds: ADMIN_PERMS },
    { name: "STAFF", isSystem: true, permIds: STAFF_PERMS },
    { name: "READONLY", isSystem: true, permIds: READONLY_PERMS },
  ] as const;

  /* =========================
     3) ROLES + PERMISOS (por joyería)
  ========================= */
  for (const r of rolesToCreate) {
    const role = await prisma.role.upsert({
      where: {
        jewelryId_name: { jewelryId: jewelry.id, name: r.name },
      },
      create: {
        name: r.name,
        jewelryId: jewelry.id,
        isSystem: r.isSystem,
      },
      update: {
        isSystem: r.isSystem,
        deletedAt: null,
      },
    });

    // idempotente: resetea permisos del rol y los recrea
    await prisma.rolePermission.deleteMany({ where: { roleId: role.id } });

    await prisma.rolePermission.createMany({
      data: r.permIds.map((permissionId) => ({
        roleId: role.id,
        permissionId,
      })),
      skipDuplicates: true,
    });
  }

  const ownerRole = await prisma.role.findFirstOrThrow({
    where: { jewelryId: jewelry.id, name: "OWNER", deletedAt: null },
  });

  /* =========================
     4) USUARIO OWNER
  ========================= */
  const passwordHash = await bcrypt.hash(OWNER_PASSWORD, 10);

  const ownerUser = await prisma.user.upsert({
    where: { email: OWNER_EMAIL },
    create: {
      email: OWNER_EMAIL,
      password: passwordHash,
      name: "Admin TPTech",
      status: UserStatus.ACTIVE,
      jewelryId: jewelry.id,
      tokenVersion: 0,
    },
    update: {
      password: passwordHash,
      status: UserStatus.ACTIVE,
      jewelryId: jewelry.id,
    },
  });

  /* =========================
     5) ASIGNAR ROL OWNER (UserRole)
  ========================= */
  // idempotente: deja SOLO el rol OWNER para este usuario
  await prisma.userRole.deleteMany({ where: { userId: ownerUser.id } });

  await prisma.userRole.create({
    data: { userId: ownerUser.id, roleId: ownerRole.id },
  });

  console.log("✅ Seed TPTech OK");
  console.log(`🏪 Jewelry: ${JEWELRY_NAME}`);
  console.log(`👤 Owner: ${OWNER_EMAIL} / ${OWNER_PASSWORD}`);
  console.log("🔐 System roles: OWNER, ADMIN, STAFF, READONLY");
}

main()
  .catch((e) => {
    console.error("❌ Seed error:", e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
