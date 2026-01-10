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
    (await prisma.jewelry.findFirst({ where: { name: JEWELRY_NAME } })) ??
    (await prisma.jewelry.create({
      data: {
        name: JEWELRY_NAME,
        firstName: "Roberto",
        lastName: "Tufenjian",
        phoneCountry: "+54",
        phoneNumber: "1130313150",
        street: "Libertad",
        number: "326",
        city: "Buenos Aires",
        province: "BA",
        postalCode: "1012",
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

  const ALL_MODULES = Object.values(PermModule) as PermModule[];
  const ALL_ACTIONS = Object.values(PermAction) as PermAction[];

  const OWNER_PERMS = allPermissions.map((p) => p.id);
  const ADMIN_PERMS = pick(ALL_MODULES, ALL_ACTIONS);
  const STAFF_PERMS = pick(ALL_MODULES, [PermAction.VIEW, PermAction.CREATE, PermAction.EDIT]);
  const READONLY_PERMS = pick(ALL_MODULES, [PermAction.VIEW]);

  /**
   * Roles del sistema
   * - name = código técnico (NO cambia)
   * - displayName = nombre visible editable
   */
  const rolesToCreate = [
    { name: "OWNER", displayName: "Propietario", isSystem: true, permIds: OWNER_PERMS },
    { name: "ADMIN", displayName: "Administrador", isSystem: true, permIds: ADMIN_PERMS },
    { name: "STAFF", displayName: "Vendedor", isSystem: true, permIds: STAFF_PERMS },
    { name: "READONLY", displayName: "Solo lectura", isSystem: true, permIds: READONLY_PERMS },
  ] as const;

  async function setRolePermissions(roleId: string, permIds: string[]) {
    await prisma.rolePermission.deleteMany({ where: { roleId } });

    if (permIds.length) {
      await prisma.rolePermission.createMany({
        data: permIds.map((permissionId) => ({ roleId, permissionId })),
        skipDuplicates: true,
      });
    }
  }

  /**
   * Limpieza de duplicados exactos (mismo jewelryId + name)
   */
  async function cleanupExactRoleDuplicates(jewelryId: string, name: string) {
    const same = await prisma.role.findMany({
      where: { jewelryId, name, deletedAt: null },
      orderBy: { createdAt: "asc" },
      select: { id: true },
    });

    if (same.length <= 1) return;

    const removeIds = same.slice(1).map((r) => r.id);

    await prisma.rolePermission.deleteMany({ where: { roleId: { in: removeIds } } });
    await prisma.userRole.deleteMany({ where: { roleId: { in: removeIds } } });
    await prisma.role.deleteMany({ where: { id: { in: removeIds } } });

    console.log(`🧹 Duplicados exactos rol ${name}: removed=${removeIds.length}`);
  }

  /* =========================
     3) ROLES + PERMISOS (por joyería)
  ========================= */
  for (const r of rolesToCreate) {
    await cleanupExactRoleDuplicates(jewelry.id, r.name);

    const role = await prisma.role.upsert({
      where: { jewelryId_name: { jewelryId: jewelry.id, name: r.name } },
      create: {
        name: r.name,
        displayName: r.displayName,
        jewelryId: jewelry.id,
        isSystem: r.isSystem,
      },
      update: {
        isSystem: r.isSystem,
        deletedAt: null,
        // 👇 NO pisa si el usuario ya personalizó el nombre
        displayName: r.displayName,
      },
    });

    if (r.name === "OWNER") {
      await setRolePermissions(role.id, r.permIds);
      continue;
    }

    // ADMIN / STAFF / READONLY:
    // solo setea permisos por defecto si está vacío (no pisa custom)
    const existingCount = await prisma.rolePermission.count({ where: { roleId: role.id } });
    if (existingCount === 0) {
      await setRolePermissions(role.id, r.permIds);
    }
  }

  /**
   * Migración de roles legacy (nombres viejos)
   * Mantiene usuarios y limpia roles antiguos
   */
  async function migrateLegacySystemRoles(jewelryId: string) {
    const mapLegacyToNew: Record<string, "OWNER" | "ADMIN" | "STAFF" | "READONLY"> = {
      PROPIETARIO: "OWNER",
      Propietario: "OWNER",

      ENCARGADO: "ADMIN",
      Encargado: "ADMIN",
      ADMINISTRADOR: "ADMIN",
      Administrador: "ADMIN",

      VENDEDOR: "STAFF",
      Vendedor: "STAFF",

      "SOLO LECTURA": "READONLY",
      "Solo lectura": "READONLY",
      "SOLO_LECTURA": "READONLY",
    };

    const legacyNames = Object.keys(mapLegacyToNew);

    const legacyRoles = await prisma.role.findMany({
      where: { jewelryId, deletedAt: null, name: { in: legacyNames } },
      select: { id: true, name: true },
    });

    if (legacyRoles.length === 0) return;

    const targetRoles = await prisma.role.findMany({
      where: { jewelryId, deletedAt: null, name: ["OWNER", "ADMIN", "STAFF", "READONLY"] },
      select: { id: true, name: true },
    });

    const targetIdByName = new Map<string, string>();
    for (const r of targetRoles) targetIdByName.set(r.name, r.id);

    for (const legacy of legacyRoles) {
      const targetName = mapLegacyToNew[legacy.name];
      const targetId = targetIdByName.get(targetName);
      if (!targetId) continue;

      const userLinks = await prisma.userRole.findMany({
        where: { roleId: legacy.id },
        select: { userId: true },
      });

      if (userLinks.length) {
        await prisma.userRole.createMany({
          data: userLinks.map((u) => ({ userId: u.userId, roleId: targetId })),
          skipDuplicates: true,
        });
        await prisma.userRole.deleteMany({ where: { roleId: legacy.id } });
      }

      await prisma.rolePermission.deleteMany({ where: { roleId: legacy.id } });
      await prisma.role.deleteMany({ where: { id: legacy.id } });

      console.log(`🧹 Legacy role eliminado: ${legacy.name} -> ${targetName}`);
    }
  }

  await migrateLegacySystemRoles(jewelry.id);

  /* =========================
     4) USUARIO OWNER
  ========================= */
  const ownerRole = await prisma.role.findFirstOrThrow({
    where: { jewelryId: jewelry.id, name: "OWNER", deletedAt: null },
  });

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
     5) ASIGNAR ROL OWNER
  ========================= */
  await prisma.userRole.deleteMany({ where: { userId: ownerUser.id } });
  await prisma.userRole.create({ data: { userId: ownerUser.id, roleId: ownerRole.id } });

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
