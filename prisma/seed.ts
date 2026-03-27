// prisma/seed.ts
import "dotenv/config";
import { PrismaClient, UserStatus } from "@prisma/client";
import { PrismaPg } from "@prisma/adapter-pg";
import bcrypt from "bcryptjs";
import { ensureGlobalPermissions, ensureSystemRoles, ensureSystemDefaults } from "../src/lib/initTenantDefaults.js";

const adapter = new PrismaPg({ connectionString: process.env.DATABASE_URL! });
const prisma = new PrismaClient({ adapter });

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
     2) PERMISOS + ROLES (GLOBAL + POR JOYERÍA)
  ========================= */
  // Limpieza de duplicados exactos (mismo jewelryId + name) — solo necesario en seed
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
  for (const name of ["OWNER", "ADMIN", "STAFF", "READONLY"] as const) {
    await cleanupExactRoleDuplicates(jewelry.id, name);
  }

  const permIdByKey = await ensureGlobalPermissions(prisma as any);
  const { ownerRoleId } = await ensureSystemRoles(prisma as any, jewelry.id, permIdByKey);
  await ensureSystemDefaults(prisma as any, jewelry.id);

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
  const passwordHash = await bcrypt.hash(OWNER_PASSWORD, 10);

  const ownerUser = await prisma.user.upsert({
    where: { jewelryId_email: { jewelryId: jewelry.id, email: OWNER_EMAIL } },
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
    },
  });

  /* =========================
     5) ASIGNAR ROL OWNER
  ========================= */
  await prisma.userRole.deleteMany({ where: { userId: ownerUser.id } });
  await prisma.userRole.create({ data: { userId: ownerUser.id, roleId: ownerRoleId } });

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
