// tptech-backend/src/lib/prisma.ts
import "dotenv/config";
import type { Request, Response, NextFunction } from "express";

import { PrismaClient } from "@prisma/client";
import { PrismaPg } from "@prisma/adapter-pg";
import { AsyncLocalStorage } from "node:async_hooks";

/**
 * Contexto por request (multi-tenant).
 * Guardamos tenantId (jewelryId) y userId.
 */
type RequestContext = {
  tenantId?: string;
  userId?: string;
};

const als = new AsyncLocalStorage<RequestContext>();

export function getRequestContext() {
  return als.getStore();
}

/**
 * Middleware que inicializa el contexto por request.
 */
export function requestContextMiddleware(_req: Request, _res: Response, next: NextFunction) {
  als.run({ tenantId: undefined, userId: undefined }, () => next());
}

/**
 * Helpers de contexto
 */
export function setContextUserId(userId: string) {
  const store = als.getStore();
  if (store) store.userId = userId;
}

export function setContextTenantId(tenantId: string) {
  const store = als.getStore();
  if (store) store.tenantId = tenantId;
}

export function clearContextUserId() {
  const store = als.getStore();
  if (store) store.userId = undefined;
}

export function clearContextTenantId() {
  const store = als.getStore();
  if (store) store.tenantId = undefined;
}

export function clearRequestContext() {
  const store = als.getStore();
  if (!store) return;
  store.userId = undefined;
  store.tenantId = undefined;
}

/**
 * Prisma singleton + adapter
 */
type PrismaGlobal = {
  prisma?: PrismaClient;
  prismaAdapter?: PrismaPg;
};

const globalForPrisma = globalThis as unknown as PrismaGlobal;

function getAdapter(): PrismaPg {
  const url = process.env.DATABASE_URL;
  if (!url) throw new Error("DATABASE_URL no está definida");

  // 🔒 Reusar adapter en dev para evitar múltiples conexiones
  if (globalForPrisma.prismaAdapter) return globalForPrisma.prismaAdapter;

  // PrismaPg acepta connectionString pero los tipos a veces no calzan perfecto según versión
  const adapter = new PrismaPg({ connectionString: url } as any);
  globalForPrisma.prismaAdapter = adapter;
  return adapter;
}

const basePrisma: PrismaClient =
  globalForPrisma.prisma ??
  new PrismaClient({
    adapter: getAdapter(),
  });

if (process.env.NODE_ENV !== "production") {
  globalForPrisma.prisma = basePrisma;
}

/**
 * Multi-tenant enforcement
 */
const TENANT_MODELS = new Set<string>(["User", "Role", "Warehouse", "AuditLog"]);

const TENANT_FIELD_BY_MODEL: Record<string, string> = {
  User: "jewelryId",
  Role: "jewelryId",
  Warehouse: "jewelryId",
  AuditLog: "jewelryId",
};

function isTenantModel(model?: string) {
  return !!model && TENANT_MODELS.has(model);
}

function tenantFieldFor(model: string) {
  return TENANT_FIELD_BY_MODEL[model] ?? "jewelryId";
}

function mergeWhereWithTenant(where: any, field: string, tenantId: string) {
  return { ...(where ?? {}), [field]: tenantId };
}

function addTenantToCreateData(data: any, field: string, tenantId: string) {
  return { ...(data ?? {}), [field]: tenantId };
}

/**
 * Prisma con enforcement multi-tenant
 *
 * ⚠️ Importante:
 * - Tipamos explícitamente el parámetro de $allOperations como `any`
 *   para evitar TS7006 (implicit any) en build estricto de Render.
 * - Exportamos `prisma` como PrismaClient para evitar casts problemáticos.
 */
export const prisma: PrismaClient = basePrisma.$extends({
  query: {
    $allModels: {
      async $allOperations(params: any) {
        const { model, operation, args, query } = params as {
          model?: string;
          operation: string;
          args: any;
          query: (a: any) => any;
        };

        const ctx = getRequestContext();
        if (!ctx?.tenantId) return query(args);
        if (!isTenantModel(model)) return query(args);

        const tenantId = ctx.tenantId;
        const tenantField = tenantFieldFor(model!);
        const a: any = args ?? {};

        if (operation === "findMany" || operation === "findFirst" || operation === "findFirstOrThrow") {
          a.where = mergeWhereWithTenant(a.where, tenantField, tenantId);
          return query(a);
        }

        if (operation === "updateMany" || operation === "deleteMany") {
          a.where = mergeWhereWithTenant(a.where, tenantField, tenantId);
          return query(a);
        }

        if (operation === "create") {
          a.data = addTenantToCreateData(a.data, tenantField, tenantId);
          return query(a);
        }

        if (operation === "createMany") {
          a.data = (Array.isArray(a.data) ? a.data : []).map((row: any) =>
            addTenantToCreateData(row, tenantField, tenantId)
          );
          return query(a);
        }

        if (operation === "upsert") {
          a.create = addTenantToCreateData(a.create, tenantField, tenantId);
          a.where = mergeWhereWithTenant(a.where, tenantField, tenantId);
          return query(a);
        }

        return query(args);
      },
    },
  },
}) as unknown as PrismaClient;
