// tptech-backend/src/lib/prisma.ts
import "dotenv/config";
import type { Request, Response, NextFunction } from "express";
import { PrismaClient } from "@prisma/client";
import { PrismaPg } from "@prisma/adapter-pg";
import { AsyncLocalStorage } from "node:async_hooks";

/* =========================
   REQUEST CONTEXT (ALS)
========================= */
type RequestContext = {
  tenantId?: string;
  userId?: string;
};

const als = new AsyncLocalStorage<RequestContext>();

export function getRequestContext() {
  return als.getStore();
}

export function requestContextMiddleware(
  _req: Request,
  _res: Response,
  next: NextFunction
) {
  als.run({ tenantId: undefined, userId: undefined }, () => next());
}

export function setContextUserId(userId: string) {
  const store = als.getStore();
  if (store) store.userId = userId;
}

export function setContextTenantId(tenantId: string) {
  const store = als.getStore();
  if (store) store.tenantId = tenantId;
}

export function clearRequestContext() {
  const store = als.getStore();
  if (!store) return;
  store.userId = undefined;
  store.tenantId = undefined;
}

/* =========================
   PRISMA CLIENT (PG)
========================= */
type PrismaGlobal = {
  prisma?: PrismaClient;
  adapter?: PrismaPg;
};

const globalForPrisma = globalThis as unknown as PrismaGlobal;

function getAdapter(): PrismaPg {
  const url = process.env.DATABASE_URL;
  if (!url) throw new Error("DATABASE_URL no está definida");

  if (globalForPrisma.adapter) return globalForPrisma.adapter;

  const adapter = new PrismaPg({ connectionString: url } as any);
  globalForPrisma.adapter = adapter;
  return adapter;
}

const basePrisma =
  globalForPrisma.prisma ??
  new PrismaClient({
    adapter: getAdapter(),
  });

if (process.env.NODE_ENV !== "production") {
  globalForPrisma.prisma = basePrisma;
}

/* =========================
   MULTI-TENANT ENFORCEMENT
========================= */
const TENANT_MODELS = new Set(["User", "Role", "Warehouse", "AuditLog"]);

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
 * Prisma extendido:
 * - agrega tenantId automáticamente
 * - filtra por tenantId en queries
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
        const field = tenantFieldFor(model!);
        const a: any = args ?? {};

        if (
          operation === "findMany" ||
          operation === "findFirst" ||
          operation === "findFirstOrThrow"
        ) {
          a.where = mergeWhereWithTenant(a.where, field, tenantId);
          return query(a);
        }

        if (operation === "updateMany" || operation === "deleteMany") {
          a.where = mergeWhereWithTenant(a.where, field, tenantId);
          return query(a);
        }

        if (operation === "create") {
          a.data = addTenantToCreateData(a.data, field, tenantId);
          return query(a);
        }

        if (operation === "createMany") {
          a.data = (Array.isArray(a.data) ? a.data : []).map((row: any) =>
            addTenantToCreateData(row, field, tenantId)
          );
          return query(a);
        }

        if (operation === "upsert") {
          a.create = addTenantToCreateData(a.create, field, tenantId);
          a.where = mergeWhereWithTenant(a.where, field, tenantId);
          return query(a);
        }

        return query(args);
      },
    },
  },
}) as unknown as PrismaClient;
