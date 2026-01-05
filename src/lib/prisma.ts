import { PrismaClient } from "@prisma/client";
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
 * En index.ts va ANTES de tus rutas.
 */
export function requestContextMiddleware(_req: any, _res: any, next: any) {
  als.run({ tenantId: undefined, userId: undefined }, () => next());
}

/**
 * Helpers para setear/limpiar contexto desde middlewares
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
 * Prisma base singleton
 */
const globalForPrisma = globalThis as unknown as { prisma?: PrismaClient };

const basePrisma =
  globalForPrisma.prisma ??
  new PrismaClient({
    // log: ["error", "warn"],
  });

if (process.env.NODE_ENV !== "production") {
  globalForPrisma.prisma = basePrisma;
}

/**
 * ✅ Multi-tenant enforcement (Prisma v6) via $extends
 *
 * - NO tocamos: findUnique / update / delete (requieren where único)
 * - Forzamos tenant en:
 *   - findMany / findFirst
 *   - updateMany / deleteMany
 *   - create / createMany
 */
const TENANT_MODELS = new Set<string>(["User", "Role", "Permission", "Warehouse"]);

const TENANT_FIELD_BY_MODEL: Record<string, string> = {
  User: "jewelryId",
  Role: "jewelryId",
  Permission: "jewelryId",
  Warehouse: "jewelryId",
};

function isTenantModel(model?: string | undefined) {
  return !!model && TENANT_MODELS.has(model);
}

function tenantFieldFor(model: string) {
  return TENANT_FIELD_BY_MODEL[model] || "jewelryId";
}

function mergeWhereWithTenant(where: any, tenantField: string, tenantId: string) {
  return { ...(where ?? {}), [tenantField]: tenantId };
}

function addTenantToCreateData(data: any, tenantField: string, tenantId: string) {
  return { ...(data ?? {}), [tenantField]: tenantId };
}

export const prisma = basePrisma.$extends({
  query: {
    $allModels: {
      async $allOperations({ model, operation, args, query }) {
        const ctx = getRequestContext();

        // si no hay tenant en contexto, no tocamos
        if (!ctx?.tenantId) return query(args);

        // si no es modelo multi-tenant, no tocamos
        if (!isTenantModel(model)) return query(args);

        const tenantField = tenantFieldFor(model!);
        const tenantId = ctx.tenantId;

        const a: any = args ?? {};

        if (operation === "findMany" || operation === "findFirst") {
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
          const data = Array.isArray(a.data) ? a.data : [];
          a.data = data.map((row: any) => addTenantToCreateData(row, tenantField, tenantId));
          return query(a);
        }

        return query(args);
      },
    },
  },
}) as unknown as PrismaClient;
