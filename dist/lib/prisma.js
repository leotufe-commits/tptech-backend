// tptech-backend/src/lib/prisma.ts
import "dotenv/config";
import { PrismaClient } from "@prisma/client";
import { PrismaPg } from "@prisma/adapter-pg";
import { AsyncLocalStorage } from "node:async_hooks";
const als = new AsyncLocalStorage();
export function getRequestContext() {
    return als.getStore();
}
/**
 * Middleware que inicializa el contexto por request.
 * En app.ts (o server.ts) va ANTES de tus rutas.
 */
export function requestContextMiddleware(_req, _res, next) {
    als.run({ tenantId: undefined, userId: undefined }, () => next());
}
/**
 * Helpers para setear/limpiar contexto desde middlewares
 */
export function setContextUserId(userId) {
    const store = als.getStore();
    if (store)
        store.userId = userId;
}
export function setContextTenantId(tenantId) {
    const store = als.getStore();
    if (store)
        store.tenantId = tenantId;
}
export function clearContextUserId() {
    const store = als.getStore();
    if (store)
        store.userId = undefined;
}
export function clearContextTenantId() {
    const store = als.getStore();
    if (store)
        store.tenantId = undefined;
}
export function clearRequestContext() {
    const store = als.getStore();
    if (!store)
        return;
    store.userId = undefined;
    store.tenantId = undefined;
}
const globalForPrisma = globalThis;
function getAdapter() {
    const url = process.env.DATABASE_URL;
    if (!url)
        throw new Error("❌ DATABASE_URL no está seteada en el entorno");
    return globalForPrisma.prismaAdapter ?? new PrismaPg({ connectionString: url });
}
const basePrisma = globalForPrisma.prisma ??
    new PrismaClient({
        adapter: getAdapter(),
        // log: ["error", "warn"],
    });
if (process.env.NODE_ENV !== "production") {
    globalForPrisma.prisma = basePrisma;
    globalForPrisma.prismaAdapter = getAdapter();
}
/**
 * ✅ Multi-tenant enforcement via $extends
 *
 * Nota: Permission es GLOBAL (catálogo) y NO tiene jewelryId -> no debe filtrarse por tenant.
 */
const TENANT_MODELS = new Set([
    "User",
    "Role",
    "Warehouse",
    "AuditLog",
]);
const TENANT_FIELD_BY_MODEL = {
    User: "jewelryId",
    Role: "jewelryId",
    Warehouse: "jewelryId",
    AuditLog: "jewelryId",
};
function isTenantModel(model) {
    return !!model && TENANT_MODELS.has(model);
}
function tenantFieldFor(model) {
    return TENANT_FIELD_BY_MODEL[model] ?? "jewelryId";
}
function mergeWhereWithTenant(where, tenantField, tenantId) {
    if (!tenantField)
        return where ?? {};
    return { ...(where ?? {}), [tenantField]: tenantId };
}
function addTenantToCreateData(data, tenantField, tenantId) {
    if (!tenantField)
        return data ?? {};
    return { ...(data ?? {}), [tenantField]: tenantId };
}
export const prisma = basePrisma.$extends({
    query: {
        $allModels: {
            async $allOperations({ model, operation, args, query }) {
                const ctx = getRequestContext();
                // si no hay tenant en contexto, no tocamos
                if (!ctx?.tenantId)
                    return query(args);
                // si no es modelo multi-tenant, no tocamos
                if (!isTenantModel(model))
                    return query(args);
                const tenantId = ctx.tenantId;
                const tenantField = tenantFieldFor(model);
                const a = args ?? {};
                // reads
                if (operation === "findMany" || operation === "findFirst" || operation === "findFirstOrThrow") {
                    a.where = mergeWhereWithTenant(a.where, tenantField, tenantId);
                    return query(a);
                }
                // bulk writes
                if (operation === "updateMany" || operation === "deleteMany") {
                    a.where = mergeWhereWithTenant(a.where, tenantField, tenantId);
                    return query(a);
                }
                // creates
                if (operation === "create") {
                    a.data = addTenantToCreateData(a.data, tenantField, tenantId);
                    return query(a);
                }
                if (operation === "createMany") {
                    const data = Array.isArray(a.data) ? a.data : [];
                    a.data = data.map((row) => addTenantToCreateData(row, tenantField, tenantId));
                    return query(a);
                }
                // upsert
                if (operation === "upsert") {
                    a.create = addTenantToCreateData(a.create, tenantField, tenantId);
                    a.where = mergeWhereWithTenant(a.where, tenantField, tenantId);
                    return query(a);
                }
                return query(args);
            },
        },
    },
});
//# sourceMappingURL=prisma.js.map