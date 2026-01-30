// tptech-backend/src/modules/users/users.roles.schemas.ts
import { z } from "zod";

/* =========================
   Helpers
========================= */
const idArray = z.array(z.string().min(1)).default([]);

/**
 * Nombre de rol:
 * - trim
 * - 2..60 chars (ajustalo si querés)
 */
const roleNameSchema = z
  .string()
  .trim()
  .min(2, "El nombre del rol es muy corto.")
  .max(60, "El nombre del rol es muy largo.");

/* =========================
   CREATE ROLE (ADMIN)
   POST /roles
========================= */
export const createRoleSchema = z.object({
  name: roleNameSchema,
  /**
   * permissionIds opcional:
   * si viene vacío -> rol sin permisos (válido)
   */
  permissionIds: idArray.optional(),
});

/* =========================
   UPDATE ROLE (ADMIN)
   PATCH /roles/:id
========================= */
export const updateRoleSchema = z
  .object({
    name: roleNameSchema.optional(),
  })
  .refine((v) => Object.keys(v).length > 0, {
    message: "No hay campos para actualizar.",
  });

/* =========================
   SET ROLE PERMISSIONS (ADMIN)
   PUT /roles/:id/permissions
   - reemplaza TODO el set de permisos del rol
========================= */
export const setRolePermissionsSchema = z.object({
  permissionIds: idArray,
});

/* =========================
   CLONE ROLE (ADMIN) (opcional)
   POST /roles/:id/clone
   - clona nombre (con sufijo) + permisos
========================= */
export const cloneRoleSchema = z.object({
  /**
   * Si no viene, el controller puede setear algo tipo:
   * `${role.name} (copia)`
   */
  name: roleNameSchema.optional(),
});

/* =========================
   Types
========================= */
export type CreateRoleInput = z.infer<typeof createRoleSchema>;
export type UpdateRoleInput = z.infer<typeof updateRoleSchema>;
export type SetRolePermissionsInput = z.infer<typeof setRolePermissionsSchema>;
export type CloneRoleInput = z.infer<typeof cloneRoleSchema>;
