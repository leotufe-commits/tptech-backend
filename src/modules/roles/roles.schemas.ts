// tptech-backend/src/modules/roles/roles.schemas.ts
import { z } from "zod";

/* =========================
   Helpers
========================= */
const roleNameSchema = z
  .string()
  .trim()
  .min(2, "El nombre del rol es muy corto.")
  .max(60, "El nombre del rol es muy largo.");

const idArray = z.array(z.string().min(1));

/* =========================
   POST /roles
========================= */
export const createRoleSchema = z.object({
  name: roleNameSchema,
  // opcional: si no viene, queda sin permisos
  permissionIds: idArray.optional().default([]),
});

/* =========================
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
   PATCH /roles/:id/permissions
   Reemplaza TODO el set de permisos del rol
========================= */
export const updateRolePermissionsSchema = z.object({
  permissionIds: idArray.default([]),
});

export type CreateRoleInput = z.infer<typeof createRoleSchema>;
export type UpdateRoleInput = z.infer<typeof updateRoleSchema>;
export type UpdateRolePermissionsInput = z.infer<typeof updateRolePermissionsSchema>;
