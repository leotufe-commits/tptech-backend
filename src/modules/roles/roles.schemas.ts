// tptech-backend/src/modules/roles/roles.schemas.ts
import { z } from "zod";

/**
 * Crear rol
 * - name: nombre visible y técnico (displayName + name)
 */
export const createRoleSchema = z.object({
  name: z
    .string()
    .trim()
    .min(2, "El nombre debe tener al menos 2 caracteres")
    .max(50, "El nombre no puede superar los 50 caracteres"),
});

/**
 * Renombrar rol
 * - mismo criterio que create
 */
export const updateRoleSchema = z.object({
  name: z
    .string()
    .trim()
    .min(2, "El nombre debe tener al menos 2 caracteres")
    .max(50, "El nombre no puede superar los 50 caracteres"),
});

/**
 * Actualizar permisos del rol
 * - permissionIds puede venir vacío (quitar todos)
 */
export const updateRolePermissionsSchema = z.object({
  permissionIds: z.array(z.string().cuid()).optional().default([]),
});
