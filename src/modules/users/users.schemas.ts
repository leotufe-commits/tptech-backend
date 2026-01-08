// tptech-backend/src/modules/users/users.schemas.ts
import { z } from "zod";

export const updateUserStatusSchema = z.object({
  status: z.enum(["ACTIVE", "BLOCKED"]),
});

export const assignRolesSchema = z.object({
  roleIds: z.array(z.string().min(1)),
});

export const userOverrideSchema = z.object({
  permissionId: z.string().min(1),
  effect: z.enum(["ALLOW", "DENY"]),
});

/**
 * Crear usuario (ADMIN)
 * - password opcional: si viene, crea ACTIVE con password hash
 * - si NO viene: crea PENDING (sin password) para luego setear contraseña por reset flow
 * - roleIds opcional
 */
export const createUserSchema = z.object({
  email: z.string().email(),
  name: z.string().min(1).optional().nullable(),
  password: z.string().min(6).optional(),
  roleIds: z.array(z.string().min(1)).optional().default([]),
  status: z.enum(["ACTIVE", "BLOCKED"]).optional(), // opcional; si no viene lo decide el controller
});

export type UpdateUserStatusInput = z.infer<typeof updateUserStatusSchema>;
export type AssignRolesInput = z.infer<typeof assignRolesSchema>;
export type UserOverrideInput = z.infer<typeof userOverrideSchema>;
export type CreateUserInput = z.infer<typeof createUserSchema>;

export default updateUserStatusSchema;
