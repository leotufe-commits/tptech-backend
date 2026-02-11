// tptech-backend/src/modules/users/users.schemas.ts
import { z } from "zod";

/* =========================
   UPDATE USER STATUS (ADMIN)
   PATCH /users/:id/status
========================= */
export const updateUserStatusSchema = z.object({
  status: z.enum(["ACTIVE", "PENDING", "BLOCKED"]),
});

/* =========================
   ASSIGN ROLES (ADMIN)
   PUT /users/:id/roles
========================= */
export const assignRolesSchema = z.object({
  roleIds: z.array(z.string().min(1)).default([]),
});

/* =========================
   SET USER OVERRIDE (ADMIN)
   POST /users/:id/overrides
========================= */
export const userOverrideSchema = z.object({
  permissionId: z.string().min(1),
  effect: z.enum(["ALLOW", "DENY"]),
});

/* =========================
   CREATE USER (ADMIN)
   POST /users
   - password opcional:
       • si viene -> puede quedar ACTIVE
       • si NO viene -> lo normal es crear PENDING
   - roleIds opcional
========================= */
export const createUserSchema = z.object({
  email: z.string().email("Email inválido."),
  name: z.string().trim().min(1).optional().nullable(),
  password: z.string().min(6, "La contraseña debe tener al menos 6 caracteres.").optional(),
  roleIds: z.array(z.string().min(1)).optional().default([]),
  status: z.enum(["ACTIVE", "PENDING", "BLOCKED"]).optional(),
});

/* =========================
   TYPES
========================= */
export type UpdateUserStatusInput = z.infer<typeof updateUserStatusSchema>;
export type AssignRolesInput = z.infer<typeof assignRolesSchema>;
export type UserOverrideInput = z.infer<typeof userOverrideSchema>;
export type CreateUserInput = z.infer<typeof createUserSchema>;
