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

export type UpdateUserStatusInput = z.infer<typeof updateUserStatusSchema>;
export type AssignRolesInput = z.infer<typeof assignRolesSchema>;
export type UserOverrideInput = z.infer<typeof userOverrideSchema>;

export default updateUserStatusSchema;
