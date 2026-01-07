import { z } from "zod";

export const createRoleSchema = z.object({
  name: z.string().min(2).max(50),
});

export const updateRoleSchema = z.object({
  name: z.string().min(2).max(50),
});

export const updateRolePermissionsSchema = z.object({
  permissionIds: z.array(z.string().cuid()).default([]),
});
