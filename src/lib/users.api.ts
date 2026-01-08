// tptech-frontend/src/lib/users.api.ts
import { apiFetch } from "./api";

export type RoleLite = { id: string; name: string; isSystem?: boolean };

export type UserLite = {
  id: string;
  email: string;
  name?: string | null;
  status: "ACTIVE" | "BLOCKED" | string;
  avatarUrl?: string | null;
  favoriteWarehouseId?: string | null;
  createdAt?: string;
  updatedAt?: string;
  roles: RoleLite[];
};

export async function listUsers() {
  return apiFetch<{ users: UserLite[] }>("/users", { method: "GET" });
}

export async function listRoles() {
  return apiFetch<{ roles?: RoleLite[] } | RoleLite[]>("/roles", { method: "GET" });
}

export async function updateUserStatus(userId: string, status: "ACTIVE" | "BLOCKED") {
  return apiFetch<{ user: any }>(`/users/${userId}/status`, {
    method: "PATCH",
    body: { status },
  });
}

export async function assignUserRoles(userId: string, roleIds: string[]) {
  return apiFetch<{ ok: true }>(`/users/${userId}/roles`, {
    method: "PUT",
    body: { roleIds },
  });
}
