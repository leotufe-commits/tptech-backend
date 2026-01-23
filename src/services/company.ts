// tptech-frontend/src/services/company.ts
import { apiFetch } from "../lib/api";

export type CompanySecuritySettings = {
  quickSwitchEnabled: boolean;
  pinLockEnabled: boolean;
  pinLockTimeoutSec: number;
  pinLockRequireOnUserSwitch: boolean;
};

export async function fetchCompanySecuritySettings(): Promise<CompanySecuritySettings> {
  const res = await apiFetch("/company/settings/security", { method: "GET" });
  const data = await res.json();
  return data.security as CompanySecuritySettings;
}

export async function updateCompanySecuritySettings(
  patch: Partial<CompanySecuritySettings>
): Promise<CompanySecuritySettings> {
  const res = await apiFetch("/company/settings/security", {
    method: "PATCH",
    body: JSON.stringify(patch),
  });
  const data = await res.json();
  return data.security as CompanySecuritySettings;
}
