// tptech-backend/src/modules/users/__tests__/theme.schema.test.ts
// =============================================================================
//  Sprint 1 de Certificación — Configuración rápida → Tema (C1 + C3).
//
//  Protege el SSOT (backend) de la lista de temas válidos y su validación
//  Zod, que reemplazó la validación manual `VALID_THEMES.includes(...)` del
//  controller `updateMyTheme`.
//
//  ⚠️ Guard de paridad FE ↔ BE: la lista canónica vive duplicada en el
//  frontend (`ThemeContext.tsx` → THEME_DEFS) porque `tptech-shared` no se
//  compila a JS y `node dist` no resuelve el alias en producción. Si este
//  test falla por un cambio en THEME_NAMES, hay que actualizar TAMBIÉN la
//  lista del frontend.
// =============================================================================
import { describe, it, expect } from "vitest";
import { THEME_NAMES, themeSchema } from "../users.schemas.js";

describe("theme — SSOT y validación (C1/C3)", () => {
  it("THEME_NAMES es exactamente la lista canónica (guard de paridad con el frontend)", () => {
    // Si cambiás esta lista, actualizá ThemeContext.tsx (THEME_DEFS) en el frontend.
    expect([...THEME_NAMES]).toEqual(["classic", "dark", "blue", "gray", "emerald"]);
  });

  it("themeSchema acepta cada tema válido", () => {
    for (const theme of THEME_NAMES) {
      const r = themeSchema.safeParse({ theme });
      expect(r.success).toBe(true);
    }
  });

  it("themeSchema rechaza un tema desconocido", () => {
    expect(themeSchema.safeParse({ theme: "rainbow" }).success).toBe(false);
  });

  it("themeSchema rechaza vacío y ausencia de campo", () => {
    expect(themeSchema.safeParse({ theme: "" }).success).toBe(false);
    expect(themeSchema.safeParse({}).success).toBe(false);
  });

  it("themeSchema es estricto en casing (la normalización vive en el controller, no en el schema)", () => {
    // updateMyTheme hace `.trim().toLowerCase()` ANTES de validar; el schema
    // en sí exige el valor exacto en minúsculas.
    expect(themeSchema.safeParse({ theme: "Dark" }).success).toBe(false);
  });
});
