// tptech-backend/src/lib/__tests__/tenantMailContext.test.ts
// =============================================================================
// Etapa 1 (mail sender real) — tests del SSOT del contexto de mail por tenant.
//
// Cubre:
//   · `composeFromHeader` (pura): combinaciones de senderName + fromEmail,
//     quoteado de display names con caracteres especiales, escape de
//     comillas internas, fallback a undefined cuando falta el email.
//   · `resolveReplyTo` (pura): fallback chain `emailReplyTo` → `email` →
//     undefined; trim; vacios.
//   · `resolveTenantMailContext` (con prisma mockeado): lee los 4 campos
//     correctos del Jewelry, respeta `MAIL_FROM` env, devuelve el shape
//     esperado para los callers (sendSaleByEmail / sendSaleDraftByEmail).
// =============================================================================

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const mockPrisma = vi.hoisted(() => ({
  jewelry: { findUnique: vi.fn() },
}));
vi.mock("../prisma.js", () => ({ prisma: mockPrisma }));

import {
  composeFromHeader,
  resolveReplyTo,
  resolveTenantMailContext,
} from "../tenantMailContext.js";

// ─────────────────────────────────────────────────────────────────────────────
// 1) composeFromHeader — pura, sin prisma
// ─────────────────────────────────────────────────────────────────────────────

describe("composeFromHeader (puro)", () => {
  it("nombre + email → '\"Nombre\" <email>' (quoteado por contener espacios)", () => {
    expect(composeFromHeader("Joyería Pérez", "no-reply@tptech.local"))
      .toBe('"Joyería Pérez" <no-reply@tptech.local>');
  });

  it("nombre sin espacios ni caracteres especiales → 'Nombre <email>' (sin quotes)", () => {
    expect(composeFromHeader("Tuport", "ventas@tuport.com"))
      .toBe("Tuport <ventas@tuport.com>");
  });

  it("nombre vacio → solo el email plano", () => {
    expect(composeFromHeader("", "no-reply@tptech.local"))
      .toBe("no-reply@tptech.local");
    expect(composeFromHeader("   ", "no-reply@tptech.local"))
      .toBe("no-reply@tptech.local");
  });

  it("email vacio o undefined → undefined (no se puede componer header)", () => {
    expect(composeFromHeader("Joyería Pérez", "")).toBeUndefined();
    expect(composeFromHeader("Joyería Pérez", undefined)).toBeUndefined();
    expect(composeFromHeader("Joyería Pérez", null)).toBeUndefined();
  });

  it("nombre con comillas internas → escapa con backslash", () => {
    // RFC 5322: comillas dentro de un quoted-string deben escaparse con `\`.
    expect(composeFromHeader('Joyería "El Sol"', "x@y.z"))
      .toBe('"Joyería \\"El Sol\\"" <x@y.z>');
  });

  it("nombre con caracteres comunes de email (@, <, >) → quoteado", () => {
    expect(composeFromHeader("Soporte (general)", "x@y.z"))
      .toBe('"Soporte (general)" <x@y.z>');
  });

  it("trim de espacios en bordes (nombre y email)", () => {
    expect(composeFromHeader("  Tuport  ", "  ventas@tuport.com  "))
      .toBe("Tuport <ventas@tuport.com>");
  });

  it("null en cualquiera de los dos params se trata como vacio", () => {
    expect(composeFromHeader(null, "x@y.z")).toBe("x@y.z");
    expect(composeFromHeader("Nombre", null)).toBeUndefined();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 2) resolveReplyTo — pura, fallback chain
// ─────────────────────────────────────────────────────────────────────────────

describe("resolveReplyTo (puro)", () => {
  it("emailReplyTo configurado → gana", () => {
    expect(resolveReplyTo("ventas@joy.com", "info@joy.com"))
      .toBe("ventas@joy.com");
  });

  it("emailReplyTo vacio → fallback a email legacy", () => {
    expect(resolveReplyTo("", "info@joy.com")).toBe("info@joy.com");
    expect(resolveReplyTo("   ", "info@joy.com")).toBe("info@joy.com");
    expect(resolveReplyTo(null, "info@joy.com")).toBe("info@joy.com");
  });

  it("ambos vacios → undefined (no agrega header Reply-To)", () => {
    expect(resolveReplyTo("", "")).toBeUndefined();
    expect(resolveReplyTo(null, null)).toBeUndefined();
    expect(resolveReplyTo(undefined, undefined)).toBeUndefined();
  });

  it("trim aplicado a ambos campos", () => {
    expect(resolveReplyTo("  ventas@joy.com  ", "")).toBe("ventas@joy.com");
    expect(resolveReplyTo("", "  info@joy.com  ")).toBe("info@joy.com");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 3) resolveTenantMailContext — con prisma mockeado + env MAIL_FROM
// ─────────────────────────────────────────────────────────────────────────────

describe("resolveTenantMailContext", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    delete (process.env as Record<string, string | undefined>).MAIL_FROM;
  });

  it("happy path: senderName + replyTo dedicado + MAIL_FROM env → headers compuestos", async () => {
    process.env.MAIL_FROM = "no-reply@tptech.local";
    mockPrisma.jewelry.findUnique.mockResolvedValueOnce({
      emailEnabled:    true,
      emailSenderName: "Joyería Tuport",
      emailReplyTo:    "ventas@joyeriatuport.com",
      email:           "info@joyeriatuport.com",
    });

    const ctx = await resolveTenantMailContext("jw-1");
    expect(ctx.from).toBe('"Joyería Tuport" <no-reply@tptech.local>');
    expect(ctx.replyTo).toBe("ventas@joyeriatuport.com");
    expect(ctx.senderName).toBe("Joyería Tuport");
    expect(ctx.fromEmail).toBe("no-reply@tptech.local");
    expect(ctx.emailEnabled).toBe(true);
  });

  it("sin emailSenderName: from cae al MAIL_FROM plano (sin display name)", async () => {
    process.env.MAIL_FROM = "no-reply@tptech.local";
    mockPrisma.jewelry.findUnique.mockResolvedValueOnce({
      emailEnabled:    true,
      emailSenderName: "",
      emailReplyTo:    "ventas@joy.com",
      email:           "info@joy.com",
    });

    const ctx = await resolveTenantMailContext("jw-1");
    expect(ctx.from).toBe("no-reply@tptech.local");
    expect(ctx.senderName).toBeUndefined();
  });

  it("sin emailReplyTo pero CON email legacy: replyTo cae al legacy (back-compat)", async () => {
    process.env.MAIL_FROM = "no-reply@tptech.local";
    mockPrisma.jewelry.findUnique.mockResolvedValueOnce({
      emailEnabled:    true,
      emailSenderName: "Joyería X",
      emailReplyTo:    "",
      email:           "info@joyeriax.com",
    });

    const ctx = await resolveTenantMailContext("jw-1");
    expect(ctx.replyTo).toBe("info@joyeriax.com");
  });

  it("sin emailReplyTo NI email legacy: replyTo undefined (no agrega header)", async () => {
    process.env.MAIL_FROM = "no-reply@tptech.local";
    mockPrisma.jewelry.findUnique.mockResolvedValueOnce({
      emailEnabled:    true,
      emailSenderName: "Joyería X",
      emailReplyTo:    "",
      email:           "",
    });

    const ctx = await resolveTenantMailContext("jw-1");
    expect(ctx.replyTo).toBeUndefined();
  });

  it("sin MAIL_FROM env: from queda undefined (mail.service usa su default interno)", async () => {
    // MAIL_FROM no seteado → from undefined → mail.service.sendMail
    // cae a su fallback "no-reply@tptech.local" interno. No rompe.
    mockPrisma.jewelry.findUnique.mockResolvedValueOnce({
      emailEnabled:    true,
      emailSenderName: "Joyería X",
      emailReplyTo:    "ventas@joy.com",
      email:           "",
    });

    const ctx = await resolveTenantMailContext("jw-1");
    expect(ctx.from).toBeUndefined();
    expect(ctx.senderName).toBe("Joyería X"); // se preserva igual
  });

  it("emailEnabled=false → flag propagado al caller (no bloquea en esta capa)", async () => {
    process.env.MAIL_FROM = "no-reply@tptech.local";
    mockPrisma.jewelry.findUnique.mockResolvedValueOnce({
      emailEnabled:    false,
      emailSenderName: "Joyería X",
      emailReplyTo:    "ventas@joy.com",
      email:           "",
    });

    const ctx = await resolveTenantMailContext("jw-1");
    expect(ctx.emailEnabled).toBe(false);
    // From/Reply-To siguen poblados — el caller decide si los usa o aborta.
    expect(ctx.from).toBe('"Joyería X" <no-reply@tptech.local>');
    expect(ctx.replyTo).toBe("ventas@joy.com");
  });

  it("tenant inexistente (findUnique → null): contexto vacio pero emailEnabled=true default", async () => {
    process.env.MAIL_FROM = "no-reply@tptech.local";
    mockPrisma.jewelry.findUnique.mockResolvedValueOnce(null);

    const ctx = await resolveTenantMailContext("jw-fake");
    expect(ctx.senderName).toBeUndefined();
    expect(ctx.replyTo).toBeUndefined();
    expect(ctx.emailEnabled).toBe(true); // default safe (no bloquea por null)
    // From cae al MAIL_FROM env plano (sin display name).
    expect(ctx.from).toBe("no-reply@tptech.local");
  });

  it("query usa select MINIMO (solo 4 campos email-related, multi-tenant + perf movil)", async () => {
    process.env.MAIL_FROM = "no-reply@tptech.local";
    mockPrisma.jewelry.findUnique.mockResolvedValueOnce({
      emailEnabled:    true,
      emailSenderName: "X",
      emailReplyTo:    "",
      email:           "",
    });
    await resolveTenantMailContext("jw-1");

    expect(mockPrisma.jewelry.findUnique).toHaveBeenCalledTimes(1);
    const args = mockPrisma.jewelry.findUnique.mock.calls[0]![0]!;
    expect(args.where).toEqual({ id: "jw-1" });
    expect(args.select).toEqual({
      emailEnabled:    true,
      emailSenderName: true,
      emailReplyTo:    true,
      email:           true,
    });
  });
});
