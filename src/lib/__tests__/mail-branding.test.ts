// tptech-backend/src/lib/__tests__/mail-branding.test.ts
// =============================================================================
//  Sprint 1 de Certificación — Correos (B-lite).
//  Unit test del composer ÚNICO del cuerpo HTML del mail.
// =============================================================================
import { describe, it, expect } from "vitest";
import { composeBrandedEmailHtml, escapeHtmlForMail } from "../mail-branding.js";

describe("composeBrandedEmailHtml (B-lite)", () => {
  it("sin branding → solo el mensaje del operador en <pre>, sin secciones extra", () => {
    const html = composeBrandedEmailHtml({ message: "Hola mundo" });
    expect(html).toContain("<pre");
    expect(html).toContain("Hola mundo");
    // las secciones de branding usan border-top; sin branding no aparece
    expect(html).not.toContain("border-top");
  });

  it("preserva y escapa el mensaje del operador (anti-XSS)", () => {
    const html = composeBrandedEmailHtml({ message: '<script>alert("x")</script> & <3' });
    expect(html).not.toContain("<script>");
    expect(html).toContain("&lt;script&gt;");
    expect(html).toContain("&amp;");
  });

  it("inyecta la firma cuando está configurada", () => {
    const html = composeBrandedEmailHtml({ message: "Hola", branding: { signature: "Equipo de Joyería X" } });
    expect(html).toContain("Equipo de Joyería X");
    expect(html).toContain("border-top"); // sección de firma presente
  });

  it("inyecta contacto, meta y pie (config = enviado)", () => {
    const html = composeBrandedEmailHtml({
      message: "Hola",
      branding: {
        contact: "c@x.com", phone: "+54 11 1234", whatsapp: "+54 9 11",
        addressLine: "Florida 123", businessHours: "Lun-Vie", website: "https://x.com",
        instagram: "@joyx", footer: "Mensaje legal.",
      },
    });
    for (const txt of ["c@x.com", "+54 11 1234", "+54 9 11", "Florida 123", "Lun-Vie", "https://x.com", "@joyx", "Mensaje legal."]) {
      expect(html).toContain(txt);
    }
  });

  it("ignora campos vacíos o solo-espacios (no agrega secciones vacías)", () => {
    const html = composeBrandedEmailHtml({ message: "Hola", branding: { signature: "   ", footer: "" } });
    expect(html).not.toContain("border-top");
  });

  it("escapa el branding del tenant (no permite HTML inyectado en la firma)", () => {
    const html = composeBrandedEmailHtml({ message: "Hola", branding: { signature: "<b>x</b>" } });
    expect(html).not.toContain("<b>x</b>");
    expect(html).toContain("&lt;b&gt;");
  });

  it("escapeHtmlForMail escapa las entidades básicas", () => {
    expect(escapeHtmlForMail(`<>&"'`)).toBe("&lt;&gt;&amp;&quot;&#039;");
  });
});
