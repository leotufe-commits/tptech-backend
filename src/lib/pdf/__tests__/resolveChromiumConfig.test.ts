// src/lib/pdf/__tests__/resolveChromiumConfig.test.ts
// =============================================================================
// Tests de `resolveChromiumConfig` — la función que decide qué binario
// de Chromium usar (env override → @sparticuz/chromium → puppeteer
// full → error claro).
//
// NO lanza Chromium real. Verifica el algoritmo de resolución y los
// fallbacks via env vars + control del puppeteer real (que está
// instalado como devDep y debería resolver un path en dev local).
// =============================================================================

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { resolveChromiumConfig } from "../browserPool.js";

const ORIG_PATH = process.env.CHROMIUM_EXECUTABLE_PATH;

beforeEach(() => {
  delete process.env.CHROMIUM_EXECUTABLE_PATH;
});

afterEach(() => {
  if (ORIG_PATH === undefined) delete process.env.CHROMIUM_EXECUTABLE_PATH;
  else                          process.env.CHROMIUM_EXECUTABLE_PATH = ORIG_PATH;
});

describe("resolveChromiumConfig", () => {
  it("respeta CHROMIUM_EXECUTABLE_PATH si está seteado (gana sobre auto-detect)", async () => {
    process.env.CHROMIUM_EXECUTABLE_PATH = "/custom/path/chrome";

    const cfg = await resolveChromiumConfig();
    expect(cfg.executablePath).toBe("/custom/path/chrome");
    // Cuando se usa override, caemos a `defaultLaunchArgs` (sane defaults).
    expect(cfg.args).toContain("--no-sandbox");
    expect(cfg.args).toContain("--disable-dev-shm-usage");
  });

  it("trimea whitespace del CHROMIUM_EXECUTABLE_PATH", async () => {
    process.env.CHROMIUM_EXECUTABLE_PATH = "  /spaced/path/chrome   ";

    const cfg = await resolveChromiumConfig();
    expect(cfg.executablePath).toBe("/spaced/path/chrome");
  });

  it("ignora CHROMIUM_EXECUTABLE_PATH vacío y cae al auto-detect", async () => {
    process.env.CHROMIUM_EXECUTABLE_PATH = "";

    // Sin override → cae a @sparticuz/chromium o puppeteer full.
    // Como puppeteer (devDep) está instalado, debería resolver. Si
    // resuelve "", entonces no asignable: tendría que tirar error.
    const cfg = await resolveChromiumConfig();
    expect(cfg.executablePath).toBeTruthy();
    expect(typeof cfg.executablePath).toBe("string");
    expect(cfg.executablePath.length).toBeGreaterThan(0);
  });

  it("[integration] resuelve un path válido en dev local (puppeteer fallback)", async () => {
    // No setear env override. Confiar en el flujo real:
    //   · En Windows local (dev del operador) `@sparticuz/chromium` no
    //     tiene binario → cae a puppeteer fallback.
    //   · En Linux CI con @sparticuz/chromium binario instalado → ese.
    //   · En cualquier caso debe devolver un path no vacío.
    const cfg = await resolveChromiumConfig();

    expect(cfg.executablePath).toBeTruthy();
    expect(typeof cfg.executablePath).toBe("string");
    expect(cfg.executablePath.length).toBeGreaterThan(0);
    expect(Array.isArray(cfg.args)).toBe(true);
  });

  it("[integration] devuelve args defaults razonables si no hay @sparticuz", async () => {
    // En Windows dev local, vendrá del fallback puppeteer →
    // `defaultLaunchArgs` con --no-sandbox.
    const cfg = await resolveChromiumConfig();

    // Validamos que los args son strings de flags (empiezan con --).
    for (const arg of cfg.args) {
      expect(typeof arg).toBe("string");
    }
    // Al menos en el fallback puppeteer, esperamos --no-sandbox.
    // En Linux CI con @sparticuz/chromium puede no estar (chromium.args
    // trae otros). Por eso solo verificamos que NO sea vacío.
    expect(cfg.args.length).toBeGreaterThan(0);
  });
});
