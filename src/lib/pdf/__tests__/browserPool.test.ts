// src/lib/pdf/__tests__/browserPool.test.ts
// =============================================================================
// C4 — Tests del pool singleton de Chromium. NO lanza Chromium real:
// usa `__setBrowserFactoryForTests` para inyectar un Browser mock.
//
// Cobertura:
//   1) singleton — dos llamadas concurrentes reciben el mismo Browser
//      (no se lanzan dos).
//   2) reuse  — si el browser está conectado, lo devuelve sin
//      re-lanzar la factory.
//   3) reset  — si el browser quedó desconectado (`connected: false`),
//      re-lanza la factory en la siguiente llamada.
//   4) close  — `closeBrowser()` libera el cache y es idempotente.
// =============================================================================

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  getBrowser,
  closeBrowser,
  __setBrowserFactoryForTests,
} from "../browserPool.js";

interface MockBrowser {
  connected: boolean;
  on:        ReturnType<typeof vi.fn>;
  close:     ReturnType<typeof vi.fn>;
  // marker para identificar instancias en los asserts.
  _id:       number;
}

function makeMockBrowser(id: number): MockBrowser {
  return {
    connected: true,
    on:        vi.fn(),
    close:     vi.fn().mockResolvedValue(undefined),
    _id:       id,
  };
}

beforeEach(() => {
  // Limpiar estado entre tests — `__setBrowserFactoryForTests(null)`
  // restablece el factory default y borra el cache singleton.
  __setBrowserFactoryForTests(null);
});

afterEach(async () => {
  await closeBrowser();
  __setBrowserFactoryForTests(null);
});

describe("browserPool — singleton", () => {
  it("dos llamadas en paralelo comparten el mismo browser (no lanza dos)", async () => {
    let calls = 0;
    const factory = vi.fn(async () => {
      calls += 1;
      return makeMockBrowser(calls) as any;
    });
    __setBrowserFactoryForTests(factory);

    const [a, b] = await Promise.all([getBrowser(), getBrowser()]);
    expect(factory).toHaveBeenCalledOnce();
    expect((a as unknown as MockBrowser)._id).toBe((b as unknown as MockBrowser)._id);
  });

  it("reutiliza el browser cacheado si sigue conectado", async () => {
    const factory = vi.fn(async () => makeMockBrowser(1) as any);
    __setBrowserFactoryForTests(factory);

    const a = await getBrowser();
    const b = await getBrowser();
    expect(factory).toHaveBeenCalledOnce();
    expect(a).toBe(b);
  });

  it("relanza la factory si el browser quedó desconectado", async () => {
    let counter = 0;
    const factory = vi.fn(async () => {
      counter += 1;
      return makeMockBrowser(counter) as any;
    });
    __setBrowserFactoryForTests(factory);

    const first = await getBrowser() as unknown as MockBrowser;
    expect(first._id).toBe(1);

    // Simulamos un crash → marcamos disconnected.
    first.connected = false;

    const second = await getBrowser() as unknown as MockBrowser;
    expect(second._id).toBe(2);
    expect(factory).toHaveBeenCalledTimes(2);
  });

  it("registra un handler `disconnected` sobre el browser para invalidar cache", async () => {
    const browser = makeMockBrowser(1);
    __setBrowserFactoryForTests(async () => browser as any);

    await getBrowser();
    expect(browser.on).toHaveBeenCalledWith("disconnected", expect.any(Function));
  });

  it("closeBrowser cierra el browser cacheado y limpia el cache", async () => {
    const browser = makeMockBrowser(1);
    __setBrowserFactoryForTests(async () => browser as any);

    await getBrowser();
    await closeBrowser();
    expect(browser.close).toHaveBeenCalledOnce();

    // Siguiente getBrowser → factory se invoca de nuevo (cache invalidado).
    const factory = vi.fn(async () => makeMockBrowser(2) as any);
    __setBrowserFactoryForTests(factory);
    await getBrowser();
    expect(factory).toHaveBeenCalledOnce();
  });

  it("closeBrowser es idempotente — llamarlo dos veces no rompe", async () => {
    await closeBrowser();
    await expect(closeBrowser()).resolves.toBeUndefined();
  });

  it("no propaga errores de close (best-effort cleanup)", async () => {
    const browser = makeMockBrowser(1);
    browser.close = vi.fn().mockRejectedValue(new Error("crash on close"));
    __setBrowserFactoryForTests(async () => browser as any);

    await getBrowser();
    // closeBrowser NO debe rechazar aunque el browser tire al cerrar.
    await expect(closeBrowser()).resolves.toBeUndefined();
  });
});
