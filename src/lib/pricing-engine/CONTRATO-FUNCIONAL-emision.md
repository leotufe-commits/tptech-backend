# CONTRATO FUNCIONAL — EMISIÓN DE LA FAMILIA C (Etapa 1)

> **Documento companion de [`CONTRATO-FUNCIONAL.md`](./CONTRATO-FUNCIONAL.md) y
> [`CONTRATO-FUNCIONAL-consumo.md`](./CONTRATO-FUNCIONAL-consumo.md).**
>
> El contrato define el *modelo de dominio*; el de consumo define *qué leer*;
> este define **cuándo la Familia C existe y cuándo puede legítimamente no
> existir**. Documento **arquitectónico** — describe reglas de dominio, no
> implementación ni file:line.
>
> **Naturaleza:** cierre de la auditoría de emisión de la Familia C (Etapa 1 del
> Roadmap Maestro de Evolución). No crea obligaciones nuevas: describe el
> contrato que el sistema **ya** encarna.
>
> **No modifica** el Contrato Funcional ni el Contrato de Consumo — los
> complementa.

---

## 0. Por qué este documento existe

Un error natural al leer el Contrato de Consumo es asumir que **"la Familia C
siempre existe"**. No es así. La Familia C es la **fuente canónica de lectura
per-línea**, pero su **emisión está condicionada al escenario**. Confundir
"fuente canónica" con "presencia universal" llevaría a construir garantías
mecánicas (guards/tests) que fallarían sobre datos perfectamente válidos
(snapshots históricos, simulador, comprobantes hermanos, líneas sin
composición). Este documento fija la frontera.

---

## 1. Qué significa que la Familia C "se emite"

Que el backend, **por cada línea**, adjunta a la respuesta el objeto-contrato
de la Familia C:

- **C-FASE 0 → `lineCommercialSummary`** — el resumen comercial autosuficiente
  de la línea (metal + monetario + total) en un único shape.
- **C-FASE 1 → `lineCommercialDisplaySummary`** — el resumen **autónomo
  line-local** (inmune a otras líneas), variante **canónica** para display.

La emisión ocurre **post-consolidación del redondeo comercial**, como capa de
**display** — **no toca `Sale.total`** ni los snapshots de cálculo. Emitir C es
adjuntar una representación; nunca recalcular.

---

## 2. Quién produce la Familia C

- La produce el **motor de Factura de Ventas** en sus dos caminos frescos:
  **`previewSale`** y **`confirmSale`**.
- El cálculo lo realizan **builders dedicados** (FASE 0 y FASE 1) a partir de
  los mismos primitivos per-línea que ya alimentan la consolidación comercial.
- **Ningún otro módulo** produce Familia C: ni el Simulador, ni los
  comprobantes hermanos, ni capas externas.

---

## 3. Cuándo se emite C-FASE 0

> **Siempre, en toda salida fresca de Factura.**

C-FASE 0 (`lineCommercialSummary`) se emite **incondicionalmente para cada
línea** de `previewSale` y `confirmSale`. Incluso cuando la línea es UNIFICADA
o no tiene redondeo comercial, el objeto se construye con un **piso UNIFIED**
(sin desglose de metal; el monetario es el total de la línea). En salida fresca
de Factura, **C-FASE 0 nunca falta**.

---

## 4. Cuándo se emite C-FASE 1

> **Condicionada a que la línea tenga composición comercial.**

C-FASE 1 (`lineCommercialDisplaySummary`) se emite **solo cuando existe
composición comercial que alimente la agregación** (líneas con metal/composición
desglosable). Una línea sin composición comercial **legítimamente no recibe
FASE 1** — y eso es correcto, porque FASE 1 es el resumen autónomo del desglose
metal/hechura, que no aplica si no hay desglose.

C-FASE 1 es la **variante canónica** para el display per-línea; su ausencia en
una línea sin composición no es una falla: el consumidor cae a C-FASE 0.

---

## 5. Preview vs Confirm

> **Espejo exacto respecto de la Familia C.**

`previewSale` y `confirmSale` aplican **el mismo contrato de emisión**: misma
condición para FASE 0 (incondicional) y FASE 1 (con composición), y el mismo
tratamiento de los casos de listas mixtas. **No hay diferencias legítimas** en
la forma ni el contenido de C entre preview y confirm. (La única divergencia
*by design* del sistema —precio congelado en confirm vs costo fresco— no altera
la Familia C.) Lo que el operador ve en el preview es lo que queda persistido al
confirmar.

---

## 6. Relación entre A, B y C durante la emisión

- En **salida fresca de Factura**, las tres familias se emiten en el mismo paso:
  A (reparto documental), B (`lineOwn*`, autónoma) y **C-FASE 0** conviven por
  línea. **C-FASE 1** se suma cuando hay composición.
- Por lo tanto, en salida fresca **no existe A o B sin C-FASE 0**.
- **C-FASE 1 puede faltar aunque A y B existan** (línea sin composición) — y es
  **correcto** (FASE 1 solo aplica con desglose).
- En **snapshots históricos** puede haber A y/o B **sin ninguna C** — eso es
  **compatibilidad histórica legítima** (datos anteriores al contrato), **no
  deuda a corregir**.

Resumen: *A/B sin C* es **bug** si es salida fresca de Factura; es **legítimo**
si es un dato histórico o foráneo.

---

## 7. Escenarios donde la ausencia de C es correcta

- **Snapshots históricos**: ventas confirmadas antes de la incorporación del
  contrato C. Inmutables; no se les exige C.
- **Simulador**: usa su propio camino de display; no emite C.
- **Comprobantes hermanos** (presupuestos, órdenes, notas de crédito, compras):
  hasta adoptar el patrón madre de Factura, no emiten C.
- **Drafts sin preview**: una venta en edición que aún no pasó por el backend no
  tiene C.
- **Líneas sin composición comercial**: dentro de una Factura fresca, esas
  líneas no reciben **C-FASE 1** (sí C-FASE 0).
- **Otros módulos** que no son el motor de Factura: no emiten C.

En todos estos casos, **la ausencia de C es válida** y el consumidor debe
tolerarla cayendo a B → A → legacy.

---

## 8. Tabla de obligatoriedad

| Escenario | C-FASE 0 | C-FASE 1 | Ausencia permitida |
|---|:--:|:--:|:--:|
| Factura — preview, línea con composición | ✅ obligatoria | ✅ esperada | — |
| Factura — preview, línea sin composición | ✅ obligatoria | ⚪ ausente OK | solo FASE 1 |
| Factura — confirm | ✅ obligatoria | ✅ esperada (si composición) | solo FASE 1 sin composición |
| Simulador | — | — | ✅ |
| Comprobantes hermanos (POC, sin backend preview) | — | — | ✅ |
| Snapshots históricos (previos al contrato C) | — | — | ✅ |
| Draft sin preview | — | — | ✅ |
| Otros módulos | — | — | ✅ |

---

## 9. Contrato oficial de emisión

> **TPTech GARANTIZA la Familia C así:**
>
> - **C-FASE 0 (`lineCommercialSummary`)** en **cada línea** de toda salida
>   **fresca** del motor de Factura (`previewSale` y `confirmSale`).
> - **C-FASE 1 (`lineCommercialDisplaySummary`)** en **cada línea fresca que
>   tenga composición comercial**.
>
> **TPTech NO GARANTIZA la Familia C en:**
>
> - el Simulador;
> - los comprobantes hermanos (hasta que adopten el patrón madre);
> - otros módulos ajenos al motor de Factura;
> - snapshots históricos previos al contrato C;
> - drafts que aún no pasaron por el preview;
> - líneas sin composición comercial (solo respecto de **C-FASE 1**).
>
> En esos contextos la ausencia de C es **correcta por dominio**, y todo lector
> debe degradar a B → A → legacy.

---

## 10. Conclusión arquitectónica

> **TPTech NO garantiza la existencia universal de la Familia C.**
>
> **TPTech garantiza la existencia de la Familia C exactamente en los
> escenarios definidos por el dominio** — la salida fresca del motor de Factura,
> con FASE 0 siempre y FASE 1 cuando hay composición.

Consecuencia para cualquier garantía mecánica futura: debe verificar la
**emisión** (lado productor: ¿el motor de Factura adjuntó C donde corresponde?),
**nunca** la **existencia universal** (lado consumidor). Un guard de presencia
absoluta contradiría el dominio y fallaría sobre datos válidos. El consumo ya
está protegido por el guard de la Familia A (no leer A documental per-línea); la
emisión se garantiza, si se decide, con una verificación **condicionada al
escenario**, acotada a la salida fresca de Factura.

---

*Cierre del aspecto "emisión de la Familia C" de la Etapa 1 del Roadmap Maestro
de Evolución de TPTech. Este documento persiste conocimiento descubierto; no
introduce obligaciones que el dominio no tenga.*
