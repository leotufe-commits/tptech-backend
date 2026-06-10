# CONTRATO FUNCIONAL OFICIAL DE TPTECH — v1.0

> **Documento arquitectónico de referencia.** Define las **reglas de negocio** del
> cálculo comercial de TPTech — qué *debe* ser verdad en el dominio, no cómo está
> implementado. Es la autoridad funcional contra la cual se valida todo desarrollo
> nuevo (Factura de Ventas y todo comprobante hermano: presupuestos, órdenes, notas
> de crédito, remitos, notas de débito).
>
> **Relación con `POLICY.md`:** `POLICY.md` documenta el contrato técnico del motor
> (capas, snapshots, file:line, reglas de rounding implementadas). Este documento
> describe el **modelo de dominio funcional** que ese motor encarna. Ante una duda
> de *negocio*, manda este contrato; ante una duda de *implementación*, manda
> `POLICY.md`. No deben contradecirse.
>
> Estado: **v1.0 — aprobado.** Construido a partir de las auditorías de pipeline
> comercial, SSOT, Card, Footer, `Sale.total`, familias A/B/C, línea vs documento,
> PER_LINE vs PER_DOCUMENT, contrato POST-TAX e invariantes funcionales.

---

## Capítulo 1 — Modelo de dominio

TPTech organiza el cálculo comercial en **tres anillos concéntricos**:

- **Línea** — un artículo dentro de un comprobante. Es **autosuficiente**: todo lo
  que define su valor comercial puede calcularse mirando solo esa línea. La línea
  es la **autoridad** de su propio valor.
- **Documento** — el comprobante completo. **Agrega** líneas, **transforma** el
  conjunto y lo **cierra** en un importe. El documento **orquesta y reconcilia;
  nunca recalcula** la línea.
- **Compartido** — la franja frontera entre ambos: los **gramos comerciales** y el
  **redondeo comercial**. Aquí la línea calcula y el documento solo consolida
  (`Σ round(línea)`).

Regla raíz: **la línea calcula su verdad; el documento la suma, la transforma y la
cierra; lo compartido es la frontera donde el documento consolida sin recalcular.**

---

## Capítulo 2 — Dominio Línea

La línea es responsable de construir el valor comercial de un artículo y cerrarlo
con su redondeo. Pipeline-contrato de la línea:

```
Artículo
  → Metal            (valor del metal con margen comercial)
  → Monetario        (hechura + todo lo no-metal: productos, servicios, ajustes)
  → Impuestos        (gravamen sobre la composición de la línea)
  → Redondeo comercial   (política comercial sobre el resultado YA gravado)
  → Total línea c/imp.
```

Responsabilidades:

- **Metal** y **Monetario/hechura** son **dominios disjuntos**: nunca se mezclan;
  solo se suman al final.
- Los **impuestos** cierran la cadena gravada de la línea.
- El **redondeo comercial** es el **último eslabón comercial** y opera **POST-TAX**
  (sobre el valor con impuesto), de forma **autónoma** (inmune a las demás líneas).
- El **total de línea** es la consecuencia:
  **`metal comercial + monetario = total línea c/imp.`** (invariante de cierre).

Lo que la línea **nunca** hace: aplicar canal, cupón, bonificación global, envío,
forma de pago, redondeo financiero ni ajuste manual. Esas no son magnitudes de
línea.

---

## Capítulo 3 — Puente Línea → Documento: `Σ round(línea)`

La frontera funcional entre los dos dominios es la **consolidación**:

> El redondeo comercial del comprobante es la **suma de los valores comerciales
> finales de cada línea** (`Σ round(línea)`), **no** el redondeo del agregado
> (`round(Σ)`).

Responsabilidades de la frontera:

- La línea entrega su total comercial ya redondado y gravado.
- El documento **suma** esos totales — no vuelve a redondear, no re-grava, no
  recalcula.
- Consecuencia garantizada: **el footer es exactamente la suma visual de los
  artículos** del card. No hay residuos `round(Σ)` vs `Σ round`.

Esta frontera es el único punto donde el dominio línea se convierte en dominio
documento.

---

## Capítulo 4 — Dominio Documento

El documento toma el subtotal comercial (Σ líneas) y le aplica capas de
transformación y cierre:

```
Subtotal comercial      ── agregado de líneas (punto de partida documental)
  → Canal               ── transformación por canal de venta
  → Bonificación global ── descuento/recargo sobre el comprobante
  → Cupón               ── transformación promocional documental
  → (Base imponible documental + impuestos escalados)
  → Envío               ── monto agregado
  → Forma de pago       ── transformación por medio de pago
  → Redondeo financiero ── capa posterior, política del tenant
  → Ajuste manual       ── capa posterior, decisión humana (última)
  → Sale.total
```

Responsabilidad de cada capa:

- **Canal / Cupón / Bonificación global / Forma de pago:** transformaciones
  documentales del valor agregado. No pertenecen a ninguna línea.
- **Envío:** monto documental posterior a lo comercial.
- **Redondeo financiero:** política institucional del tenant; redondea el total del
  comprobante. Es **posterior** al comercial y opera sobre el total ya consolidado.
- **Ajuste manual:** intervención humana sobre el total del motor. Es **siempre la
  última capa**; no recalcula impuestos ni costos.

> Nota de orden: el dominio documental compone estas capas de forma conmutativa en
> su mayoría; lo que el contrato fija es que **comercial precede a financiero, y
> financiero precede a manual** — ese orden es inviolable.

---

## Capítulo 5 — Card (Resumen Comercial del Artículo)

- **Qué representa:** la verdad comercial **autónoma de una línea** — gramos, valor
  metal, hechura/monetario, redondeo comercial y total de esa línea, tal como
  serían si el artículo estuviera solo.
- **Qué consume:** la representación per-línea (resumen comercial de la línea),
  post-tax.
- **Qué nunca debe hacer:**
  - recalcular negocio (cero matemática comercial);
  - depender de otras líneas — el mismo artículo muestra el mismo resumen sin
    importar qué más haya en el comprobante;
  - leer valores documentales prorrateados (el reparto del redondeo del documento
    no pertenece al card).

Invariante del card: **autonomía por artículo**.

---

## Capítulo 6 — Footer (Total del Comprobante)

El footer cumple tres roles:

- **Representa a las líneas** (las **agrega**): suma de gramos y valores
  comerciales. Los gramos del footer son **los mismos del card** (frontera
  compartida).
- **Representa al documento** (lo **transforma/reconcilia**): canal, cupón,
  bonificación global, impuestos, envío, pago, redondeo financiero.
- **Representa el cobro final**: muestra `Sale.total` (el importe que paga el
  cliente).

Qué **nunca recalcula:** ningún valor de negocio. Solo **suma** valores ya
emitidos, **selecciona** entre fuentes y **resta** para mostrar saldos
(reconciliación de display, p. ej. `saldo monetario = total − Σ metal`). Si un
número "se ve raro", el dominio dice que el problema está en la fuente, nunca en el
footer.

---

## Capítulo 7 — Sale.total

- **Rol:** el importe final que el cliente paga; el resultado de todo el pipeline.
- **Autoridad:** es la **única fuente de verdad del cobro**. Card, footer, PDF, mail
  y cuenta corriente lo leen; ninguno lo redefine. Toda divergencia entre una vista
  y `Sale.total` es un defecto de la vista.
- **Relación con el documento:** es la salida de la cadena documental — el total
  del motor (con redondeo comercial y financiero) más el ajuste manual, con clamp
  **≥ 0**. Una vez confirmado, es **inmutable** (snapshot histórico).

---

## Capítulo 8 — Redondeos

Tres mecanismos, dominios y momentos distintos:

| Mecanismo | Dominio | Momento | Responsabilidad |
|---|---|---|---|
| **Redondeo comercial** | precio comercial / artículo | **post-tax**, dentro de la cadena comercial | cierra el valor comercial de la línea; se consolida `Σ round(línea)` |
| **Redondeo financiero** | total del comprobante / tenant | **posterior** al comercial | redondea el total del documento según política institucional |
| **Ajuste manual** | total del comprobante / humano | **último**, post-motor | intervención del operador sobre el total; no recalcula impuestos ni costos |

Orden inmutable: **comercial → financiero → ajuste manual.** Nunca se pisan; operan
en momentos distintos y sobre objetivos distintos. En modo **DESGLOSADO**, los tres
respetan el contrato canónico: **metal padre físico (gramos) + hechura/saldo
monetario**, dominios disjuntos.

---

## Capítulo 9 — Invariantes oficiales

1. **La línea es autónoma** — su resultado comercial no depende de las demás líneas.
2. **El documento consolida, no recalcula** la línea.
3. **`Sale.total` es la única autoridad del cobro**; todo lo demás es vista.
4. **El redondeo comercial es POST-TAX** — nunca antes de impuestos, nunca sobre
   valores parciales.
5. **La consolidación comercial es `Σ round(línea)`**, no `round(Σ)`.
6. **El redondeo financiero es posterior** al comercial.
7. **El ajuste manual es la última capa.**
8. **Metal y monetario/hechura son dominios disjuntos** — solo se suman al cierre.
9. **`metal comercial + monetario = total línea c/imp.`** (cierre de línea).
10. **Footer = suma visual de las líneas** (frontera `Σ round`).
11. **Gramos comerciales del card = gramos del footer** (frontera compartida).
12. **Preview = Confirm** — misma autoridad, mismo resultado.
13. **Los componentes negativos son válidos** — no se clampa a cero lo que el motor
    emite negativo.
14. **El frontend renderiza; el backend calcula** — ninguna vista infiere,
    reconstruye ni recalcula un valor del motor.
15. **El clamp final mantiene `Sale.total ≥ 0`**, recortando el bucket monetario,
    nunca los gramos del operador.

---

## Capítulo 10 — Compatibilidad histórica

- **Canónico (contrato oficial):** redondeo comercial **PER_DOCUMENT, POST-TAX,
  `Σ round(línea)`**; metal padre en **gramos físicos** en modo desglosado;
  identidad de metal por **id**.
- **Legacy (solo compatibilidad histórica, no es contrato):**
  - redondeo comercial **PER_LINE / PER_LINE_LEGACY** (pre-tax);
  - redondeo de subtotales monetarios de metal sin pasar por gramos (MONETARY
    directo);
  - redondeo comercial físico PER_UNIT;
  - match de metal por nombre.
- **Regla de dominio:** ningún desarrollo nuevo debe **depender de**, **extender** ni
  **documentar como contrato** lo legacy. Los helpers de display priorizan siempre
  el campo canónico y caen al legacy solo como fallback de lectura de datos
  antiguos.

(Este documento no propone migraciones — solo declara qué es canónico y qué es
histórico.)

---

## Capítulo 11 — Pipeline oficial TPTech

```
Artículo
  ↓  el artículo aporta su composición (metal + no-metal)
Metal
  ↓  valor del metal con margen comercial
Monetario (hechura)
  ↓  todo lo no-metal: hechura, productos, servicios, ajustes
Impuestos
  ↓  gravamen sobre la composición → cierra la cadena gravada de la LÍNEA
Redondeo comercial
  ↓  política comercial POST-TAX, autónoma por línea
Total línea c/imp.
  ↓  ── FRONTERA LÍNEA→DOCUMENTO ──
Σ round(línea)
  ↓  el documento SUMA los totales de línea (no re-redondea)
Subtotal comercial
  ↓  punto de partida documental
Canal
  ↓  transformación por canal de venta
Bonificación global
  ↓  descuento/recargo sobre el comprobante
Cupón
  ↓  transformación promocional documental
Envío
  ↓  monto documental
Forma de pago
  ↓  transformación por medio de pago
Redondeo financiero
  ↓  capa posterior, política del tenant, sobre el total consolidado
Ajuste manual
  ↓  capa posterior, decisión humana, última
Sale.total
     importe final a cobrar (autoridad única, inmutable al confirmar)
```

**Transiciones clave:**

- *Impuestos → Redondeo comercial:* el redondeo comercial nunca precede al
  impuesto; actúa sobre el valor ya gravado.
- *Total línea → Σ round(línea):* única frontera donde la línea se vuelve
  documento; el documento suma, no recalcula.
- *Comercial → Financiero → Manual:* tres capas posteriores en orden inmutable,
  cada una sobre el resultado de la anterior.
- *→ Sale.total:* cierre con clamp ≥ 0; a partir de aquí, todo consumidor lee,
  nadie redefine.

---

## Capítulo 12 — Conclusión

**El lenguaje oficial del negocio de TPTech:**

> Un comprobante se construye **línea por línea**: cada artículo forma su valor
> (metal + monetario), lo grava, lo cierra con un **redondeo comercial post-tax** y
> produce un **total de línea autónomo**. El documento **suma** esos totales
> (`Σ round(línea)`), les aplica las **transformaciones documentales** (canal,
> cupón, bonificación global, envío, forma de pago) y las **capas de cierre**
> (redondeo financiero y, por último, ajuste manual), dando el **`Sale.total`** — el
> único importe que el cliente paga y la única autoridad del sistema.

**Reglas que todo desarrollo futuro debe respetar:**

1. La línea es autónoma; el documento consolida; nadie recalcula la línea.
2. El redondeo comercial es POST-TAX y se consolida como `Σ round(línea)`.
3. El orden comercial → financiero → manual es inviolable.
4. `Sale.total` es la autoridad; el frontend solo renderiza.
5. Metal y monetario son dominios disjuntos; en desglosado, metal padre = gramos
   físicos.
6. Card = verdad por artículo; Footer = suma + transformaciones + cobro; ambos leen
   la misma frontera compartida.
7. Lo PER_DOCUMENT/POST-TAX es canónico; lo PER_LINE/pre-tax es solo compatibilidad
   histórica y no se extiende.

Este es el contrato funcional oficial de TPTech. Toda pantalla, comprobante o flujo
nuevo se valida contra él.
