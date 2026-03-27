// src/lib/initTenantDefaults.ts
//
// Shared logic for initializing system roles, permissions and catalog defaults
// for a new tenant. Used by: auth.controller.ts (register) and prisma/seed.ts
//
import { PermModule, PermAction } from "@prisma/client";
import type { Prisma } from "@prisma/client";

// Precio de referencia del Oro en moneda base (ARS / gramo)
const ORO_REF_VALUE = 250_000;

const ALL_MODULES = Object.values(PermModule) as PermModule[];
const ALL_ACTIONS = Object.values(PermAction) as PermAction[];

function pick(permIdByKey: Map<string, string>, modules: PermModule[], actions: PermAction[]): string[] {
  const ids: string[] = [];
  for (const m of modules)
    for (const a of actions) {
      const id = permIdByKey.get(`${m}:${a}`);
      if (id) ids.push(id);
    }
  return ids;
}

/* ============================================================
   PRIVATE HELPERS — categorías y atributos
============================================================ */

/**
 * Ensures an ArticleCategory exists for the tenant.
 * Idempotent: returns existing id if already present.
 */
async function ensureCategory(
  db: any,
  jewelryId: string,
  name: string,
  parentId?: string,
  sortOrder = 0
): Promise<string> {
  const existing = await db.articleCategory.findFirst({
    where: { jewelryId, name, deletedAt: null },
    select: { id: true },
  });
  if (existing) return existing.id;

  const cat = await db.articleCategory.create({
    data: { jewelryId, name, parentId: parentId ?? null, sortOrder, isActive: true },
    select: { id: true },
  });
  return cat.id;
}

/**
 * Ensures an ArticleAttributeDef exists for the tenant.
 * If it doesn't exist, creates it with all its options.
 * Idempotent by code.
 */
async function ensureAttributeDef(
  db: any,
  jewelryId: string,
  def: {
    code: string;
    name: string;
    inputType: string;
    options: (string | { label: string; codeExtension?: string })[];
  }
): Promise<string> {
  const existing = await db.articleAttributeDef.findFirst({
    where: { jewelryId, code: def.code, deletedAt: null },
    select: { id: true },
  });
  if (existing) return existing.id;

  const created = await db.articleAttributeDef.create({
    data: { jewelryId, name: def.name, code: def.code, inputType: def.inputType, isActive: true },
    select: { id: true },
  });

  for (let i = 0; i < def.options.length; i++) {
    const opt = def.options[i];
    const label = typeof opt === "string" ? opt : opt.label;
    const codeExtension = typeof opt === "string" ? "" : (opt.codeExtension ?? "");
    await db.articleAttributeDefOption.create({
      data: {
        definitionId: created.id,
        label,
        value: label,
        codeExtension,
        sortOrder: i,
        isActive: true,
      },
    });
  }

  return created.id;
}

/**
 * Assigns an attribute definition to a category.
 * Idempotent: skips if already assigned.
 */
async function ensureAttributeAssignment(
  db: any,
  jewelryId: string,
  categoryId: string,
  definitionId: string,
  sortOrder = 0,
  inheritToChild = true,
  isVariantAxis = true
): Promise<void> {
  const existing = await db.articleCategoryAttribute.findFirst({
    where: { jewelryId, categoryId, definitionId, deletedAt: null },
    select: { id: true },
  });
  if (existing) return;

  await db.articleCategoryAttribute.create({
    data: {
      jewelryId,
      categoryId,
      definitionId,
      inheritToChild,
      isVariantAxis,
      isActive: true,
      isFilterable: true,
      sortOrder,
    },
  });
}

/**
 * Creates the simplified jewelry category taxonomy for a tenant.
 * Returns a map of { parentName → parentId, childName → childId }.
 */
async function ensureJewelryCategories(
  db: any,
  jewelryId: string
): Promise<Record<string, string>> {
  const TAXONOMY: {
    name: string;
    sortOrder: number;
    children: { name: string; sortOrder: number }[];
  }[] = [
    {
      name: "Anillos", sortOrder: 0,
      children: [
        { name: "Anillo sin piedras",  sortOrder: 0 },
        { name: "Anillos con piedras", sortOrder: 1 },
        { name: "Anillos sellos",      sortOrder: 2 },
      ],
    },
    {
      name: "Cadenas", sortOrder: 1,
      children: [
        { name: "Cadenas huecas",      sortOrder: 0 },
        { name: "Cadenas maquinadas",  sortOrder: 1 },
      ],
    },
  ];

  const ids: Record<string, string> = {};

  for (const parent of TAXONOMY) {
    const parentId = await ensureCategory(db, jewelryId, parent.name, undefined, parent.sortOrder);
    ids[parent.name] = parentId;

    for (const child of parent.children) {
      const childId = await ensureCategory(db, jewelryId, child.name, parentId, child.sortOrder);
      ids[child.name] = childId;
    }
  }

  return ids;
}

/**
 * Creates attribute definitions and assigns them to specific categories.
 *
 * COLOR_ORO → Anillos (inheritToChild: true) + Cadenas (inheritToChild: true)
 * COLOR_GEMAS → "Anillos con piedras" subcategory (inheritToChild: false)
 */
async function ensureJewelryAttributes(
  db: any,
  jewelryId: string,
  categoryIds: Record<string, string>
): Promise<void> {
  const ATTR_COLOR_ORO = await ensureAttributeDef(db, jewelryId, {
    code: "COLOR_ORO",
    name: "Color de Oro",
    inputType: "SELECT",
    options: [
      { label: "Oro Amarillo 18Kts", codeExtension: "A" },
      { label: "Oro Blanco 18Kts",   codeExtension: "B" },
      { label: "Oro Rojo 18Kts",     codeExtension: "R" },
    ],
  });

  const ATTR_COLOR_GEMAS = await ensureAttributeDef(db, jewelryId, {
    code: "COLOR_GEMAS",
    name: "Color de Gemas",
    inputType: "SELECT",
    options: [
      { label: "Sin gema", codeExtension: "" },
      { label: "Blanca",   codeExtension: "B" },
      { label: "Roja",     codeExtension: "R" },
      { label: "Azul",     codeExtension: "A" },
      { label: "Verde",    codeExtension: "V" },
      { label: "Negra",    codeExtension: "N" },
    ],
  });

  // COLOR_ORO → Anillos y Cadenas (se hereda a subcategorías)
  for (const parentName of ["Anillos", "Cadenas"]) {
    if (categoryIds[parentName]) {
      await ensureAttributeAssignment(db, jewelryId, categoryIds[parentName], ATTR_COLOR_ORO, 0, true);
    }
  }

  // COLOR_GEMAS → solo "Anillos con piedras"
  if (categoryIds["Anillos con piedras"]) {
    await ensureAttributeAssignment(db, jewelryId, categoryIds["Anillos con piedras"], ATTR_COLOR_GEMAS, 0, false);
  }
}

/**
 * Creates the 3 base currencies for a new tenant.
 * ARS (base), USD, EUR — all idempotent by code.
 * Returns the ARS currency id (needed for metal quote snapshots).
 */
async function ensureCurrencies(db: any, jewelryId: string): Promise<string> {
  const now = new Date();

  // ── ARS (moneda base) ────────────────────────────────────────────────────
  // upsert en @@unique([jewelryId, code]) — cubre también registros soft-deleted
  // update restores deletedAt/isBase en caso de que el registro haya sido borrado
  const ars = await db.currency.upsert({
    where: { jewelryId_code: { jewelryId, code: "ARS" } },
    create: { jewelryId, code: "ARS", name: "Peso Argentino", symbol: "AR$", isBase: true,  isActive: true },
    update: { deletedAt: null, isBase: true, isActive: true },
    select: { id: true },
  });
  const arsId: string = ars.id;

  // ── USD ──────────────────────────────────────────────────────────────────
  const usd = await db.currency.upsert({
    where: { jewelryId_code: { jewelryId, code: "USD" } },
    create: { jewelryId, code: "USD", name: "Dólares", symbol: "US$", isBase: false, isActive: true },
    update: { deletedAt: null, isActive: true },
    select: { id: true, createdAt: true, updatedAt: true },
  });
  // Crear rate solo si la moneda acaba de ser creada (no tiene rates previos)
  const usdRateCount = await db.currencyRate.count({ where: { currencyId: usd.id } });
  if (usdRateCount === 0) {
    await db.currencyRate.create({ data: { currencyId: usd.id, rate: "1500", effectiveAt: now } });
  }

  // ── EUR ──────────────────────────────────────────────────────────────────
  const eur = await db.currency.upsert({
    where: { jewelryId_code: { jewelryId, code: "EUR" } },
    create: { jewelryId, code: "EUR", name: "Euro", symbol: "€", isBase: false, isActive: true },
    update: { deletedAt: null, isActive: true },
    select: { id: true },
  });
  const eurRateCount = await db.currencyRate.count({ where: { currencyId: eur.id } });
  if (eurRateCount === 0) {
    await db.currencyRate.create({ data: { currencyId: eur.id, rate: "1800", effectiveAt: now } });
  }

  return arsId;
}

/**
 * Creates the "Oro" metal with its 4 standard variants.
 * Also seeds MetalRefValueHistory, MetalVariantValueHistory and MetalQuote
 * (base-currency snapshot) for each variant — same data the UI expects.
 *
 * baseCurrencyId: id of the ARS Currency row (must exist beforehand).
 * Idempotent: skips metal if (jewelryId, name) exists; skips variants by sku.
 */
async function ensureMetalWithVariants(
  db: any,
  jewelryId: string,
  baseCurrencyId: string
): Promise<void> {
  const now = new Date();
  const refValue = String(ORO_REF_VALUE); // Prisma Decimal acepta string

  // ── Metal "Oro" ──────────────────────────────────────────────────────────
  // Buscar sin filtrar deletedAt: @@unique([jewelryId, name]) no incluye deletedAt.
  // deleteMetal() libera el nombre (freedName), así que un metal borrado no matcheará "Oro".
  const existingMetal = await db.metal.findFirst({
    where: { jewelryId, name: "Oro" },
    select: { id: true },
  });

  let metalId: string;
  if (existingMetal) {
    metalId = existingMetal.id;
  } else {
    const metal = await db.metal.create({
      data: {
        jewelryId,
        name: "Oro",
        symbol: "AU",
        referenceValue: refValue,
        sortOrder: 1,
        isActive: true,
      },
      select: { id: true },
    });
    metalId = metal.id;

    // Historial inicial del metal padre
    await db.metalRefValueHistory.create({
      data: { jewelryId, metalId, referenceValue: refValue, effectiveAt: now },
    });
  }

  // ── Variantes ────────────────────────────────────────────────────────────
  // finalSalePrice = referenceValue × purity × saleFactor (redondeado a 2 dec)
  const VARIANTS: { name: string; sku: string; purity: number; saleFactor: number }[] = [
    { name: "Oro 24 Kilates",        sku: "AU24K", purity: 1.0,    saleFactor: 1.0  },
    { name: "Oro 22 Kilates",        sku: "AU22K", purity: 0.9,    saleFactor: 1.0  },
    { name: "Oro 18 Kilates",        sku: "AU18K", purity: 0.825,  saleFactor: 1.0  },
    { name: "Chafalonia 18 Kilates", sku: "CH18K", purity: 0.7,    saleFactor: 0.95 },
  ];

  for (const v of VARIANTS) {
    // Buscar sin filtrar deletedAt: @@unique([metalId, sku]) no incluye deletedAt.
    // Si la variante fue soft-deleted y su sku fue liberado (freedSku), no matcheará → se crea.
    // Si existe activa → skip.
    const existingVariant = await db.metalVariant.findFirst({
      where: { metalId, sku: v.sku },
      select: { id: true },
    });
    if (existingVariant) continue;

    const finalSaleRaw = ORO_REF_VALUE * v.purity * v.saleFactor;
    const finalSale = String(Math.round(finalSaleRaw * 100) / 100);
    const purityStr = String(v.purity);
    const saleFactorStr = String(v.saleFactor);

    const variant = await db.metalVariant.create({
      data: {
        metalId,
        name: v.name,
        sku: v.sku,
        purity: purityStr,
        saleFactor: saleFactorStr,
        isActive: true,
        isFavorite: false,
      },
      select: { id: true },
    });

    // Historial de valor de variante
    await db.metalVariantValueHistory.create({
      data: {
        jewelryId,
        metalId,
        variantId: variant.id,
        referenceValue: refValue,
        purity: purityStr,
        saleFactor: saleFactorStr,
        finalSalePrice: finalSale,
        effectiveAt: now,
      },
    });

    // Cotización en moneda base (ARS)
    await db.metalQuote.create({
      data: {
        variantId: variant.id,
        currencyId: baseCurrencyId,
        price: finalSale,
        effectiveAt: now,
      },
    });
  }
}

/* ============================================================
   PUBLIC API
============================================================ */

/**
 * Ensures all Permission rows exist (global, shared across all tenants).
 * Idempotent — skips duplicates.
 * Returns a Map of "MODULE:ACTION" -> permissionId.
 */
export async function ensureGlobalPermissions(
  db: Prisma.TransactionClient
): Promise<Map<string, string>> {
  const permissionsData = ALL_MODULES.flatMap((module) =>
    ALL_ACTIONS.map((action) => ({ module, action }))
  );

  await db.permission.createMany({ data: permissionsData, skipDuplicates: true });

  const all = await db.permission.findMany();
  const permIdByKey = new Map<string, string>();
  for (const p of all) permIdByKey.set(`${p.module}:${p.action}`, p.id);
  return permIdByKey;
}

/**
 * Idempotent upsert of the 4 system roles for a tenant.
 *
 * - OWNER: permissions are always fully reset to all permissions.
 * - ADMIN / STAFF / READONLY: permissions are only set if the role has none yet
 *   (preserves any custom configuration the user may have made).
 *
 * Returns the ownerRoleId.
 */
export async function ensureSystemRoles(
  db: Prisma.TransactionClient,
  jewelryId: string,
  permIdByKey: Map<string, string>
): Promise<{ ownerRoleId: string }> {
  const OWNER_PERMS = Array.from(permIdByKey.values());
  const ADMIN_PERMS = pick(permIdByKey, ALL_MODULES, ALL_ACTIONS);
  const STAFF_PERMS = pick(permIdByKey, ALL_MODULES, [PermAction.VIEW, PermAction.CREATE, PermAction.EDIT]);
  const READONLY_PERMS = pick(permIdByKey, ALL_MODULES, [PermAction.VIEW]);

  const roleDefs = [
    { name: "OWNER",    displayName: "Propietario",   isSystem: true, permIds: OWNER_PERMS,    forcePerms: true  },
    { name: "ADMIN",    displayName: "Administrador", isSystem: true, permIds: ADMIN_PERMS,    forcePerms: false },
    { name: "STAFF",    displayName: "Vendedor",      isSystem: true, permIds: STAFF_PERMS,    forcePerms: false },
    { name: "READONLY", displayName: "Solo lectura",  isSystem: true, permIds: READONLY_PERMS, forcePerms: false },
  ] as const;

  let ownerRoleId = "";

  for (const r of roleDefs) {
    const role = await db.role.upsert({
      where: { jewelryId_name: { jewelryId, name: r.name } },
      create: { name: r.name, displayName: r.displayName, jewelryId, isSystem: r.isSystem },
      update: { isSystem: r.isSystem, deletedAt: null },
      select: { id: true },
    });

    if (r.name === "OWNER") ownerRoleId = role.id;

    if (r.forcePerms) {
      await db.rolePermission.deleteMany({ where: { roleId: role.id } });
      if (r.permIds.length) {
        await db.rolePermission.createMany({
          data: r.permIds.map((permissionId) => ({ roleId: role.id, permissionId })),
          skipDuplicates: true,
        });
      }
    } else {
      const existingCount = await db.rolePermission.count({ where: { roleId: role.id } });
      if (existingCount === 0 && r.permIds.length) {
        await db.rolePermission.createMany({
          data: r.permIds.map((permissionId) => ({ roleId: role.id, permissionId })),
          skipDuplicates: true,
        });
      }
    }
  }

  return { ownerRoleId };
}

/**
 * Creates all system defaults for a new tenant:
 *
 * Catálogos:
 *   DOCUMENT_TYPE (DNI, CUIT, CUIL)
 *   IVA_CONDITION (4 condiciones)
 *   PHONE_PREFIX  (10 países de referencia)
 *   COUNTRY       (10 países)
 *   PROVINCE      (24 provincias argentinas)
 *   CITY          (10 ciudades principales)
 *
 * Taxes:          IVA 21%, IVA 10.5%
 * PaymentMethods: Efectivo, Transferencia
 * ShippingCarriers: Retiro en sucursal, Envío estándar
 *
 * Currencies:
 *   ARS (base), USD (rate 1500), EUR (rate 1800)
 *
 * Metal:
 *   Oro (AU, referenceValue 250000 ARS/g) + 4 variantes (AU24K, AU22K, AU18K, CH18K)
 *   Cada variante genera MetalVariantValueHistory + MetalQuote en ARS.
 *
 * PriceLists:
 *   Lista Minorista — Valor Unificado (MARGIN_TOTAL 150%, isFavorite)
 *   Lista Mayorista — Valor Desglosado (METAL_HECHURA: metal 20% / hechura 50%)
 *   Lista Costo por Gramo (COST_PER_GRAM 120%)
 *
 * ArticleCategories: Anillos (+ 3 hijos) y Cadenas (+ 2 hijos)
 * ArticleAttributeDefs + assignments:
 *   Color de Oro → Anillos y Cadenas (inheritToChild: true)
 *   Color de Gemas → Anillos con piedras (inheritToChild: false)
 *
 * Idempotente: safe to call multiple times.
 */
export async function ensureSystemDefaults(
  db: Prisma.TransactionClient,
  jewelryId: string
): Promise<void> {
  const anyDb = db as any;

  // ── CatalogItems ────────────────────────────────────────────────────────
  type CatalogType = "IVA_CONDITION" | "DOCUMENT_TYPE" | "PHONE_PREFIX" | "COUNTRY" | "PROVINCE" | "CITY"
    | "PAYMENT_TERM" | "ARTICLE_BRAND" | "ARTICLE_MANUFACTURER" | "UNIT_OF_MEASURE" | "MULTIPLIER_BASE";

  const catalogDefaults: { type: CatalogType; label: string }[] = [
    // Tipos de documento
    { type: "DOCUMENT_TYPE", label: "DNI"  },
    { type: "DOCUMENT_TYPE", label: "CUIT" },
    { type: "DOCUMENT_TYPE", label: "CUIL" },

    // Condición IVA
    { type: "IVA_CONDITION", label: "Responsable Inscripto" },
    { type: "IVA_CONDITION", label: "Monotributo"           },
    { type: "IVA_CONDITION", label: "Consumidor Final"      },
    { type: "IVA_CONDITION", label: "Exento"                },

    // Prefijos telefónicos (10 países de referencia)
    { type: "PHONE_PREFIX", label: "AR +54"  }, // Argentina
    { type: "PHONE_PREFIX", label: "UY +598" }, // Uruguay
    { type: "PHONE_PREFIX", label: "CL +56"  }, // Chile
    { type: "PHONE_PREFIX", label: "BR +55"  }, // Brasil
    { type: "PHONE_PREFIX", label: "PY +595" }, // Paraguay
    { type: "PHONE_PREFIX", label: "BO +591" }, // Bolivia
    { type: "PHONE_PREFIX", label: "PE +51"  }, // Perú
    { type: "PHONE_PREFIX", label: "US +1"   }, // Estados Unidos
    { type: "PHONE_PREFIX", label: "ES +34"  }, // España
    { type: "PHONE_PREFIX", label: "IT +39"  }, // Italia

    // Países
    { type: "COUNTRY", label: "Argentina"      },
    { type: "COUNTRY", label: "Uruguay"        },
    { type: "COUNTRY", label: "Chile"          },
    { type: "COUNTRY", label: "Brasil"         },
    { type: "COUNTRY", label: "Paraguay"       },
    { type: "COUNTRY", label: "Bolivia"        },
    { type: "COUNTRY", label: "Perú"           },
    { type: "COUNTRY", label: "Estados Unidos" },
    { type: "COUNTRY", label: "España"         },
    { type: "COUNTRY", label: "Italia"         },

    // Provincias argentinas
    { type: "PROVINCE", label: "Buenos Aires"                  },
    { type: "PROVINCE", label: "Catamarca"                     },
    { type: "PROVINCE", label: "Chaco"                         },
    { type: "PROVINCE", label: "Chubut"                        },
    { type: "PROVINCE", label: "Córdoba"                       },
    { type: "PROVINCE", label: "Corrientes"                    },
    { type: "PROVINCE", label: "Entre Ríos"                    },
    { type: "PROVINCE", label: "Formosa"                       },
    { type: "PROVINCE", label: "Jujuy"                         },
    { type: "PROVINCE", label: "La Pampa"                      },
    { type: "PROVINCE", label: "La Rioja"                      },
    { type: "PROVINCE", label: "Mendoza"                       },
    { type: "PROVINCE", label: "Misiones"                      },
    { type: "PROVINCE", label: "Neuquén"                       },
    { type: "PROVINCE", label: "Río Negro"                     },
    { type: "PROVINCE", label: "Salta"                         },
    { type: "PROVINCE", label: "San Juan"                      },
    { type: "PROVINCE", label: "San Luis"                      },
    { type: "PROVINCE", label: "Santa Cruz"                    },
    { type: "PROVINCE", label: "Santa Fe"                      },
    { type: "PROVINCE", label: "Santiago del Estero"           },
    { type: "PROVINCE", label: "Tierra del Fuego"              },
    { type: "PROVINCE", label: "Tucumán"                       },

    // Ciudades principales
    { type: "CITY", label: "Ciudad Autónoma de Buenos Aires" },
    { type: "CITY", label: "La Plata"                        },
    { type: "CITY", label: "Mar del Plata"                   },
    { type: "CITY", label: "Córdoba"                         },
    { type: "CITY", label: "Rosario"                         },
    { type: "CITY", label: "Mendoza"                         },
    { type: "CITY", label: "San Miguel de Tucumán"           },
    { type: "CITY", label: "Salta"                           },
    { type: "CITY", label: "Neuquén"                         },
    { type: "CITY", label: "San Carlos de Bariloche"         },

    // Términos de pago
    { type: "PAYMENT_TERM", label: "Contado"       },
    { type: "PAYMENT_TERM", label: "30 días"        },
    { type: "PAYMENT_TERM", label: "60 días"        },
    { type: "PAYMENT_TERM", label: "90 días"        },
    { type: "PAYMENT_TERM", label: "15 días"        },
    { type: "PAYMENT_TERM", label: "Anticipo 50%"   },
    { type: "PAYMENT_TERM", label: "Anticipo 100%"  },

    // Marcas de artículos
    { type: "ARTICLE_BRAND", label: "Genérica"  },
    { type: "ARTICLE_BRAND", label: "Sin marca" },

    // Fabricantes
    { type: "ARTICLE_MANUFACTURER", label: "Fabricación propia" },
    { type: "ARTICLE_MANUFACTURER", label: "Tercero"            },

    // Unidades de medida
    { type: "UNIT_OF_MEASURE", label: "UND" },
    { type: "UNIT_OF_MEASURE", label: "GR"  },
    { type: "UNIT_OF_MEASURE", label: "KG"  },
    { type: "UNIT_OF_MEASURE", label: "MT"  },
    { type: "UNIT_OF_MEASURE", label: "PAR" },

    // Bases del multiplicador de costo
    { type: "MULTIPLIER_BASE", label: "Gramos"  },
    { type: "MULTIPLIER_BASE", label: "Kilates" },
    { type: "MULTIPLIER_BASE", label: "Piezas"  },
  ];

  // Un solo batch insert en lugar de N upserts individuales — mucho más rápido dentro de TX
  await anyDb.catalogItem.createMany({
    data: catalogDefaults.map((item) => ({
      jewelryId,
      type:      item.type,
      label:     item.label,
      isSystem:  true,
      isActive:  true,
      sortOrder: 0,
    })),
    skipDuplicates: true,
  });

  // ── Taxes ────────────────────────────────────────────────────────────────
  const taxDefaults = [
    { name: "IVA 21%",   code: "IVA21",  rate: "21",   applyOn: "TOTAL" as const },
    { name: "IVA 10.5%", code: "IVA105", rate: "10.5", applyOn: "TOTAL" as const },
  ];

  for (const t of taxDefaults) {
    const exists = await db.tax.findFirst({
      where: { jewelryId, code: t.code, deletedAt: null },
      select: { id: true },
    });
    if (!exists) {
      await db.tax.create({
        data: {
          jewelryId, name: t.name, code: t.code,
          taxType: "IVA", calculationType: "PERCENTAGE",
          rate: t.rate, applyOn: t.applyOn,
          isSystem: true, isActive: true,
        },
      });
    } else {
      await db.tax.update({ where: { id: exists.id }, data: { isSystem: true } });
    }
  }

  // ── PaymentMethods ───────────────────────────────────────────────────────
  const paymentDefaults = [
    { name: "Efectivo",      code: "CASH",     type: "CASH"     as const },
    { name: "Transferencia", code: "TRANSFER", type: "TRANSFER" as const },
  ];

  for (const p of paymentDefaults) {
    const exists = await db.paymentMethod.findFirst({
      where: { jewelryId, code: p.code, deletedAt: null },
      select: { id: true },
    });
    if (!exists) {
      await db.paymentMethod.create({
        data: { jewelryId, name: p.name, code: p.code, type: p.type, isSystem: true, isActive: true },
      });
    } else {
      await db.paymentMethod.update({ where: { id: exists.id }, data: { isSystem: true } });
    }
  }

  // ── ShippingCarriers ─────────────────────────────────────────────────────
  const shippingDefaults = [
    { name: "Retiro en sucursal", code: "PICKUP",   type: "PICKUP"   as const },
    { name: "Envío estándar",     code: "STANDARD", type: "DELIVERY" as const },
  ];

  for (const s of shippingDefaults) {
    const exists = await anyDb.shippingCarrier.findFirst({
      where: { jewelryId, code: s.code, deletedAt: null },
      select: { id: true },
    });
    if (!exists) {
      await anyDb.shippingCarrier.create({
        data: { jewelryId, name: s.name, code: s.code, type: s.type, isSystem: true, isActive: true },
      });
    } else {
      await anyDb.shippingCarrier.update({ where: { id: exists.id }, data: { isSystem: true } });
    }
  }

  // ── PriceLists ───────────────────────────────────────────────────────────
  // Identificadas por code único por tenant (@@unique([jewelryId, code])).
  // Los valores numéricos (márgenes) se cargan desde el inicio para que sean
  // visibles y educativos al abrir la pantalla por primera vez.
  const priceListDefaults = [
    {
      code:          "MINORISTA",
      name:          "Lista Minorista — Valor Unificado",
      description:   "Precio de venta al público. Margen total del 150% sobre el costo base.",
      mode:          "MARGIN_TOTAL" as const,
      marginTotal:   "150",
      isFavorite:    true,
      sortOrder:     0,
    },
    {
      code:          "MAYORISTA",
      name:          "Lista Mayorista — Valor Desglosado",
      description:   "Precio mayorista. 20% sobre el metal y 50% sobre la hechura.",
      mode:          "METAL_HECHURA" as const,
      marginMetal:   "20",
      marginHechura: "50",
      isFavorite:    false,
      sortOrder:     1,
    },
    {
      code:          "COSTO-GRAMO",
      name:          "Lista Costo por Gramo",
      description:   "Precio fijo por gramo de metal. El porcentaje equivale aproximadamente a un margen del 120%.",
      mode:          "COST_PER_GRAM" as const,
      costPerGram:   "120",
      isFavorite:    false,
      sortOrder:     2,
    },
  ];

  for (const pl of priceListDefaults) {
    // upsert en @@unique([jewelryId, code]) — crea si no existe, restaura si fue borrado.
    // update: solo completa los márgenes si estaban vacíos (no sobreescribe valores del usuario).
    await db.priceList.upsert({
      where: { jewelryId_code: { jewelryId, code: pl.code } },
      create: {
        jewelryId,
        name:          pl.name,
        code:          pl.code,
        description:   pl.description,
        scope:         "GENERAL",
        mode:          pl.mode,
        isActive:      true,
        isFavorite:    pl.isFavorite,
        sortOrder:     pl.sortOrder,
        deletedAt:     null,
        marginTotal:   "marginTotal"   in pl ? pl.marginTotal   : null,
        marginMetal:   "marginMetal"   in pl ? pl.marginMetal   : null,
        marginHechura: "marginHechura" in pl ? pl.marginHechura : null,
        costPerGram:   "costPerGram"   in pl ? pl.costPerGram   : null,
      },
      update: {
        // Solo restaurar si fue borrado; no tocar valores que el usuario haya modificado
        deletedAt: null,
      },
    });
  }

  // ── Monedas (ARS base, USD, EUR) ─────────────────────────────────────────
  // Deben crearse ANTES que los metales (las variantes generan MetalQuote en ARS).
  const baseCurrencyId = await ensureCurrencies(anyDb, jewelryId);

  // ── Categorías de joyería + atributos ────────────────────────────────────
  const categoryIds = await ensureJewelryCategories(anyDb, jewelryId);
  await ensureJewelryAttributes(anyDb, jewelryId, categoryIds);

  // ── Metal Oro + variantes ─────────────────────────────────────────────────
  await ensureMetalWithVariants(anyDb, jewelryId, baseCurrencyId);

  // ── Entidades demo (solo si no hay ninguna) ────────────────────────────────
  await ensureDemoEntities(anyDb, jewelryId);
}

/**
 * Crea 2 clientes y 2 proveedores de demostración solo si el tenant aún no tiene entidades.
 * Los datos son ficticios y están claramente marcados con "[DEMO]".
 */
async function ensureDemoEntities(db: any, jewelryId: string): Promise<void> {
  const existing = await db.commercialEntity.count({ where: { jewelryId, deletedAt: null } });
  if (existing > 0) return;

  const demos = [
    { code: "CE-DEMO-001", displayName: "García, María", entityType: "PERSON", isClient: true, isSupplier: false, firstName: "María", lastName: "García", companyName: "", tradeName: "", email: "maria.garcia.demo@ejemplo.com", phone: "AR +54 11 5555-0001", documentType: "DNI", documentNumber: "00-000001-0", ivaCondition: "Consumidor Final", notes: "[DEMO] Cliente de muestra para explorar el sistema." },
    { code: "CE-DEMO-002", displayName: "Pérez Joyería", entityType: "COMPANY", isClient: true, isSupplier: false, firstName: "", lastName: "", companyName: "Joyería Pérez SA", tradeName: "Pérez Joyería", email: "contacto.demo@joyeriaperez.ejemplo.com", phone: "AR +54 11 5555-0002", documentType: "CUIT", documentNumber: "00-000002-0", ivaCondition: "Responsable Inscripto", notes: "[DEMO] Cliente empresa de muestra." },
    { code: "CE-DEMO-003", displayName: "Metales Demo", entityType: "COMPANY", isClient: false, isSupplier: true, firstName: "", lastName: "", companyName: "Distribuidora Metales Demo SRL", tradeName: "Metales Demo", email: "ventas.demo@metalesdemo.ejemplo.com", phone: "AR +54 11 5555-0003", documentType: "CUIT", documentNumber: "00-000003-0", ivaCondition: "Responsable Inscripto", notes: "[DEMO] Proveedor de metales de muestra." },
    { code: "CE-DEMO-004", displayName: "López, Roberto", entityType: "PERSON", isClient: false, isSupplier: true, firstName: "Roberto", lastName: "López", companyName: "", tradeName: "", email: "roberto.lopez.demo@ejemplo.com", phone: "AR +54 11 5555-0004", documentType: "CUIT", documentNumber: "00-000004-0", ivaCondition: "Monotributo", notes: "[DEMO] Proveedor persona física de muestra." },
  ];

  for (const d of demos) {
    const exists = await db.commercialEntity.findFirst({ where: { jewelryId, code: d.code }, select: { id: true } });
    if (!exists) {
      await db.commercialEntity.create({
        data: { ...d, jewelryId, balanceType: "UNIFIED", isActive: true, avatarUrl: "", sourceType: "MANUAL", paymentTerm: "" },
      });
    }
  }
}

/**
 * Initializes email branding fields in Jewelry using data from registration.
 * Only runs on first initialization (skipped if emailSenderName already set).
 *
 * Called exclusively from auth.controller.ts register() — NOT from seed.
 */
export async function ensureEmailBranding(
  db: Prisma.TransactionClient,
  jewelry: {
    id: string;
    name: string;
    phoneCountry: string;
    phoneNumber: string;
    street: string;
    number: string;
    city: string;
    province: string;
    country: string;
  },
  ownerEmail: string
): Promise<void> {
  // Skip if already initialized
  const existing = await db.jewelry.findUnique({
    where: { id: jewelry.id },
    select: { emailSenderName: true },
  });
  if (existing?.emailSenderName) return;

  const phone = [jewelry.phoneCountry, jewelry.phoneNumber].filter(Boolean).join(" ").trim();

  const addressParts = [
    jewelry.street && jewelry.number
      ? `${jewelry.street} ${jewelry.number}`
      : jewelry.street,
    jewelry.city,
    jewelry.province,
    jewelry.country,
  ].filter(Boolean);
  const addressLine = addressParts.join(", ");

  await db.jewelry.update({
    where: { id: jewelry.id },
    data: {
      emailEnabled:     true,
      emailSenderName:  jewelry.name,
      emailReplyTo:     ownerEmail,
      emailContact:     ownerEmail,
      emailPhone:       phone,
      emailAddressLine: addressLine,
      emailSignature:   jewelry.name,
      emailFooter:      addressLine ? `${jewelry.name} · ${addressLine}` : jewelry.name,
    },
  });
}
