import { prisma } from "../../lib/prisma.js";
import type { EntityType, BalanceType, AddressType } from "@prisma/client";
import { aggregateEntityBalance } from "./balance.utils.js";

function s(v: any) {
  return String(v ?? "").trim();
}

function assert(cond: any, msg: string): asserts cond {
  if (!cond) {
    const err: any = new Error(msg);
    err.status = 400;
    throw err;
  }
}

// ---------------------------------------------------------------------------
// displayName calculation — called on every create/update, never edited manually
// ---------------------------------------------------------------------------
function calcDisplayName(
  entityType: EntityType,
  firstName: string,
  lastName: string,
  tradeName: string,
  companyName: string
): string {
  if (entityType === "COMPANY") {
    return tradeName.trim() || companyName.trim() || "Sin nombre";
  }
  const ln = lastName.trim();
  const fn = firstName.trim();
  if (ln && fn) return `${ln}, ${fn}`;
  return ln || fn || "Sin nombre";
}

// ---------------------------------------------------------------------------
// Code generation: CE-0001, CE-0002, ...
// Loop ensures uniqueness even after deletions / gaps
// ---------------------------------------------------------------------------
async function generateCode(jewelryId: string): Promise<string> {
  const total = await prisma.commercialEntity.count({ where: { jewelryId } });
  let seq = total + 1;
  let code = `CE-${String(seq).padStart(4, "0")}`;
  while (
    await prisma.commercialEntity.findFirst({
      where: { jewelryId, code },
      select: { id: true },
    })
  ) {
    seq++;
    code = `CE-${String(seq).padStart(4, "0")}`;
  }
  return code;
}

// ---------------------------------------------------------------------------
// SELECT objects
// ---------------------------------------------------------------------------
const ENTITY_LIST_SELECT = {
  id: true,
  jewelryId: true,
  code: true,
  displayName: true,
  entityType: true,
  isClient: true,
  isSupplier: true,
  firstName: true,
  lastName: true,
  companyName: true,
  tradeName: true,
  email: true,
  phone: true,
  documentType: true,
  documentNumber: true,
  ivaCondition: true,
  avatarUrl: true,
  priceListId: true,
  currencyId: true,
  sellerId: true,
  seller: { select: { id: true, displayName: true, firstName: true, lastName: true, email: true, isActive: true, isFavorite: true } },
  paymentTerm: true,
  commercialApplyOn: true,
  commercialRuleType: true,
  commercialValueType: true,
  commercialValue: true,
  taxExempt: true,
  taxApplyOnOverride: true,
  balanceType: true,
  isActive: true,
  sourceType: true,
  mergedIntoEntityId: true,
  // Conteo de mermas overrides activas. La merma del cliente es relacional
  // (1 row por variante de metal en `EntityMermaOverride`), no un escalar.
  // Si _count > 0, la entidad tiene merma personalizada; si es 0, "Global".
  _count: {
    select: {
      mermaOverrides: { where: { deletedAt: null, isActive: true } },
    },
  },
  createdAt: true,
  updatedAt: true,
} as const;

const ENTITY_DETAIL_SELECT = {
  ...ENTITY_LIST_SELECT,
  creditLimitClient: true,
  creditLimitSupplier: true,
  notes: true,
  deletedAt: true,
  addresses: {
    where: { deletedAt: null },
    select: {
      id: true,
      type: true,
      label: true,
      attn: true,
      street: true,
      streetNumber: true,
      floor: true,
      apartment: true,
      city: true,
      province: true,
      country: true,
      postalCode: true,
      isDefault: true,
      createdAt: true,
    },
    orderBy: { createdAt: "asc" as const },
  },
  contacts: {
    where: { deletedAt: null },
    select: {
      id: true,
      firstName: true,
      lastName: true,
      position: true,
      email: true,
      phonePrefix: true,
      phone: true,
      whatsapp: true,
      isPrimary: true,
      receivesDocuments: true,
      receivesPaymentsOrCollections: true,
      portalAccess: true,
      notes: true,
      createdAt: true,
    },
    orderBy: [
      { createdAt: "asc" as const },
      { lastName: "asc" as const },
      { firstName: "asc" as const },
    ] as any,
  },
  commercialRules: {
    where: { deletedAt: null, isActive: true },
    select: {
      id: true,
      scope: true,
      metalId: true,
      variantId: true,
      categoryId: true,
      ruleType: true,
      valueType: true,
      value: true,
      applyOn: true,
      minQuantity: true,
      validFrom: true,
      validTo: true,
      notes: true,
      isActive: true,
      sortOrder: true,
    },
    orderBy: { sortOrder: "asc" as const },
  },
  taxOverrides: {
    where: { isActive: true },
    select: {
      id: true,
      taxId: true,
      overrideMode: true,
      customRate: true,
      applyOn: true,
      notes: true,
      isActive: true,
    },
  },
  attachments: {
    where: { deletedAt: null },
    select: {
      id: true,
      filename: true,
      url: true,
      mimeType: true,
      size: true,
      label: true,
      createdAt: true,
    },
    orderBy: { createdAt: "asc" as const },
  },
} as const;

// ---------------------------------------------------------------------------
// List (paginated)
// ---------------------------------------------------------------------------
const ENTITY_SORT_MAP: Record<string, string> = {
  displayName:    "displayName",
  email:          "email",
  documentNumber: "documentNumber",
  entityType:     "entityType",
  code:           "code",
  createdAt:      "createdAt",
  updatedAt:      "updatedAt",
};

export async function listEntities(
  jewelryId: string,
  params: {
    role?: "client" | "supplier" | "all";
    q?: string;
    skip?: number;
    take?: number;
    showInactive?: boolean;
    sortKey?: string;
    sortDir?: "asc" | "desc";
  } = {}
) {
  assert(jewelryId, "Tenant inválido.");
  const { role = "all", q = "", skip = 0, take = 25, showInactive = false, sortKey = "displayName", sortDir = "asc" } = params;

  const roleFilter =
    role === "client"
      ? { isClient: true }
      : role === "supplier"
      ? { isSupplier: true }
      : {};

  const searchFilter = q.trim()
    ? {
        OR: [
          { displayName: { contains: q, mode: "insensitive" as const } },
          { code: { contains: q, mode: "insensitive" as const } },
          { documentNumber: { contains: q, mode: "insensitive" as const } },
          { email: { contains: q, mode: "insensitive" as const } },
          { phone: { contains: q, mode: "insensitive" as const } },
        ],
      }
    : {};

  const activeFilter = showInactive ? {} : { isActive: true };

  const where = {
    jewelryId,
    deletedAt: null,
    ...roleFilter,
    ...activeFilter,
    ...searchFilter,
  };

  const [rowsRaw, total] = await Promise.all([
    prisma.commercialEntity.findMany({
      where,
      select: {
        ...ENTITY_LIST_SELECT,
        _count: {
          select: {
            relationsFrom: { where: { deletedAt: null } },
            relationsTo:   { where: { deletedAt: null } },
          },
        },
      },
      orderBy: { [ENTITY_SORT_MAP[sortKey] ?? "displayName"]: sortDir },
      skip,
      take,
    }),
    prisma.commercialEntity.count({ where }),
  ]);

  const rows = rowsRaw.map(({ _count, ...e }) => ({
    ...e,
    hasRelations: (_count.relationsFrom + _count.relationsTo) > 0,
  }));

  return { rows, total, skip, take };
}

// ---------------------------------------------------------------------------
// Get one (full detail)
// ---------------------------------------------------------------------------
export async function getEntity(id: string, jewelryId: string) {
  assert(id, "Id inválido.");
  assert(jewelryId, "Tenant inválido.");

  const [raw, balanceEntries] = await Promise.all([
    prisma.commercialEntity.findFirst({
      where: { id, jewelryId, deletedAt: null },
      select: {
        ...ENTITY_DETAIL_SELECT,
        _count: {
          select: {
            relationsFrom: { where: { deletedAt: null } },
            relationsTo:   { where: { deletedAt: null } },
          },
        },
      },
    }),
    prisma.entityBalanceEntry.findMany({
      where: { entityId: id, jewelryId },
      select: {
        id: true,
        role: true,
        entryType: true,
        amount: true,
        currency: true,
        documentRef: true,
        notes: true,
        createdAt: true,
        voidedAt: true,
        breakdownSnapshot: true,
      },
      orderBy: { createdAt: "desc" },
    }),
  ]);

  assert(raw, "Entidad no encontrada.");
  const { _count, ...entity } = raw;

  // Calcular balance agregado
  const balanceType = entity.balanceType as "UNIFIED" | "BREAKDOWN";
  const balance = aggregateEntityBalance(
    balanceEntries.map((e) => ({
      amount:            e.amount,
      voidedAt:          e.voidedAt,
      breakdownSnapshot: e.breakdownSnapshot,
    })),
    balanceType,
  );

  return {
    ...entity,
    hasRelations: (_count.relationsFrom + _count.relationsTo) > 0,
    balance,
    balanceEntries,
  };
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------
// Vendedor por defecto — resuelve y valida `sellerId` recibido del cliente.
// Devuelve:
//   - el id si la variante existe en el tenant, no soft-deleted y activa,
//   - null si el caller envió string vacío / null / undefined explícitamente.
// Lanza 400 si el id no existe en el tenant o el vendedor está inactivo/borrado.
// ---------------------------------------------------------------------------
async function resolveDefaultSellerId(
  jewelryId: string,
  raw: unknown,
): Promise<string | null> {
  if (raw === undefined) return null;
  const id = typeof raw === "string" ? raw.trim() : "";
  if (!id) return null;
  const seller = await prisma.seller.findFirst({
    where: { id, jewelryId, deletedAt: null },
    select: { id: true, isActive: true },
  });
  assert(seller, "El vendedor seleccionado no existe o pertenece a otro tenant.");
  assert(seller!.isActive, "El vendedor seleccionado está inactivo.");
  return seller!.id;
}

// ---------------------------------------------------------------------------
export async function createEntity(jewelryId: string, data: any) {
  assert(jewelryId, "Tenant inválido.");

  const entityType: EntityType = data?.entityType === "COMPANY" ? "COMPANY" : "PERSON";
  const isClient = data?.isClient === true;
  const isSupplier = data?.isSupplier === true;

  assert(isClient || isSupplier, "La entidad debe ser cliente, proveedor o ambos.");

  const firstName = s(data?.firstName);
  const lastName = s(data?.lastName);
  const companyName = s(data?.companyName);
  const tradeName = s(data?.tradeName);

  if (entityType === "PERSON") {
    assert(firstName, "El nombre es obligatorio para personas físicas.");
    assert(lastName, "El apellido es obligatorio para personas físicas.");
  } else {
    assert(tradeName, "El nombre de fantasía es obligatorio para empresas.");
  }

  const displayName = calcDisplayName(entityType, firstName, lastName, tradeName, companyName);
  const code = await generateCode(jewelryId);

  const balanceType: BalanceType =
    data?.balanceType === "BREAKDOWN" ? "BREAKDOWN" : "UNIFIED";

  const creditLimitClient =
    data?.creditLimitClient != null && data.creditLimitClient !== ""
      ? String(data.creditLimitClient)
      : undefined;
  const creditLimitSupplier =
    data?.creditLimitSupplier != null && data.creditLimitSupplier !== ""
      ? String(data.creditLimitSupplier)
      : undefined;

  const sellerId = await resolveDefaultSellerId(jewelryId, data?.sellerId);

  return prisma.commercialEntity.create({
    data: {
      jewelryId,
      code,
      displayName,
      entityType,
      isClient,
      isSupplier,
      firstName,
      lastName,
      companyName,
      tradeName,
      email: s(data?.email),
      phone: s(data?.phone),
      documentType: s(data?.documentType),
      documentNumber: s(data?.documentNumber),
      ivaCondition: s(data?.ivaCondition),
      balanceType,
      creditLimitClient,
      creditLimitSupplier,
      priceListId: data?.priceListId || null,
      currencyId: data?.currencyId || null,
      sellerId,
      paymentTerm: s(data?.paymentTerm),
      commercialApplyOn: data?.commercialApplyOn || null,
      commercialRuleType: data?.commercialRuleType || null,
      commercialValueType: data?.commercialValueType || null,
      commercialValue:
        data?.commercialValue != null && data.commercialValue !== ""
          ? String(data.commercialValue)
          : null,
      taxExempt: data?.taxExempt === true,
      taxApplyOnOverride: data?.taxApplyOnOverride || null,
      notes: s(data?.notes),
      isActive: true,
      sourceType: "MANUAL",
    },
    select: ENTITY_DETAIL_SELECT,
  });
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------
export async function updateEntity(id: string, jewelryId: string, data: any) {
  assert(id, "Id inválido.");
  assert(jewelryId, "Tenant inválido.");

  const existing = await prisma.commercialEntity.findFirst({
    where: { id, jewelryId, deletedAt: null },
    select: { id: true },
  });
  assert(existing, "Entidad no encontrada.");

  const entityType: EntityType = data?.entityType === "COMPANY" ? "COMPANY" : "PERSON";
  const isClient = data?.isClient === true;
  const isSupplier = data?.isSupplier === true;

  assert(isClient || isSupplier, "La entidad debe ser cliente, proveedor o ambos.");

  const firstName = s(data?.firstName);
  const lastName = s(data?.lastName);
  const companyName = s(data?.companyName);
  const tradeName = s(data?.tradeName);

  if (entityType === "PERSON") {
    assert(firstName, "El nombre es obligatorio para personas físicas.");
    assert(lastName, "El apellido es obligatorio para personas físicas.");
  } else {
    assert(tradeName, "El nombre de fantasía es obligatorio para empresas.");
  }

  const displayName = calcDisplayName(entityType, firstName, lastName, tradeName, companyName);

  const balanceType: BalanceType =
    data?.balanceType === "BREAKDOWN" ? "BREAKDOWN" : "UNIFIED";

  const creditLimitClient =
    data?.creditLimitClient != null && data.creditLimitClient !== ""
      ? String(data.creditLimitClient)
      : null;
  const creditLimitSupplier =
    data?.creditLimitSupplier != null && data.creditLimitSupplier !== ""
      ? String(data.creditLimitSupplier)
      : null;

  // Vendedor por defecto: solo se actualiza si el caller mandó el campo. Si el
  // payload no trae `sellerId`, preservamos el valor actual.
  const sellerIdPatch = data?.sellerId === undefined
    ? {}
    : { sellerId: await resolveDefaultSellerId(jewelryId, data.sellerId) };

  return prisma.commercialEntity.update({
    where: { id },
    data: {
      displayName,
      entityType,
      isClient,
      isSupplier,
      firstName,
      lastName,
      companyName,
      tradeName,
      email: s(data?.email),
      phone: s(data?.phone),
      documentType: s(data?.documentType),
      documentNumber: s(data?.documentNumber),
      ivaCondition: s(data?.ivaCondition),
      balanceType,
      creditLimitClient,
      creditLimitSupplier,
      priceListId: data?.priceListId || null,
      currencyId: data?.currencyId || null,
      ...sellerIdPatch,
      paymentTerm: s(data?.paymentTerm),
      commercialApplyOn: data?.commercialApplyOn || null,
      commercialRuleType: data?.commercialRuleType || null,
      commercialValueType: data?.commercialValueType || null,
      commercialValue:
        data?.commercialValue != null && data.commercialValue !== ""
          ? String(data.commercialValue)
          : null,
      taxExempt: data?.taxExempt === true,
      taxApplyOnOverride: data?.taxApplyOnOverride || null,
      notes: s(data?.notes),
    },
    select: ENTITY_DETAIL_SELECT,
  });
}

// ---------------------------------------------------------------------------
// Toggle active/inactive
// ---------------------------------------------------------------------------
export async function toggleEntity(id: string, jewelryId: string) {
  assert(id, "Id inválido.");
  assert(jewelryId, "Tenant inválido.");

  const entity = await prisma.commercialEntity.findFirst({
    where: { id, jewelryId, deletedAt: null },
    select: { id: true, isActive: true },
  });
  assert(entity, "Entidad no encontrada.");

  return prisma.commercialEntity.update({
    where: { id },
    data: { isActive: !entity.isActive },
    select: ENTITY_LIST_SELECT,
  });
}

// ---------------------------------------------------------------------------
// Soft delete — protected: cannot delete if has financial history
// ---------------------------------------------------------------------------
export async function deleteEntity(id: string, jewelryId: string) {
  assert(id, "Id inválido.");
  assert(jewelryId, "Tenant inválido.");

  const entity = await prisma.commercialEntity.findFirst({
    where: { id, jewelryId, deletedAt: null },
    select: {
      id: true,
      _count: {
        select: { balanceEntries: true },
      },
    },
  });
  assert(entity, "Entidad no encontrada.");

  assert(
    entity._count.balanceEntries === 0,
    "No se puede eliminar esta entidad porque tiene movimientos en cuenta corriente. Podés inactivarla en su lugar."
  );

  return prisma.commercialEntity.update({
    where: { id },
    data: { deletedAt: new Date(), isActive: false },
    select: { id: true },
  });
}

// ---------------------------------------------------------------------------
// Bulk soft-delete — máx. 100 IDs por operación
// Protección: no elimina entidades con historial financiero (balanceEntries)
// ---------------------------------------------------------------------------
export async function bulkDeleteEntities(ids: string[], jewelryId: string) {
  assert(ids.length > 0, "Se requiere al menos un ID.");
  assert(jewelryId, "Tenant inválido.");

  const capped = ids.slice(0, 100);

  const entities = await prisma.commercialEntity.findMany({
    where: { id: { in: capped }, jewelryId, deletedAt: null },
    select: { id: true, _count: { select: { balanceEntries: true } } },
  });

  const deletable: string[] = [];
  let blocked = 0;

  for (const e of entities) {
    if (e._count.balanceEntries > 0) {
      blocked++;
    } else {
      deletable.push(e.id);
    }
  }

  const skipped = capped.length - entities.length;

  if (deletable.length > 0) {
    await prisma.commercialEntity.updateMany({
      where: { id: { in: deletable }, jewelryId },
      data: { deletedAt: new Date(), isActive: false },
    });
  }

  return { deleted: deletable.length, blocked, skipped };
}

// ===========================================================================
// Helpers for sub-resources
// ===========================================================================
const VALID_ADDR_TYPES = new Set(["BILLING", "SHIPPING", "FISCAL", "COMMERCIAL", "OTHER"]);

const ADDRESS_SELECT = {
  id: true,
  type: true,
  label: true,
  attn: true,
  street: true,
  streetNumber: true,
  floor: true,
  apartment: true,
  city: true,
  province: true,
  country: true,
  postalCode: true,
  isDefault: true,
  createdAt: true,
} as const;

const CONTACT_SELECT = {
  id: true,
  firstName: true,
  lastName: true,
  position: true,
  email: true,
  phonePrefix: true,
  phone: true,
  whatsapp: true,
  isPrimary: true,
  receivesDocuments: true,
  receivesPaymentsOrCollections: true,
  portalAccess: true,
  notes: true,
  createdAt: true,
} as const;

const ATTACHMENT_SELECT = {
  id: true,
  filename: true,
  url: true,
  mimeType: true,
  size: true,
  label: true,
  createdAt: true,
} as const;

async function assertEntityOwnership(entityId: string, jewelryId: string) {
  const entity = await prisma.commercialEntity.findFirst({
    where: { id: entityId, jewelryId, deletedAt: null },
    select: { id: true },
  });
  assert(entity, "Entidad no encontrada.");
}

// ===========================================================================
// Addresses
// ===========================================================================
export async function listAddresses(entityId: string, jewelryId: string) {
  assert(entityId, "Id de entidad inválido.");
  assert(jewelryId, "Tenant inválido.");
  await assertEntityOwnership(entityId, jewelryId);
  return prisma.entityAddress.findMany({
    where: { entityId, deletedAt: null },
    select: ADDRESS_SELECT,
    orderBy: [{ isDefault: "desc" as const }, { createdAt: "asc" as const }],
  });
}

export async function createAddress(entityId: string, jewelryId: string, data: any) {
  assert(entityId, "Id de entidad inválido.");
  assert(jewelryId, "Tenant inválido.");
  await assertEntityOwnership(entityId, jewelryId);

  const type: AddressType = VALID_ADDR_TYPES.has(data?.type) ? data.type : "OTHER";

  // Backend rule: first address of a given type is always default
  const existingCount = await prisma.entityAddress.count({
    where: { entityId, deletedAt: null, type },
  });
  const makeDefault = existingCount === 0 || data?.isDefault === true;

  return prisma.$transaction(async (tx) => {
    if (makeDefault) {
      await tx.entityAddress.updateMany({
        where: { entityId, type, deletedAt: null },
        data: { isDefault: false },
      });
    }
    return tx.entityAddress.create({
      data: {
        entityId,
        jewelryId,
        type,
        label: s(data?.label),
        attn: s(data?.attn),
        street: s(data?.street),
        streetNumber: s(data?.streetNumber),
        floor: s(data?.floor),
        apartment: s(data?.apartment),
        city: s(data?.city),
        province: s(data?.province),
        country: s(data?.country) || "Argentina",
        postalCode: s(data?.postalCode),
        isDefault: makeDefault,
      },
      select: ADDRESS_SELECT,
    });
  });
}

export async function updateAddress(entityId: string, addressId: string, jewelryId: string, data: any) {
  assert(entityId && addressId, "Ids inválidos.");
  assert(jewelryId, "Tenant inválido.");
  await assertEntityOwnership(entityId, jewelryId);

  const existing = await prisma.entityAddress.findFirst({
    where: { id: addressId, entityId, deletedAt: null },
    select: { id: true, type: true, isDefault: true },
  });
  assert(existing, "Dirección no encontrada.");

  const newType: AddressType = VALID_ADDR_TYPES.has(data?.type) ? data.type : existing.type;
  const typeChanged = newType !== existing.type;

  // Enforce first-of-type rule: if this is the only address of its type, it must stay default
  let makeDefault = data?.isDefault === true;
  if (typeChanged) {
    // Type changed: check if the new type has no other addresses
    const countOfNewType = await prisma.entityAddress.count({
      where: { entityId, deletedAt: null, type: newType, id: { not: addressId } },
    });
    if (countOfNewType === 0) makeDefault = true; // first of new type, force default
  } else if (!makeDefault) {
    // Same type, isDefault=false requested: only allow if there is another default of this type
    const othersOfType = await prisma.entityAddress.count({
      where: { entityId, deletedAt: null, type: newType, id: { not: addressId } },
    });
    if (othersOfType === 0) makeDefault = true; // única del tipo, forzar default
  }

  return prisma.$transaction(async (tx) => {
    if (makeDefault) {
      await tx.entityAddress.updateMany({
        where: { entityId, type: newType, deletedAt: null, id: { not: addressId } },
        data: { isDefault: false },
      });
    }
    return tx.entityAddress.update({
      where: { id: addressId },
      data: {
        type: newType,
        label: s(data?.label),
        attn: s(data?.attn),
        street: s(data?.street),
        streetNumber: s(data?.streetNumber),
        floor: s(data?.floor),
        apartment: s(data?.apartment),
        city: s(data?.city),
        province: s(data?.province),
        country: s(data?.country) || "Argentina",
        postalCode: s(data?.postalCode),
        isDefault: makeDefault,
      },
      select: ADDRESS_SELECT,
    });
  });
}

export async function removeAddress(entityId: string, addressId: string, jewelryId: string) {
  assert(entityId && addressId, "Ids inválidos.");
  assert(jewelryId, "Tenant inválido.");
  await assertEntityOwnership(entityId, jewelryId);

  const address = await prisma.entityAddress.findFirst({
    where: { id: addressId, entityId, deletedAt: null },
    select: { id: true },
  });
  assert(address, "Dirección no encontrada.");

  await prisma.entityAddress.update({
    where: { id: addressId },
    data: { deletedAt: new Date() },
  });
  return { id: addressId };
}

export async function setDefaultAddress(entityId: string, addressId: string, jewelryId: string) {
  assert(entityId && addressId, "Ids inválidos.");
  assert(jewelryId, "Tenant inválido.");
  await assertEntityOwnership(entityId, jewelryId);

  const address = await prisma.entityAddress.findFirst({
    where: { id: addressId, entityId, deletedAt: null },
    select: { id: true, type: true },
  });
  assert(address, "Dirección no encontrada.");

  return prisma.$transaction(async (tx) => {
    await tx.entityAddress.updateMany({
      where: { entityId, type: address.type, deletedAt: null },
      data: { isDefault: false },
    });
    return tx.entityAddress.update({
      where: { id: addressId },
      data: { isDefault: true },
      select: ADDRESS_SELECT,
    });
  });
}

// ===========================================================================
// Contacts
// ===========================================================================
export async function listContacts(entityId: string, jewelryId: string) {
  assert(entityId, "Id de entidad inválido.");
  assert(jewelryId, "Tenant inválido.");
  await assertEntityOwnership(entityId, jewelryId);
  return prisma.entityContact.findMany({
    where: { entityId, deletedAt: null },
    select: CONTACT_SELECT,
    orderBy: [
      { createdAt: "asc" as const },
      { lastName: "asc" as const },
      { firstName: "asc" as const },
    ],
  });
}

export async function createContact(entityId: string, jewelryId: string, data: any) {
  assert(entityId, "Id de entidad inválido.");
  assert(jewelryId, "Tenant inválido.");
  await assertEntityOwnership(entityId, jewelryId);

  const firstName = s(data?.firstName);
  const lastName = s(data?.lastName);
  assert(firstName || lastName, "El contacto debe tener al menos nombre o apellido.");

  const makePrimary = data?.isPrimary === true;

  return prisma.$transaction(async (tx) => {
    if (makePrimary) {
      await tx.entityContact.updateMany({
        where: { entityId, deletedAt: null },
        data: { isPrimary: false },
      });
    }
    return tx.entityContact.create({
      data: {
        entityId,
        jewelryId,
        firstName,
        lastName,
        position: s(data?.position),
        email: s(data?.email),
        phonePrefix: s(data?.phonePrefix),
        phone: s(data?.phone),
        whatsapp: s(data?.whatsapp),
        isPrimary: makePrimary,
        receivesDocuments: data?.receivesDocuments === true,
        receivesPaymentsOrCollections: data?.receivesPaymentsOrCollections === true,
        portalAccess: false, // reservado para portal futuro
        notes: s(data?.notes),
      },
      select: CONTACT_SELECT,
    });
  });
}

export async function updateContact(entityId: string, contactId: string, jewelryId: string, data: any) {
  assert(entityId && contactId, "Ids inválidos.");
  assert(jewelryId, "Tenant inválido.");
  await assertEntityOwnership(entityId, jewelryId);

  const existing = await prisma.entityContact.findFirst({
    where: { id: contactId, entityId, deletedAt: null },
    select: { id: true },
  });
  assert(existing, "Contacto no encontrado.");

  const firstName = s(data?.firstName);
  const lastName = s(data?.lastName);
  assert(firstName || lastName, "El contacto debe tener al menos nombre o apellido.");

  const makePrimary = data?.isPrimary === true;

  return prisma.$transaction(async (tx) => {
    if (makePrimary) {
      await tx.entityContact.updateMany({
        where: { entityId, deletedAt: null, id: { not: contactId } },
        data: { isPrimary: false },
      });
    }
    return tx.entityContact.update({
      where: { id: contactId },
      data: {
        firstName,
        lastName,
        position: s(data?.position),
        email: s(data?.email),
        phonePrefix: s(data?.phonePrefix),
        phone: s(data?.phone),
        whatsapp: s(data?.whatsapp),
        isPrimary: makePrimary,
        receivesDocuments: data?.receivesDocuments === true,
        receivesPaymentsOrCollections: data?.receivesPaymentsOrCollections === true,
        notes: s(data?.notes),
      },
      select: CONTACT_SELECT,
    });
  });
}

export async function removeContact(entityId: string, contactId: string, jewelryId: string) {
  assert(entityId && contactId, "Ids inválidos.");
  assert(jewelryId, "Tenant inválido.");
  await assertEntityOwnership(entityId, jewelryId);

  const contact = await prisma.entityContact.findFirst({
    where: { id: contactId, entityId, deletedAt: null },
    select: { id: true },
  });
  assert(contact, "Contacto no encontrado.");

  await prisma.entityContact.update({
    where: { id: contactId },
    data: { deletedAt: new Date() },
  });
  return { id: contactId };
}

export async function setPrimaryContact(entityId: string, contactId: string, jewelryId: string) {
  assert(entityId && contactId, "Ids inválidos.");
  assert(jewelryId, "Tenant inválido.");
  await assertEntityOwnership(entityId, jewelryId);

  const contact = await prisma.entityContact.findFirst({
    where: { id: contactId, entityId, deletedAt: null },
    select: { id: true },
  });
  assert(contact, "Contacto no encontrado.");

  return prisma.$transaction(async (tx) => {
    await tx.entityContact.updateMany({
      where: { entityId, deletedAt: null },
      data: { isPrimary: false },
    });
    return tx.entityContact.update({
      where: { id: contactId },
      data: { isPrimary: true },
      select: CONTACT_SELECT,
    });
  });
}

// ===========================================================================
// Attachments
// ===========================================================================
export async function listAttachments(entityId: string, jewelryId: string) {
  assert(entityId, "Id de entidad inválido.");
  assert(jewelryId, "Tenant inválido.");
  await assertEntityOwnership(entityId, jewelryId);
  return prisma.entityAttachment.findMany({
    where: { entityId, deletedAt: null },
    select: ATTACHMENT_SELECT,
    orderBy: { createdAt: "desc" as const },
  });
}

export async function addAttachment(
  entityId: string,
  jewelryId: string,
  data: { filename: string; url: string; mimeType: string; size: number; label?: string; uploadedBy?: string }
) {
  assert(entityId, "Id de entidad inválido.");
  assert(jewelryId, "Tenant inválido.");
  assert(data?.filename, "Nombre de archivo inválido.");
  assert(data?.url, "URL inválida.");
  await assertEntityOwnership(entityId, jewelryId);

  return prisma.entityAttachment.create({
    data: {
      entityId,
      jewelryId,
      filename: data.filename,
      url: data.url,
      mimeType: data.mimeType || "",
      size: data.size || 0,
      label: s(data?.label),
      uploadedBy: s(data?.uploadedBy),
    },
    select: ATTACHMENT_SELECT,
  });
}

export async function updateAttachmentLabel(
  entityId: string,
  attachmentId: string,
  jewelryId: string,
  label: string
) {
  assert(entityId && attachmentId, "Ids inválidos.");
  assert(jewelryId, "Tenant inválido.");
  await assertEntityOwnership(entityId, jewelryId);

  const att = await prisma.entityAttachment.findFirst({
    where: { id: attachmentId, entityId, deletedAt: null },
    select: { id: true },
  });
  assert(att, "Adjunto no encontrado.");

  return prisma.entityAttachment.update({
    where: { id: attachmentId },
    data: { label: s(label) },
    select: ATTACHMENT_SELECT,
  });
}

export async function removeAttachment(entityId: string, attachmentId: string, jewelryId: string) {
  assert(entityId && attachmentId, "Ids inválidos.");
  assert(jewelryId, "Tenant inválido.");
  await assertEntityOwnership(entityId, jewelryId);

  const att = await prisma.entityAttachment.findFirst({
    where: { id: attachmentId, entityId, deletedAt: null },
    select: { id: true },
  });
  assert(att, "Adjunto no encontrado.");

  await prisma.entityAttachment.update({
    where: { id: attachmentId },
    data: { deletedAt: new Date() },
  });
  return { id: attachmentId };
}

// ===========================================================================
// Commercial Rules
// ===========================================================================
const VALID_SCOPES = new Set(["GLOBAL", "METAL", "VARIANT", "CATEGORY"]);
const VALID_RULE_TYPES = new Set(["DISCOUNT", "BONUS", "SURCHARGE"]);
const VALID_VALUE_TYPES = new Set(["PERCENTAGE", "FIXED_AMOUNT"]);
// CommercialApplyOn — used for commercial rules
const VALID_APPLY_ON = new Set(["TOTAL", "METAL", "HECHURA", "METAL_Y_HECHURA"]);
// TaxApplyOn — used for tax override applyOn (superset of CommercialApplyOn)
const VALID_TAX_APPLY_ON = new Set(["TOTAL", "METAL", "HECHURA", "METAL_Y_HECHURA", "SUBTOTAL_AFTER_DISCOUNT", "SUBTOTAL_BEFORE_DISCOUNT"]);

const RULE_SELECT = {
  id: true,
  scope: true,
  metalId: true,
  variantId: true,
  categoryId: true,
  ruleType: true,
  valueType: true,
  value: true,
  applyOn: true,
  minQuantity: true,
  validFrom: true,
  validTo: true,
  notes: true,
  isActive: true,
  sortOrder: true,
  createdAt: true,
} as const;

export async function listRules(entityId: string, jewelryId: string) {
  assert(entityId && jewelryId, "Ids inválidos.");
  await assertEntityOwnership(entityId, jewelryId);
  return prisma.entityCommercialRule.findMany({
    where: { entityId, deletedAt: null },
    select: RULE_SELECT,
    orderBy: [{ sortOrder: "asc" as const }, { createdAt: "asc" as const }],
  });
}

export async function createRule(entityId: string, jewelryId: string, data: any) {
  assert(entityId && jewelryId, "Ids inválidos.");
  await assertEntityOwnership(entityId, jewelryId);

  const scope = VALID_SCOPES.has(data?.scope) ? data.scope : "GLOBAL";
  const ruleType = VALID_RULE_TYPES.has(data?.ruleType) ? data.ruleType : "DISCOUNT";
  const valueType = VALID_VALUE_TYPES.has(data?.valueType) ? data.valueType : "PERCENTAGE";
  const applyOn = VALID_APPLY_ON.has(data?.applyOn) ? data.applyOn : "TOTAL";

  assert(data?.value != null && data.value !== "", "El valor de la regla es obligatorio.");
  const value = String(data.value);

  const validFrom = data?.validFrom ? new Date(data.validFrom) : null;
  const validTo = data?.validTo ? new Date(data.validTo) : null;
  if (validFrom && validTo) {
    assert(validFrom <= validTo, "La fecha 'desde' no puede ser posterior a 'hasta'.");
  }

  return prisma.entityCommercialRule.create({
    data: {
      entityId,
      jewelryId,
      scope,
      ruleType,
      valueType,
      value,
      applyOn,
      metalId: scope === "METAL" ? (data?.metalId || null) : null,
      variantId: scope === "VARIANT" ? (data?.variantId || null) : null,
      categoryId: scope === "CATEGORY" ? (data?.categoryId || null) : null,
      minQuantity: data?.minQuantity != null && data.minQuantity !== "" ? String(data.minQuantity) : null,
      validFrom,
      validTo,
      notes: s(data?.notes),
      isActive: true,
      sortOrder: typeof data?.sortOrder === "number" ? data.sortOrder : 0,
    },
    select: RULE_SELECT,
  });
}

export async function updateRule(entityId: string, ruleId: string, jewelryId: string, data: any) {
  assert(entityId && ruleId && jewelryId, "Ids inválidos.");
  await assertEntityOwnership(entityId, jewelryId);

  const rule = await prisma.entityCommercialRule.findFirst({
    where: { id: ruleId, entityId, deletedAt: null },
    select: { id: true },
  });
  assert(rule, "Regla no encontrada.");

  const scope = VALID_SCOPES.has(data?.scope) ? data.scope : "GLOBAL";
  const ruleType = VALID_RULE_TYPES.has(data?.ruleType) ? data.ruleType : "DISCOUNT";
  const valueType = VALID_VALUE_TYPES.has(data?.valueType) ? data.valueType : "PERCENTAGE";
  const applyOn = VALID_APPLY_ON.has(data?.applyOn) ? data.applyOn : "TOTAL";

  assert(data?.value != null && data.value !== "", "El valor de la regla es obligatorio.");

  const validFrom = data?.validFrom ? new Date(data.validFrom) : null;
  const validTo = data?.validTo ? new Date(data.validTo) : null;
  if (validFrom && validTo) {
    assert(validFrom <= validTo, "La fecha 'desde' no puede ser posterior a 'hasta'.");
  }

  return prisma.entityCommercialRule.update({
    where: { id: ruleId },
    data: {
      scope,
      ruleType,
      valueType,
      value: String(data.value),
      applyOn,
      metalId: scope === "METAL" ? (data?.metalId || null) : null,
      variantId: scope === "VARIANT" ? (data?.variantId || null) : null,
      categoryId: scope === "CATEGORY" ? (data?.categoryId || null) : null,
      minQuantity: data?.minQuantity != null && data.minQuantity !== "" ? String(data.minQuantity) : null,
      validFrom,
      validTo,
      notes: s(data?.notes),
      sortOrder: typeof data?.sortOrder === "number" ? data.sortOrder : 0,
    },
    select: RULE_SELECT,
  });
}

export async function toggleRule(entityId: string, ruleId: string, jewelryId: string) {
  assert(entityId && ruleId && jewelryId, "Ids inválidos.");
  await assertEntityOwnership(entityId, jewelryId);

  const rule = await prisma.entityCommercialRule.findFirst({
    where: { id: ruleId, entityId, deletedAt: null },
    select: { id: true, isActive: true },
  });
  assert(rule, "Regla no encontrada.");

  return prisma.entityCommercialRule.update({
    where: { id: ruleId },
    data: { isActive: !rule.isActive },
    select: RULE_SELECT,
  });
}

export async function removeRule(entityId: string, ruleId: string, jewelryId: string) {
  assert(entityId && ruleId && jewelryId, "Ids inválidos.");
  await assertEntityOwnership(entityId, jewelryId);

  const rule = await prisma.entityCommercialRule.findFirst({
    where: { id: ruleId, entityId, deletedAt: null },
    select: { id: true },
  });
  assert(rule, "Regla no encontrada.");

  await prisma.entityCommercialRule.update({
    where: { id: ruleId },
    data: { deletedAt: new Date(), isActive: false },
  });
  return { id: ruleId };
}

// ===========================================================================
// Tax Overrides
// ===========================================================================
const VALID_OVERRIDE_MODES = new Set(["INHERIT", "EXEMPT", "CUSTOM_RATE"]);

const TAX_OVERRIDE_SELECT = {
  id: true,
  taxId: true,
  overrideMode: true,
  customRate: true,
  applyOn: true,
  notes: true,
  isActive: true,
  createdAt: true,
} as const;

export async function listTaxOverrides(entityId: string, jewelryId: string) {
  assert(entityId && jewelryId, "Ids inválidos.");
  await assertEntityOwnership(entityId, jewelryId);
  return prisma.entityTaxOverride.findMany({
    where: { entityId },
    select: TAX_OVERRIDE_SELECT,
    orderBy: { createdAt: "asc" as const },
  });
}

export async function upsertTaxOverride(entityId: string, jewelryId: string, data: any) {
  assert(entityId && jewelryId, "Ids inválidos.");
  await assertEntityOwnership(entityId, jewelryId);

  const taxId = s(data?.taxId);
  assert(taxId, "taxId es obligatorio.");

  // Verify tax belongs to this tenant
  const tax = await prisma.tax.findFirst({
    where: { id: taxId, jewelryId, deletedAt: null },
    select: { id: true },
  });
  assert(tax, "Impuesto no encontrado.");

  const overrideMode = VALID_OVERRIDE_MODES.has(data?.overrideMode) ? data.overrideMode : "INHERIT";

  if (overrideMode === "CUSTOM_RATE") {
    assert(data?.customRate != null && data.customRate !== "", "customRate es obligatorio en modo CUSTOM_RATE.");
    assert(VALID_TAX_APPLY_ON.has(data?.applyOn), "applyOn es obligatorio en modo CUSTOM_RATE.");
  }

  const customRate = overrideMode === "CUSTOM_RATE" && data?.customRate != null && data.customRate !== ""
    ? String(data.customRate)
    : null;
  const applyOn = VALID_TAX_APPLY_ON.has(data?.applyOn) ? data.applyOn : null;

  return prisma.entityTaxOverride.upsert({
    where: { entityId_taxId: { entityId, taxId } },
    create: {
      entityId,
      jewelryId,
      taxId,
      overrideMode,
      customRate,
      applyOn,
      notes: s(data?.notes),
      isActive: true,
    },
    update: {
      overrideMode,
      customRate,
      applyOn,
      notes: s(data?.notes),
      isActive: true,
    },
    select: TAX_OVERRIDE_SELECT,
  });
}

export async function removeTaxOverride(entityId: string, overrideId: string, jewelryId: string) {
  assert(entityId && overrideId && jewelryId, "Ids inválidos.");
  await assertEntityOwnership(entityId, jewelryId);

  const override = await prisma.entityTaxOverride.findFirst({
    where: { id: overrideId, entityId },
    select: { id: true },
  });
  assert(override, "Override no encontrado.");

  await prisma.entityTaxOverride.delete({ where: { id: overrideId } });
  return { id: overrideId };
}

// ===========================================================================
// Avatar
// ===========================================================================
export async function updateEntityAvatar(entityId: string, jewelryId: string, url: string) {
  assert(entityId, "Id de entidad inválido.");
  assert(jewelryId, "Tenant inválido.");
  assert(url, "URL inválida.");
  await assertEntityOwnership(entityId, jewelryId);

  return prisma.commercialEntity.update({
    where: { id: entityId },
    data: { avatarUrl: url },
    select: { id: true, avatarUrl: true },
  });
}
