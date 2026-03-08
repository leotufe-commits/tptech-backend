export function roundMoney(n: any): number {
  const v = Number(n);
  if (!Number.isFinite(v)) return NaN;

  return Math.round(v * 1_000_000) / 1_000_000;
}

export function moneyMul(a: any, b: any): number {
  const x = Number(a);
  const y = Number(b);

  if (!Number.isFinite(x) || !Number.isFinite(y)) return NaN;

  return roundMoney(x * y);
}

export function moneyDiv(a: any, b: any): number {
  const x = Number(a);
  const y = Number(b);

  if (!Number.isFinite(x) || !Number.isFinite(y) || y === 0) return NaN;

  return roundMoney(x / y);
}

export function moneyAdd(a: any, b: any): number {
  const x = Number(a);
  const y = Number(b);

  if (!Number.isFinite(x) || !Number.isFinite(y)) return NaN;

  return roundMoney(x + y);
}

export function moneySub(a: any, b: any): number {
  const x = Number(a);
  const y = Number(b);

  if (!Number.isFinite(x) || !Number.isFinite(y)) return NaN;

  return roundMoney(x - y);
}