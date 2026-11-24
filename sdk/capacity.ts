/** Binary storage units. The wire representation is an integer number of bytes. */
export type QuotaUnit = 'B' | 'GB' | 'TB';
const factors: Record<QuotaUnit, bigint> = { B: 1n, GB: 1n << 30n, TB: 1n << 40n };
const precision: Record<QuotaUnit, number> = { B: 0, GB: 10, TB: 13 };
const displayUnits = ['byte', 'kilobyte', 'megabyte', 'gigabyte', 'terabyte', 'petabyte'];
const maxBytes = BigInt(Number.MAX_SAFE_INTEGER);

function checkBytes(bytes: number) {
  if (!Number.isSafeInteger(bytes) || bytes < 0) throw new RangeError('Invalid byte count');
}

export function formatBytes(locale: string, bytes: number): string {
  checkBytes(bytes);
  let value = bytes;
  let index = 0;
  while (value >= 1024 && index < displayUnits.length - 1) {
    value /= 1024;
    index++;
  }
  return new Intl.NumberFormat(locale, {
    style: 'unit', unit: displayUnits[index], unitDisplay: 'short', maximumFractionDigits: index ? 1 : 0,
  }).format(value);
}

export function defaultQuotaUnit(bytes: number): QuotaUnit {
  checkBytes(bytes);
  if (bytes >= Number(factors.TB) && bytes % Number(factors.TB) === 0) return 'TB';
  return bytes > 0 && bytes < Number(factors.GB) ? 'B' : 'GB';
}

/** Round a decimal quantity to the nearest byte using integer arithmetic. */
export function parseQuotaBytes(raw: string, unit: QuotaUnit): number | undefined {
  const text = raw.trim();
  const match = /^(\d{1,16})(?:\.(\d{1,13}))?$/u.exec(text);
  if (!match) return undefined;
  const digits = match[2] ?? '';
  if (digits.length > precision[unit]) return undefined;
  const scale = 10n ** BigInt(digits.length);
  const quantity = BigInt(match[1]) * scale + BigInt(digits || '0');
  const bytes = (quantity * factors[unit] + scale / 2n) / scale;
  if ((quantity > 0n && bytes === 0n) || bytes > maxBytes) return undefined;
  return Number(bytes);
}

/** Return the shortest rounded representation that restores the original byte count. */
export function formatQuotaInput(bytes: number, unit: QuotaUnit): string {
  checkBytes(bytes);
  const factor = factors[unit];
  for (let digits = 0; digits <= precision[unit]; digits++) {
    const scale = 10n ** BigInt(digits);
    const rounded = (BigInt(bytes) * scale + factor / 2n) / factor;
    const whole = String(rounded / scale);
    const fraction = String(rounded % scale).padStart(digits, '0').replace(/0+$/, '');
    const text = fraction ? whole + '.' + fraction : whole;
    if (parseQuotaBytes(text, unit) === bytes) return text;
  }
  throw new RangeError('Byte count could not be represented');
}
