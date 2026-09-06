import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

/** Case-insensitive "does any of this text match the search box" test. */
export function matchesQuery(query: string, ...terms: (string | undefined)[]): boolean {
  const needle = query.trim().toLowerCase();
  if (!needle) return true;
  return terms.some((term) => term?.toLowerCase().includes(needle));
}

export function plural(count: number, one: string, many = `${one}s`): string {
  return Math.abs(count) === 1 ? one : many;
}
