import { assets, initialFindings, initialScans, type Asset, type Finding, type Scan } from './operatorConsole';

const PREFIX = 'aidast-console-';
function readRows<T extends { id: string }>(name: string, fallback: T[]): T[] {
  try {
    const value = localStorage.getItem(PREFIX + name);
    if (!value) return fallback;
    const parsed: unknown = JSON.parse(value);
    return Array.isArray(parsed) && parsed.every(row => row && typeof row === 'object' && typeof row.id === 'string') ? parsed as T[] : fallback;
  } catch { return fallback; }
}
export const operatorRepository = {
  assets: () => readRows<Asset>('assets',assets),
  scans: () => readRows<Scan>('scans',initialScans),
  findings: () => readRows<Finding>('findings',initialFindings),
  saveAssets: (rows: Asset[]) => localStorage.setItem(PREFIX + 'assets',JSON.stringify(rows)),
  saveScans: (rows: Scan[]) => localStorage.setItem(PREFIX + 'scans',JSON.stringify(rows)),
  saveFindings: (rows: Finding[]) => localStorage.setItem(PREFIX + 'findings',JSON.stringify(rows)),
};
