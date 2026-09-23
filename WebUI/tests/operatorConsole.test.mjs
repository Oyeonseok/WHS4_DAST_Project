import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assets, initialFindings, initialScans, projects, severityOrder, trend, unresolved } from '../src/data/operatorConsole.ts';

test('console fixture keeps asset, scan and finding relationships coherent', () => {
  const assetIds = new Set(assets.map(asset => asset.id));
  const scanIds = new Set(initialScans.map(scan => scan.id));
  const projectIds = new Set(projects.map(project => project.id));
  assert.equal(assetIds.size, assets.length);
  assert.equal(scanIds.size, initialScans.length);
  for (const asset of assets) {
    assert.ok(projectIds.has(asset.projectId));
    assert.match(asset.baseUrl, /^https:\/\/(?:[\w-]+\.)?example\.com$/);
  }
  for (const scan of initialScans) assert.ok(assetIds.has(scan.assetId));
  for (const finding of initialFindings) {
    assert.ok(assetIds.has(finding.assetId));
    assert.ok(scanIds.has(finding.scanId));
    assert.equal(initialScans.find(scan => scan.id === finding.scanId)?.assetId, finding.assetId);
    assert.ok(finding.url.startsWith(assets.find(asset => asset.id === finding.assetId).baseUrl));
    assert.match(finding.request, new RegExp(`Host: ${new URL(finding.url).host.replaceAll('.', '\\.')}`));
    assert.match(finding.request, /Authorization: Bearer \[REDACTED\]/);
    assert.match(finding.response, /session=\[REDACTED\]/);
  }
});

test('dashboard severity groups and trends derive from the same findings', () => {
  const open = initialFindings.filter(unresolved);
  const bySeverity = severityOrder.map(level => open.filter(finding => finding.severity === level).length);
  assert.equal(bySeverity.reduce((sum,count) => sum + count,0),open.length);
  assert.equal(bySeverity[0] + bySeverity[1],open.filter(finding => ['Critical','High'].includes(finding.severity)).length);
  const seven = trend(initialFindings,7);
  const thirty = trend(initialFindings,30);
  assert.equal(seven.length,7);
  assert.equal(thirty.length,10);
  assert.ok(thirty.reduce((sum,point) => sum + point.newCount,0) >= seven.reduce((sum,point) => sum + point.newCount,0));
});
