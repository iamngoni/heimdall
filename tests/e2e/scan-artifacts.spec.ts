import { expect, test } from '@playwright/test';
import { Client } from 'pg';
import crypto from 'node:crypto';
import fs from 'node:fs';

const password = 'E2ePassword1!';
const databaseURL = process.env.DATABASE_URL;

test.skip(!databaseURL, 'DATABASE_URL is required for Heimdall E2E tests');

let db: Client;
const usersToDelete = new Set<string>();

test.beforeAll(async () => {
  db = new Client({ connectionString: databaseURL });
  await db.connect();
});

test.afterEach(async () => {
  for (const email of usersToDelete) {
    await db.query('DELETE FROM users WHERE email = $1', [email]);
  }
  usersToDelete.clear();
});

test.afterAll(async () => {
  await db.end();
});

test('registered users can review completed scan artifacts', async ({ page }) => {
  const runId = crypto.randomUUID();
  const email = `e2e-${runId}@example.com`;
  usersToDelete.add(email);

  await page.goto('/register');
  await page.getByLabel('Display name').fill('E2E Operator');
  await page.getByLabel('Email address').fill(email);
  await page.getByLabel('Password').fill(password);
  await page.getByRole('button', { name: 'Create Account' }).click();
  await page.waitForURL('**/');
  await expect(page.locator('body')).toContainText('Heimdall');

  const userId = await lookupUserId(email);
  const scan = await seedCompletedScan(userId, runId);

  await page.goto(`/scans/${scan.scanId}`);
  await expect(page.getByRole('link', { name: 'Report' })).toBeVisible();
  await expect(page.getByRole('link', { name: 'SARIF' })).toBeVisible();
  await expect(page.getByRole('link', { name: /Findings/ }).first()).toBeVisible();

  await page.goto(`/scans/${scan.scanId}/report`);
  await expect(page.locator('body')).toContainText('Security Scan Report');
  await expect(page.locator('body')).toContainText('E2E SQL injection finding');

  await page.goto(`/scans/${scan.scanId}/findings`);
  await expect(page.locator('body')).toContainText('E2E SQL injection finding');
  await expect(page.locator('body')).toContainText('src/e2e.ts');

  await page.goto(`/scans/${scan.scanId}`);
  const [download] = await Promise.all([
    page.waitForEvent('download'),
    page.getByRole('link', { name: 'SARIF' }).click(),
  ]);
  const sarifPath = await download.path();
  expect(sarifPath).toBeTruthy();
  const sarif = JSON.parse(fs.readFileSync(sarifPath!, 'utf8'));
  expect(sarif.version).toBe('2.1.0');
  expect(sarif.runs[0].results).toHaveLength(1);
  expect(sarif.runs[0].results[0].ruleId).toBe('CWE-89');
  expect(
    sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri,
  ).toBe('src/e2e.ts');
});

async function lookupUserId(email: string): Promise<string> {
  const result = await db.query<{ id: string }>('SELECT id FROM users WHERE email = $1', [email]);
  expect(result.rowCount).toBe(1);
  return result.rows[0].id;
}

async function seedCompletedScan(userId: string, runId: string) {
  const repoId = crypto.randomUUID();
  const scanId = crypto.randomUUID();
  const findingId = crypto.randomUUID();
  const patchId = crypto.randomUUID();
  const repoName = `e2e-repo-${runId}`;

  await db.query(
    `INSERT INTO repos (
       id, user_id, name, source_type, remote_url, default_branch, last_commit_sha
     ) VALUES ($1, $2, $3, 'git_url', $4, 'main', $5)`,
    [repoId, userId, repoName, `https://example.com/${repoName}.git`, runId],
  );

  await db.query(
    `INSERT INTO scans (
       id, repo_id, scan_type, status, commit_sha, triggered_by, finding_count,
       critical_count, high_count, medium_count, low_count, started_at, completed_at
     ) VALUES (
       $1, $2, 'full', 'completed', $3, $4, 1, 0, 1, 0, 0, now(), now()
     )`,
    [scanId, repoId, runId, userId],
  );

  await db.query(
    `INSERT INTO findings (
       id, scan_id, repo_id, source, status, severity, confidence, title,
       description, cwe_id, file_path, line_start, line_end, code_snippet,
       suggested_patch, fix_type, fix_summary, fingerprint
     ) VALUES (
       $1, $2, $3, 'static_analysis', 'open', 'high', 'high', $4,
       $5, 'CWE-89', 'src/e2e.ts', 12, 13, $6, $7, 'code_change', $8, $9
     )`,
    [
      findingId,
      scanId,
      repoId,
      'E2E SQL injection finding',
      'Untrusted request input reaches a SQL query without parameter binding.',
      "db.query(`SELECT * FROM users WHERE id = ${req.query.id}`);",
      '@@ -1 +1 @@\n-db.query(`SELECT * FROM users WHERE id = ${req.query.id}`);\n+db.query("SELECT * FROM users WHERE id = $1", [req.query.id]);',
      'Use a parameterized query instead of string interpolation.',
      `e2e-${runId}`,
    ],
  );

  await db.query(
    `INSERT INTO patches (
       id, finding_id, scan_id, diff_content, description, applies_cleanly
     ) VALUES ($1, $2, $3, $4, $5, true)`,
    [
      patchId,
      findingId,
      scanId,
      '@@ -1 +1 @@\n-db.query(`SELECT * FROM users WHERE id = ${req.query.id}`);\n+db.query("SELECT * FROM users WHERE id = $1", [req.query.id]);',
      'Parameterize the SQL query',
    ],
  );

  return { repoId, scanId, findingId };
}
