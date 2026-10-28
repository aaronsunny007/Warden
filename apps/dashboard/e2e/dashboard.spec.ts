import { expect, test } from '@playwright/test';

test('renders overview, feed, tools, pending approval and OWASP coverage', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByTestId('dashboard')).toBeVisible();

  // Overview stats from the stub gateway status.
  await expect(page.getByText('Active rules')).toBeVisible();
  await expect(page.getByText('baseline')).toBeVisible();

  // Live attack feed shows the seeded verdicts, including a block and a redact.
  const rows = page.getByTestId('verdict-row');
  await expect(rows.first()).toBeVisible();
  await expect(page.getByText('W-ARG-001')).toBeVisible();
  await expect(page.getByText(/SSRF to 169\.254\.169\.254/)).toBeVisible();

  // Tool inventory shows the quarantined poisoned tool.
  const toolRows = page.getByTestId('tool-row');
  await expect(toolRows.filter({ hasText: 'facts.random_fact' })).toContainText('quarantined');

  // A pending step-up approval is actionable.
  await expect(page.getByTestId('approval-row')).toContainText('email.send_email');
  await expect(page.getByRole('button', { name: 'Approve' })).toBeVisible();

  // OWASP coverage grid distinguishes covered from uncovered items.
  const mcp03 = page.getByTestId('owasp-item').filter({ hasText: 'MCP03' });
  await expect(mcp03).toContainText('covered');
  const mcp07 = page.getByTestId('owasp-item').filter({ hasText: 'MCP07' });
  await expect(mcp07).toContainText('none');
});

test('streams a live verdict over SSE', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByTestId('verdict-row').filter({ hasText: 'read_email' }).first()).toBeVisible({
    timeout: 10_000,
  });
});
