import { MAX_TOOL_INPUT_ELEMENTS } from '@/mcp/mcpServer';
import { McpContext } from '@/mcp/tools/types';

import { callTool, createTestClient, getFirstText } from './mcpTestUtils';

const context: McpContext = { teamId: 'team-id', userId: 'user-id' };

// GHSA-46jr-4wx8-v453 / CVE-2026-111768: without maxToolInputElements the SDK
// validates arbitrarily many array elements / object keys per tool call and
// can be driven into heap exhaustion. The element count is checked before the
// tool's schema runs, so any registered tool exercises it.
describe('MCP tool input element limit', () => {
  it('bounds the limit well above any model-generated tool input', () => {
    expect(MAX_TOOL_INPUT_ELEMENTS).toBeGreaterThanOrEqual(10_000);
    expect(Number.isFinite(MAX_TOOL_INPUT_ELEMENTS)).toBe(true);
  });

  it('rejects a tool call whose arguments exceed the limit', async () => {
    const client = await createTestClient(context);
    const { tools } = await client.listTools();
    expect(tools.length).toBeGreaterThan(0);

    const result = await callTool(client, tools[0].name, {
      padding: new Array(MAX_TOOL_INPUT_ELEMENTS + 1).fill(0),
    });

    expect(result.isError).toBe(true);
    expect(getFirstText(result)).toContain(
      `more than the maximum of ${MAX_TOOL_INPUT_ELEMENTS} elements`,
    );
  });
});
