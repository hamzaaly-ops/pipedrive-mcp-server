import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import * as pipedrive from "pipedrive";
import { getAuthUrl, authorizeUser, createTenantApiClient, getPipedriveUserInfo } from './oauth.js';
import { upsertTenant } from './db.js';

dotenv.config();

const app = express();
app.use(cors());

const PORT = process.env.PORT || 3000;
const MCP_ENDPOINT = process.env.MCP_ENDPOINT || '/message';

function getErrorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  return String(error);
}

// -------------------------------------------------------------
// OAuth Routes (For Supabase Storage)
// -------------------------------------------------------------

app.get('/auth/login', (req, res) => {
  console.log('OAuth login initiated');
  res.redirect(getAuthUrl());
});

app.get('/auth/callback', async (req, res) => {
  const code = req.query.code as string;
  if (!code) {
    return res.status(400).send("No code provided");
  }

  try {
    const tokens = await authorizeUser(code);
    
    // Fetch user info to get the company ID
    const userInfo = await getPipedriveUserInfo(tokens.access_token);
    const companyId = userInfo.company_id;

    // Upsert tenant
    const expiresAt = new Date(Date.now() + tokens.expires_in * 1000).toISOString();
    const tenantId = await upsertTenant({
      pipedrive_company_id: companyId,
      access_token: tokens.access_token,
      refresh_token: tokens.refresh_token,
      expires_at: expiresAt
    });

    const baseUri = process.env.APP_BASE_URL || `http://localhost:${PORT}`;
    const sseUrl = `${baseUri}/sse?tenantId=${tenantId}`;

    res.send(`
      <html>
        <head>
          <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; padding: 2rem; max-width: 800px; margin: 0 auto; line-height: 1.6; background-color: #f5f7f9; }
            .card { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
            pre { background: #f0f0f0; padding: 10px; border-radius: 4px; overflow-x: auto; font-size: 1.2rem; }
            h1 { color: #00b05a; }
            .important { background-color: #ffeef0; padding: 15px; border-left: 4px solid #f23a3c; margin-top: 20px;}
          </style>
        </head>
        <body>
          <div class="card">
            <h1>Pipedrive Connected Successfully!</h1>
            <p>Your Pipedrive account has been authorized and linked to a unique session ID.</p>
            <p>To use this in Claude Desktop, open "Custom Connectors", and paste the following exact URL into the <b>Remote MCP server URL</b> box:</p>
            <pre>${sseUrl}</pre>
            <div class="important">
                <b>CRITICAL:</b> Leave the "OAuth Client ID" and "OAuth Client Secret" completely blank in Claude.<br/><br/>
                We have bypassed Anthropic's broken Native OAuth feature securely. This unique URL securely connects directly to your tenant!
            </div>
          </div>
        </body>
      </html>
    `);

  } catch (error) {
    console.error("Auth callback error:", error);
    res.status(500).send(`Authentication failed: ${getErrorMessage(error)}`);
  }
});

// -------------------------------------------------------------
// MCP Server Setup per Connection
// -------------------------------------------------------------

// Active transports
const transports = new Map<string, SSEServerTransport>();

function createServerForTenant(tenantId: string): McpServer {
  const server = new McpServer({
    name: "pipedrive-mcp-server-global",
    version: "2.0.0",
    capabilities: {
      resources: {},
      tools: {},
      prompts: {}
    }
  });

  // Helper to lazily build apis for a tenant
  async function getApis() {
    const apiClient = await createTenantApiClient(tenantId);
    return {
      dealsApi: new pipedrive.DealsApi(apiClient),
      personsApi: new pipedrive.PersonsApi(apiClient),
      organizationsApi: new pipedrive.OrganizationsApi(apiClient),
      pipelinesApi: new pipedrive.PipelinesApi(apiClient),
      itemSearchApi: new pipedrive.ItemSearchApi(apiClient),
      leadsApi: new pipedrive.LeadsApi(apiClient),
      // @ts-ignore
      notesApi: new pipedrive.NotesApi(apiClient),
      // @ts-ignore
      usersApi: new pipedrive.UsersApi(apiClient)
    };
  }

  // --- Register Tools ---
  server.tool("get-users", "Get all users/owners from Pipedrive", {}, async () => {
    try {
      const { usersApi } = await getApis();
      const response = await usersApi.getUsers();
      return { content: [{ type: "text", text: JSON.stringify({ users: response.data || [] }, null, 2) }] };
    } catch (error) {
       return { content: [{ type: "text", text: `Error: ${getErrorMessage(error)}` }], isError: true };
    }
  });

  server.tool(
    "get-deals",
    "Get deals with flexible filtering",
    {
      limit: z.number().optional().default(50)
    },
    async ({ limit }) => {
      try {
        const { dealsApi } = await getApis();
        const params: any = { limit: limit, status: 'open' };
        // @ts-ignore
        const res = await dealsApi.getDeals(params);
        return { content: [{ type: "text", text: JSON.stringify(res.data || [], null, 2) }] };
      } catch (error: any) {
        return { content: [{ type: "text", text: `Error fetching deals: ${getErrorMessage(error)}` }], isError: true };
      }
    }
  );

  return server;
}

// -------------------------------------------------------------
// MCP HTTP Routes
// -------------------------------------------------------------

app.get('/sse', async (req, res) => {
  const tenantId = req.query.tenantId as string;
  console.log(`SSE connection request received. tenantId: ${tenantId}`);
  if (!tenantId) {
    return res.status(400).send("Missing tenantId query parameter.");
  }

  const server = createServerForTenant(tenantId);
  
  const transport = new SSEServerTransport(MCP_ENDPOINT, res as any);
  transports.set(transport.sessionId, transport);
  console.log(`SSE transport created. sessionId: ${transport.sessionId}`);

  transport.onclose = () => {
    console.log(`SSE connection closed. sessionId: ${transport.sessionId}`);
    transports.delete(transport.sessionId);
  };

  try {
    await server.connect(transport);
    console.log(`MCP server connected for tenant ${tenantId}, session ${transport.sessionId}`);
  } catch (err) {
    console.error('Failed to connect MCP transport:', err);
    transports.delete(transport.sessionId);
    if (!res.headersSent) {
      res.status(500).send("Failed to connect transport");
    }
  }
});

app.post(MCP_ENDPOINT, async (req, res) => {
  const sessionId = req.query.sessionId as string;
  if (!sessionId) {
    return res.status(400).json({ error: 'Missing sessionId' });
  }

  const transport = transports.get(sessionId);
  if (!transport) {
    return res.status(404).json({ error: 'Session not found' });
  }
  
  try {
    await transport.handlePostMessage(req as any, res as any);
  } catch (e) {
    if (!res.headersSent) {
      res.status(500).json({ error: 'Internal error' });
    }
  }
});

app.listen(PORT, () => {
  console.log(`Global Pipedrive MCP Server listening on port ${PORT}`);
  console.log(`OAuth Login URL: http://localhost:${PORT}/auth/login`);
});
