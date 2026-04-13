import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { z } from "zod";
import * as pipedrive from "pipedrive";
import * as dotenv from 'dotenv';
import Bottleneck from 'bottleneck';
import jwt from 'jsonwebtoken';
import http from 'http';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import type { RequestHandlerExtra } from "@modelcontextprotocol/sdk/shared/protocol.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

// Type for error handling
interface ErrorWithMessage {
  message: string;
}

function isErrorWithMessage(error: unknown): error is ErrorWithMessage {
  return (
    typeof error === 'object' &&
    error !== null &&
    'message' in error &&
    typeof (error as Record<string, unknown>).message === 'string'
  );
}

function getErrorMessage(error: unknown): string {
  if (isErrorWithMessage(error)) {
    return error.message;
  }
  return String(error);
}

// Load environment variables
dotenv.config();

const jwtSecret = process.env.MCP_JWT_SECRET;
const jwtAlgorithm = (process.env.MCP_JWT_ALGORITHM || 'HS256') as jwt.Algorithm;
const jwtVerifyOptions = {
  algorithms: [jwtAlgorithm],
  audience: process.env.MCP_JWT_AUDIENCE,
  issuer: process.env.MCP_JWT_ISSUER,
};

if (jwtSecret) {
  const bootToken = process.env.MCP_JWT_TOKEN;
  if (!bootToken) {
    console.error("ERROR: MCP_JWT_TOKEN environment variable is required when MCP_JWT_SECRET is set");
    process.exit(1);
  }

  try {
    jwt.verify(bootToken, jwtSecret, jwtVerifyOptions);
  } catch (error) {
    console.error("ERROR: Failed to verify MCP_JWT_TOKEN", error);
    process.exit(1);
  }
}

const verifyRequestAuthentication = (req: http.IncomingMessage) => {
  if (!jwtSecret) {
    return { ok: true } as const;
  }

  const header = req.headers['authorization'];
  if (!header) {
    return { ok: false, status: 401, message: 'Missing Authorization header' } as const;
  }

  const [scheme, token] = header.split(' ');
  if (scheme !== 'Bearer' || !token) {
    return { ok: false, status: 401, message: 'Invalid Authorization header format' } as const;
  }

  try {
    jwt.verify(token, jwtSecret, jwtVerifyOptions);
    return { ok: true } as const;
  } catch (error) {
    return { ok: false, status: 401, message: 'Invalid or expired token' } as const;
  }
};

const limiter = new Bottleneck({
  minTime: Number(process.env.PIPEDRIVE_RATE_LIMIT_MIN_TIME_MS || 250),
  maxConcurrent: Number(process.env.PIPEDRIVE_RATE_LIMIT_MAX_CONCURRENT || 2),
});

const withRateLimit = <T extends object>(client: T): T => {
  return new Proxy(client, {
    get(target, prop, receiver) {
      const value = Reflect.get(target, prop, receiver);
      if (typeof value === 'function') {
        return (...args: unknown[]) => limiter.schedule(() => (value as Function).apply(target, args));
      }
      return value;
    },
  });
};

type ApiKeyCredentials = {
  type: "apiKey";
  apiToken: string;
  domain: string;
};

type OAuthCredentials = {
  type: "oauth";
  accessToken: string;
  refreshToken?: string;
  expiresAt?: number;
  domain: string;
};

type PipedriveCredentials = ApiKeyCredentials | OAuthCredentials;

const DEFAULT_SESSION_KEY = "stdio";

const normalizeDomain = (domain: string) =>
  domain.replace(/^https?:\/\//i, "").replace(/\/+$/, "");

const defaultPipedriveCredentials: PipedriveCredentials | undefined =
  process.env.PIPEDRIVE_API_TOKEN && process.env.PIPEDRIVE_DOMAIN
    ? {
        type: "apiKey",
        apiToken: process.env.PIPEDRIVE_API_TOKEN,
        domain: normalizeDomain(process.env.PIPEDRIVE_DOMAIN),
      }
    : undefined;

if (!defaultPipedriveCredentials) {
  console.warn(
    "No default Pipedrive credentials configured; each session must authorize before calling the tools."
  );
}

const STORAGE_DIR = path.resolve(process.cwd(), "storage");
const TENANT_STORE_FILE = path.join(STORAGE_DIR, "tenant-credentials.json");

const ensureStorageDirectory = () => {
  if (!fs.existsSync(STORAGE_DIR)) {
    fs.mkdirSync(STORAGE_DIR, { recursive: true });
  }
};

type StoredTenantCredentials = {
  type: "apiKey";
  apiToken: string;
  domain: string;
} | {
  type: "oauth";
  accessToken: string;
  refreshToken?: string;
  expiresAt?: number;
  domain: string;
};

const tenantCredentialStore = new Map<string, PipedriveCredentials>();

const persistTenantCredentials = () => {
  ensureStorageDirectory();
  const payload: Record<string, StoredTenantCredentials> = {};
  for (const [tenantId, credentials] of tenantCredentialStore.entries()) {
    payload[tenantId] = { ...credentials } as StoredTenantCredentials;
  }
  fs.writeFileSync(TENANT_STORE_FILE, JSON.stringify(payload, null, 2), "utf-8");
};

const loadTenantCredentials = () => {
  if (!fs.existsSync(TENANT_STORE_FILE)) {
    return;
  }
  try {
    const contents = fs.readFileSync(TENANT_STORE_FILE, "utf-8");
    const parsed: Record<string, StoredTenantCredentials> = JSON.parse(contents);
    for (const [tenantId, creds] of Object.entries(parsed)) {
      tenantCredentialStore.set(tenantId, creds);
    }
  } catch (error) {
    console.error("Failed to load tenant credentials:", error);
  }
};

loadTenantCredentials();

const sessionTenantMap = new Map<string, string>();

const setTenantForSession = (sessionKey: string, tenantId: string) => {
  if (tenantId) {
    sessionTenantMap.set(sessionKey, tenantId);
  }
};

const getTenantForSession = (sessionKey: string) => sessionTenantMap.get(sessionKey);

const clearTenantForSession = (sessionKey: string) => sessionTenantMap.delete(sessionKey);

const getSessionKey = (extra?: RequestHandlerExtra) =>
  extra?.sessionId ?? DEFAULT_SESSION_KEY;

const resolveTenantId = (extra?: RequestHandlerExtra, providedTenant?: string) => {
  if (providedTenant) {
    return providedTenant;
  }
  const sessionKey = getSessionKey(extra);
  return getTenantForSession(sessionKey) ?? sessionKey;
};

const storeTenantCredentials = (
  tenantId: string,
  credentials: PipedriveCredentials
) => {
  tenantCredentialStore.set(tenantId, credentials);
  persistTenantCredentials();
  return tenantId;
};

const getCredentialsForSession = (extra?: RequestHandlerExtra) => {
  const sessionKey = getSessionKey(extra);
  const tenantId = getTenantForSession(sessionKey);
  if (tenantId && tenantCredentialStore.has(tenantId)) {
    return tenantCredentialStore.get(tenantId);
  }
  return defaultPipedriveCredentials;
};

type PipedriveClients = {
  dealsApi: pipedrive.DealsApi;
  personsApi: pipedrive.PersonsApi;
  organizationsApi: pipedrive.OrganizationsApi;
  pipelinesApi: pipedrive.PipelinesApi;
  itemSearchApi: pipedrive.ItemSearchApi;
  leadsApi: pipedrive.LeadsApi;
  activitiesApi: pipedrive.ActivitiesApi;
  notesApi: pipedrive.NotesApi;
  usersApi: pipedrive.UsersApi;
};

const createPipedriveClients = (
  credentials: PipedriveCredentials,
  onTokenUpdate?: (updated: OAuthCredentials) => void
): PipedriveClients => {
  const normalizedDomain = normalizeDomain(credentials.domain);

  if (!normalizedDomain) {
    throw new Error("Invalid Pipedrive domain. Provide a value like 'example.pipedrive.com'.");
  }

  const apiClient = new pipedrive.ApiClient();
  apiClient.basePath = `https://${normalizedDomain}/api/v1`;
  apiClient.authentications = apiClient.authentications || {};

  if (credentials.type === "apiKey") {
    apiClient.authentications["api_key"] = {
      type: "apiKey",
      in: "query",
      name: "api_token",
      apiKey: credentials.apiToken,
    };
  } else {
    apiClient.authentications["oauth2"] = {
      type: "oauth2",
      accessToken: credentials.accessToken,
      refreshToken: credentials.refreshToken,
      expiresAt: credentials.expiresAt,
      tokenUpdateCallback: (token: any) => {
        const updated: OAuthCredentials = {
          type: "oauth",
          domain: credentials.domain,
          accessToken: token.access_token ?? credentials.accessToken,
          refreshToken: token.refresh_token ?? credentials.refreshToken,
          expiresAt: token.expires_in ? Date.now() + token.expires_in * 1000 : credentials.expiresAt,
        };

        onTokenUpdate?.(updated);
      },
    };
  }

  return {
    dealsApi: withRateLimit(new pipedrive.DealsApi(apiClient)),
    personsApi: withRateLimit(new pipedrive.PersonsApi(apiClient)),
    organizationsApi: withRateLimit(new pipedrive.OrganizationsApi(apiClient)),
    pipelinesApi: withRateLimit(new pipedrive.PipelinesApi(apiClient)),
    itemSearchApi: withRateLimit(new pipedrive.ItemSearchApi(apiClient)),
    leadsApi: withRateLimit(new pipedrive.LeadsApi(apiClient)),
    activitiesApi: withRateLimit(new pipedrive.ActivitiesApi(apiClient)),
    notesApi: withRateLimit(new pipedrive.NotesApi(apiClient)),
    usersApi: withRateLimit(new pipedrive.UsersApi(apiClient)),
  };
};

const getPipedriveClients = (extra?: RequestHandlerExtra) => {
  const credentials = getCredentialsForSession(extra);
  if (!credentials) {
    return null;
  }

  const onTokenUpdate =
    credentials.type === "oauth"
      ? (updated: OAuthCredentials) => {
          const sessionKey = getSessionKey(extra);
          const tenantId = getTenantForSession(sessionKey);
          if (tenantId) {
            storeTenantCredentials(tenantId, updated);
          }
        }
      : undefined;

  return createPipedriveClients(credentials, onTokenUpdate);
};

const textContent = (text: string): CallToolResult["content"] =>
  [
    {
      type: "text" as const,
      text,
    },
  ] as const;

const buildTextResult = (text: string, isError = false): CallToolResult => {
  const payload: CallToolResult = {
    content: textContent(text),
  };

  return isError ? { ...payload, isError: true } : payload;
};

const missingCredentialsResponse = () =>
  buildTextResult(
    `No Pipedrive credentials configured for this session. Run "get-pipedrive-oauth-url" or "authorize-pipedrive" to provide credentials.`,
    true
  );

const OAUTH_HOST_DEFAULT = "https://oauth.pipedrive.com";
const oauthClientId = process.env.PIPEDRIVE_OAUTH_CLIENT_ID;
const oauthClientSecret = process.env.PIPEDRIVE_OAUTH_CLIENT_SECRET;
const oauthRedirectUri = process.env.PIPEDRIVE_OAUTH_REDIRECT_URI;
const oauthHostEnv = process.env.PIPEDRIVE_OAUTH_HOST || OAUTH_HOST_DEFAULT;
const oauthScopes = process.env.PIPEDRIVE_OAUTH_SCOPES;
const OAUTH_CONFIG_FILE = path.join(STORAGE_DIR, "oauth-config.json");
const oauthStateStore = new Map<string, { sessionKey: string; tenantId?: string }>();

type OAuthConfig = {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  host?: string;
  scopes?: string;
};

let oauthConfig: OAuthConfig | undefined;

const loadOAuthConfig = () => {
  if (!fs.existsSync(OAUTH_CONFIG_FILE)) {
    return;
  }
  try {
    const contents = fs.readFileSync(OAUTH_CONFIG_FILE, "utf-8");
    oauthConfig = JSON.parse(contents);
  } catch (error) {
    console.error("Failed to load OAuth config:", error);
  }
};

const persistOAuthConfig = (config: OAuthConfig) => {
  ensureStorageDirectory();
  fs.writeFileSync(OAUTH_CONFIG_FILE, JSON.stringify(config, null, 2), "utf-8");
  oauthConfig = config;
};

const getOAuthConfig = (): OAuthConfig | undefined => {
  if (oauthConfig) {
    return oauthConfig;
  }
  if (oauthClientId && oauthClientSecret && oauthRedirectUri) {
    const config: OAuthConfig = {
      clientId: oauthClientId,
      clientSecret: oauthClientSecret,
      redirectUri: oauthRedirectUri,
      host: oauthHostEnv !== OAUTH_HOST_DEFAULT ? oauthHostEnv : undefined,
      scopes: oauthScopes,
    };
    persistOAuthConfig(config);
    return config;
  }
  return undefined;
};

loadOAuthConfig();

const isOAuthConfigured = () => Boolean(getOAuthConfig());

const createOAuthApiClient = () => {
  const config = getOAuthConfig();
  if (!config) {
    throw new Error("OAuth configuration is missing");
  }

  const oauthClient = new pipedrive.ApiClient();
  oauthClient.authentications = oauthClient.authentications || {};
  oauthClient.authentications.oauth2 = {
    type: "oauth2",
    host: config.host ?? OAUTH_HOST_DEFAULT,
    clientId: config.clientId,
    clientSecret: config.clientSecret,
    redirectUri: config.redirectUri,
  };
  return oauthClient;
};

const buildOAuthAuthorizationUrl = (state: string) => {
  const config = getOAuthConfig();
  if (!config) {
    throw new Error("OAuth configuration is missing");
  }

  const oauthClient = createOAuthApiClient();
  const url = new URL(oauthClient.buildAuthorizationUrl());
  url.searchParams.set("state", state);
  url.searchParams.set("response_type", "code");
  const scopes = config.scopes ?? oauthScopes;
  if (scopes) {
    url.searchParams.set("scope", scopes);
  }
  return url.toString();
};

const registerOAuthState = (sessionKey: string, tenantId?: string) => {
  const state = crypto.randomUUID();
  oauthStateStore.set(state, { sessionKey, tenantId });
  return state;
};

const consumeOAuthState = (state: string) => {
  const payload = oauthStateStore.get(state);
  oauthStateStore.delete(state);
  return payload;
};

// Create MCP server
const server = new McpServer({
  name: "pipedrive-mcp-server",
  version: "1.0.2",
  capabilities: {
    resources: {},
    tools: {},
    prompts: {}
  }
});

// === TOOLS ===

// Allow connectors to register their own Pipedrive credentials.
server.tool(
  "authorize-pipedrive",
  "Store Pipedrive API token and domain for this session",
  {
    apiToken: z.string().min(1).describe("Pipedrive API token"),
    domain: z.string().min(1).describe("Pipedrive domain (e.g., 'example.pipedrive.com')"),
    tenantId: z.string().min(1).optional().describe("Optional tenant identifier for your customer"),
  },
  async ({ apiToken, domain, tenantId }, extra) => {
    const normalizedDomain = normalizeDomain(domain);
    if (!normalizedDomain) {
      return buildTextResult(
        "Provide a valid Pipedrive domain such as 'example.pipedrive.com'.",
        true
      );
    }

    const tenantKey = resolveTenantId(extra, tenantId?.trim());
    setTenantForSession(getSessionKey(extra), tenantKey);

    const storedTenant = storeTenantCredentials(tenantKey, {
      type: "apiKey",
      apiToken,
      domain: normalizedDomain,
    });

    return buildTextResult(`Stored credentials for tenant ${storedTenant}.`);
  }
);

server.tool(
  "get-pipedrive-oauth-url",
  "Get a one-time URL to authorize your Pipedrive account via OAuth",
  {
    tenantId: z.string().min(1).optional().describe("Optional stable tenant identifier (e.g., your customer slug)"),
  },
  async ({ tenantId }, extra) => {
    if (!isOAuthConfigured()) {
      return buildTextResult(
        "OAuth is not configured on this server. Set PIPEDRIVE_OAUTH_CLIENT_ID/SECRET/REDIRECT_URI.",
        true
      );
    }

    const sessionKey = getSessionKey(extra);
    const tenantKey = resolveTenantId(extra, tenantId?.trim());
    setTenantForSession(sessionKey, tenantKey);

    const state = registerOAuthState(sessionKey, tenantKey);
    const authUrl = buildOAuthAuthorizationUrl(state);

    return buildTextResult(
      `Open this URL in your browser to authorize your Pipedrive account:\n${authUrl}`
    );
  }
);

server.tool(
  "set-pipedrive-oauth-config",
  "Persist OAuth client credentials (client_id, secret, redirect URI)",
  {
    clientId: z.string().min(1).describe("Pipedrive OAuth client ID"),
    clientSecret: z.string().min(1).describe("Pipedrive OAuth client secret"),
    redirectUri: z.string().min(1).describe("OAuth redirect URI (https://...)"),
    host: z.string().optional().describe("OAuth host (default: https://oauth.pipedrive.com)"),
    scopes: z.string().optional().describe("Comma-separated scopes (e.g., read,write)"),
  },
  async ({ clientId, clientSecret, redirectUri, host, scopes }) => {
    persistOAuthConfig({
      clientId,
      clientSecret,
      redirectUri,
      host: host?.trim() || undefined,
      scopes: scopes?.trim() || undefined,
    });

    return buildTextResult("OAuth client configuration stored.");
  }
);

server.tool(
  "clear-pipedrive-authorization",
  "Remove stored Pipedrive credentials for this session or tenant",
  {
    tenantId: z.string().min(1).optional().describe("Tenant identifier whose credentials should be cleared"),
  },
  async ({ tenantId }, extra) => {
    const sessionKey = getSessionKey(extra);
    const targetTenantId = tenantId?.trim() || getTenantForSession(sessionKey);

    if (!targetTenantId) {
      return buildTextResult(
        "No tenant identifier found for this session. Provide tenantId or call authorize first.",
        true
      );
    }

    const removed = tenantCredentialStore.delete(targetTenantId);
    if (removed) {
      persistTenantCredentials();
      clearTenantForSession(sessionKey);
    }

    const message = removed
      ? `Cleared stored credentials for tenant ${targetTenantId}.`
      : `No stored credentials found for tenant ${targetTenantId}.`;

    return buildTextResult(message);
  }
);

// Get all users (for finding owner IDs)
server.tool(
  "get-users",
  "Get all users/owners from Pipedrive to identify owner IDs for filtering deals",
  {},
  async (_, extra) => {
    const clients = getPipedriveClients(extra);
    if (!clients) {
      return missingCredentialsResponse();
    }

    const { usersApi } = clients;

    try {
      const response = await usersApi.getUsers();
      const users = response.data?.map((user: any) => ({
        id: user.id,
        name: user.name,
        email: user.email,
        active_flag: user.active_flag,
        role_name: user.role_name
      })) || [];

      return buildTextResult(
        JSON.stringify(
          {
            summary: `Found ${users.length} users in your Pipedrive account`,
            users,
          },
          null,
          2
        )
      );
    } catch (error) {
      console.error("Error fetching users:", error);
      return buildTextResult(`Error fetching users: ${getErrorMessage(error)}`, true);
    }
  }
);

// Get deals with flexible filtering options
server.tool(
  "get-deals",
  "Get deals from Pipedrive with flexible filtering options including search by title, date range, owner, stage, status, and more. Use 'get-users' tool first to find owner IDs.",
  {
    searchTitle: z.string().optional().describe("Search deals by title/name (partial matches supported)"),
    daysBack: z.number().optional().describe("Number of days back to fetch deals based on last activity date (default: 365)"),
    ownerId: z.number().optional().describe("Filter deals by owner/user ID (use get-users tool to find IDs)"),
    stageId: z.number().optional().describe("Filter deals by stage ID"),
    status: z.enum(['open', 'won', 'lost', 'deleted']).optional().describe("Filter deals by status (default: open)"),
    pipelineId: z.number().optional().describe("Filter deals by pipeline ID"),
    minValue: z.number().optional().describe("Minimum deal value filter"),
    maxValue: z.number().optional().describe("Maximum deal value filter"),
    limit: z.number().optional().describe("Maximum number of deals to return (default: 500)")
  },
  async ({
    searchTitle,
    daysBack = 365,
    ownerId,
    stageId,
    status = 'open',
    pipelineId,
    minValue,
    maxValue,
    limit = 500
  }, extra) => {
    const clients = getPipedriveClients(extra);
    if (!clients) {
      return missingCredentialsResponse();
    }

    const { dealsApi } = clients;

    try {
      let filteredDeals: any[] = [];

      // If searching by title, use the search API first
      if (searchTitle) {
        // @ts-ignore - Bypass incorrect TypeScript definition
        const searchResponse = await dealsApi.searchDeals(searchTitle);
        filteredDeals = searchResponse.data || [];
      } else {
        // Calculate the date filter (daysBack days ago)
        const filterDate = new Date();
        filterDate.setDate(filterDate.getDate() - daysBack);
        const startDate = filterDate.toISOString().split('T')[0]; // Format as YYYY-MM-DD

        // Build API parameters (using actual Pipedrive API parameter names)
        const params: any = {
          sort: 'last_activity_date DESC',
          status: status,
          limit: limit
        };

        // Add optional filters
        if (ownerId) params.user_id = ownerId;
        if (stageId) params.stage_id = stageId;
        if (pipelineId) params.pipeline_id = pipelineId;

        // Fetch deals with filters
        // @ts-ignore - getDeals accepts parameters but types may be incomplete
        const response = await dealsApi.getDeals(params);
        filteredDeals = response.data || [];
      }

      // Apply additional client-side filtering

      // Filter by date if not searching by title
      if (!searchTitle) {
        const filterDate = new Date();
        filterDate.setDate(filterDate.getDate() - daysBack);

        filteredDeals = filteredDeals.filter((deal: any) => {
          if (!deal.last_activity_date) return false;
          const dealActivityDate = new Date(deal.last_activity_date);
          return dealActivityDate >= filterDate;
        });
      }

      // Filter by owner if specified and not already applied in API call
      if (ownerId && searchTitle) {
        filteredDeals = filteredDeals.filter((deal: any) => deal.owner_id === ownerId);
      }

      // Filter by status if specified and searching by title
      if (status && searchTitle) {
        filteredDeals = filteredDeals.filter((deal: any) => deal.status === status);
      }

      // Filter by stage if specified and not already applied in API call
      if (stageId && (searchTitle || !stageId)) {
        filteredDeals = filteredDeals.filter((deal: any) => deal.stage_id === stageId);
      }

      // Filter by pipeline if specified and not already applied in API call
      if (pipelineId && (searchTitle || !pipelineId)) {
        filteredDeals = filteredDeals.filter((deal: any) => deal.pipeline_id === pipelineId);
      }

      // Filter by value range if specified
      if (minValue !== undefined || maxValue !== undefined) {
        filteredDeals = filteredDeals.filter((deal: any) => {
          const value = parseFloat(deal.value) || 0;
          if (minValue !== undefined && value < minValue) return false;
          if (maxValue !== undefined && value > maxValue) return false;
          return true;
        });
      }

      // Apply limit
      if (filteredDeals.length > limit) {
        filteredDeals = filteredDeals.slice(0, limit);
      }

      // Build filter summary for response
      const filterSummary = {
        ...(searchTitle && { search_title: searchTitle }),
        ...(!searchTitle && { days_back: daysBack }),
        ...(!searchTitle && { filter_date: new Date(Date.now() - daysBack * 24 * 60 * 60 * 1000).toISOString().split('T')[0] }),
        status: status,
        ...(ownerId && { owner_id: ownerId }),
        ...(stageId && { stage_id: stageId }),
        ...(pipelineId && { pipeline_id: pipelineId }),
        ...(minValue !== undefined && { min_value: minValue }),
        ...(maxValue !== undefined && { max_value: maxValue }),
        total_deals_found: filteredDeals.length,
        limit_applied: limit
      };

      // Summarize deals to avoid massive responses but include notes and booking details
      const bookingFieldKey = "8f4b27fbd9dfc70d2296f23ce76987051ad7324e";
      const summarizedDeals = filteredDeals.map((deal: any) => ({
        id: deal.id,
        title: deal.title,
        value: deal.value,
        currency: deal.currency,
        status: deal.status,
        stage_name: deal.stage?.name || 'Unknown',
        pipeline_name: deal.pipeline?.name || 'Unknown',
        owner_name: deal.owner?.name || 'Unknown',
        organization_name: deal.org?.name || null,
        person_name: deal.person?.name || null,
        add_time: deal.add_time,
        last_activity_date: deal.last_activity_date,
        close_time: deal.close_time,
        won_time: deal.won_time,
        lost_time: deal.lost_time,
        notes_count: deal.notes_count || 0,
        // Include recent notes if available
        notes: deal.notes || [],
        // Include custom booking details field
        booking_details: deal[bookingFieldKey] || null
      }));

      return buildTextResult(
        JSON.stringify(
          {
            summary: searchTitle
              ? `Found ${filteredDeals.length} deals matching title search "${searchTitle}"`
              : `Found ${filteredDeals.length} deals matching the specified filters`,
            filters_applied: filterSummary,
            total_found: filteredDeals.length,
            deals: summarizedDeals.slice(0, 30), // Limit to 30 deals max to prevent huge responses
          },
          null,
          2
        )
      );
    } catch (error) {
      console.error("Error fetching deals:", error);
      return buildTextResult(`Error fetching deals: ${getErrorMessage(error)}`, true);
    }
  }
);

// Get deal by ID
server.tool(
  "get-deal",
  "Get a specific deal by ID including custom fields",
  {
    dealId: z.number().describe("Pipedrive deal ID")
  },
  async ({ dealId }, extra) => {
    const clients = getPipedriveClients(extra);
    if (!clients) {
      return missingCredentialsResponse();
    }

    const { dealsApi } = clients;

    try {
      // @ts-ignore - Bypass incorrect TypeScript definition, API expects just the ID
      const response = await dealsApi.getDeal(dealId);
      return buildTextResult(JSON.stringify(response.data, null, 2));
    } catch (error) {
      console.error(`Error fetching deal ${dealId}:`, error);
      return buildTextResult(
        `Error fetching deal ${dealId}: ${getErrorMessage(error)}`,
        true
      );
    }
  }
);

// Get deal notes and custom booking details
server.tool(
  "get-deal-notes",
  "Get detailed notes and custom booking details for a specific deal",
  {
    dealId: z.number().describe("Pipedrive deal ID"),
    limit: z.number().optional().describe("Maximum number of notes to return (default: 20)")
  },
  async ({ dealId, limit = 20 }, extra) => {
    const clients = getPipedriveClients(extra);
    if (!clients) {
      return missingCredentialsResponse();
    }

    const { dealsApi, notesApi } = clients;

    try {
      const result: any = {
        deal_id: dealId,
        notes: [],
        booking_details: null
      };

      // Get deal details including custom fields
      try {
        // @ts-ignore - Bypass incorrect TypeScript definition
        const dealResponse = await dealsApi.getDeal(dealId);
        const deal = dealResponse.data;

        // Extract custom booking field
        const bookingFieldKey = "8f4b27fbd9dfc70d2296f23ce76987051ad7324e";
        if (deal && deal[bookingFieldKey]) {
          result.booking_details = deal[bookingFieldKey];
        }
      } catch (dealError) {
        console.error(`Error fetching deal details for ${dealId}:`, dealError);
        result.deal_error = getErrorMessage(dealError);
      }

      // Get deal notes
      try {
        // @ts-ignore - API parameters may not be fully typed
        // @ts-ignore - Bypass incorrect TypeScript definition
        const notesResponse = await notesApi.getNotes({
          deal_id: dealId,
          limit: limit
        });
        result.notes = notesResponse.data || [];
      } catch (noteError) {
        console.error(`Error fetching notes for deal ${dealId}:`, noteError);
        result.notes_error = getErrorMessage(noteError);
      }

      return buildTextResult(
        JSON.stringify(
          {
            summary: `Retrieved ${result.notes.length} notes and booking details for deal ${dealId}`,
            ...result,
          },
          null,
          2
        )
      );
    } catch (error) {
      console.error(`Error fetching deal notes ${dealId}:`, error);
      return buildTextResult(
        `Error fetching deal notes ${dealId}: ${getErrorMessage(error)}`,
        true
      );
    }
  }
);

// Search deals
server.tool(
  "search-deals",
  "Search deals by term",
  {
    term: z.string().describe("Search term for deals")
  },
  async ({ term }, extra) => {
    const clients = getPipedriveClients(extra);
    if (!clients) {
      return missingCredentialsResponse();
    }

    const { dealsApi } = clients;

    try {
      // @ts-ignore - Bypass incorrect TypeScript definition
      const response = await dealsApi.searchDeals(term);
      return buildTextResult(JSON.stringify(response.data, null, 2));
    } catch (error) {
      console.error(`Error searching deals with term "${term}":`, error);
      return buildTextResult(
        `Error searching deals: ${getErrorMessage(error)}`,
        true
      );
    }
  }
);

// Get all persons
server.tool(
  "get-persons",
  "Get all persons from Pipedrive including custom fields",
  {},
  async (_, extra) => {
    const clients = getPipedriveClients(extra);
    if (!clients) {
      return missingCredentialsResponse();
    }

    const { personsApi } = clients;

    try {
      const response = await personsApi.getPersons();
      return buildTextResult(JSON.stringify(response.data, null, 2));
    } catch (error) {
      console.error("Error fetching persons:", error);
      return buildTextResult(
        `Error fetching persons: ${getErrorMessage(error)}`,
        true
      );
    }
  }
);

// Get person by ID
server.tool(
  "get-person",
  "Get a specific person by ID including custom fields",
  {
    personId: z.number().describe("Pipedrive person ID")
  },
  async ({ personId }, extra) => {
    const clients = getPipedriveClients(extra);
    if (!clients) {
      return missingCredentialsResponse();
    }

    const { personsApi } = clients;

    try {
      // @ts-ignore - Bypass incorrect TypeScript definition
      const response = await personsApi.getPerson(personId);
      return buildTextResult(JSON.stringify(response.data, null, 2));
    } catch (error) {
      console.error(`Error fetching person ${personId}:`, error);
      return buildTextResult(
        `Error fetching person ${personId}: ${getErrorMessage(error)}`,
        true
      );
    }
  }
);

// Search persons
server.tool(
  "search-persons",
  "Search persons by term",
  {
    term: z.string().describe("Search term for persons")
  },
  async ({ term }, extra) => {
    const clients = getPipedriveClients(extra);
    if (!clients) {
      return missingCredentialsResponse();
    }

    const { personsApi } = clients;

    try {
      // @ts-ignore - Bypass incorrect TypeScript definition
      const response = await personsApi.searchPersons(term);
      return buildTextResult(JSON.stringify(response.data, null, 2));
    } catch (error) {
      console.error(`Error searching persons with term "${term}":`, error);
      return buildTextResult(
        `Error searching persons: ${getErrorMessage(error)}`,
        true
      );
    }
  }
);

// Get all organizations
server.tool(
  "get-organizations",
  "Get all organizations from Pipedrive including custom fields",
  {},
  async (_, extra) => {
    const clients = getPipedriveClients(extra);
    if (!clients) {
      return missingCredentialsResponse();
    }

    const { organizationsApi } = clients;

    try {
      const response = await organizationsApi.getOrganizations();
      return buildTextResult(JSON.stringify(response.data, null, 2));
    } catch (error) {
      console.error("Error fetching organizations:", error);
      return buildTextResult(
        `Error fetching organizations: ${getErrorMessage(error)}`,
        true
      );
    }
  }
);

// Get organization by ID
server.tool(
  "get-organization",
  "Get a specific organization by ID including custom fields",
  {
    organizationId: z.number().describe("Pipedrive organization ID")
  },
  async ({ organizationId }, extra) => {
    const clients = getPipedriveClients(extra);
    if (!clients) {
      return missingCredentialsResponse();
    }

    const { organizationsApi } = clients;

    try {
      // @ts-ignore - Bypass incorrect TypeScript definition
      const response = await organizationsApi.getOrganization(organizationId);
      return buildTextResult(JSON.stringify(response.data, null, 2));
    } catch (error) {
      console.error(`Error fetching organization ${organizationId}:`, error);
      return buildTextResult(
        `Error fetching organization ${organizationId}: ${getErrorMessage(error)}`,
        true
      );
    }
  }
);

// Search organizations
server.tool(
  "search-organizations",
  "Search organizations by term",
  {
    term: z.string().describe("Search term for organizations")
  },
  async ({ term }, extra) => {
    const clients = getPipedriveClients(extra);
    if (!clients) {
      return missingCredentialsResponse();
    }

    const { organizationsApi } = clients;

    try {
      // @ts-ignore - API method exists but TypeScript definition is wrong
      const response = await (organizationsApi as any).searchOrganization({ term });
      return buildTextResult(JSON.stringify(response.data, null, 2));
    } catch (error) {
      console.error(`Error searching organizations with term "${term}":`, error);
      return buildTextResult(
        `Error searching organizations: ${getErrorMessage(error)}`,
        true
      );
    }
  }
);

// Get all pipelines
server.tool(
  "get-pipelines",
  "Get all pipelines from Pipedrive",
  {},
  async (_, extra) => {
    const clients = getPipedriveClients(extra);
    if (!clients) {
      return missingCredentialsResponse();
    }

    const { pipelinesApi } = clients;

    try {
      const response = await pipelinesApi.getPipelines();
      return buildTextResult(JSON.stringify(response.data, null, 2));
    } catch (error) {
      console.error("Error fetching pipelines:", error);
      return buildTextResult(
        `Error fetching pipelines: ${getErrorMessage(error)}`,
        true
      );
    }
  }
);

// Get pipeline by ID
server.tool(
  "get-pipeline",
  "Get a specific pipeline by ID",
  {
    pipelineId: z.number().describe("Pipedrive pipeline ID")
  },
  async ({ pipelineId }, extra) => {
    const clients = getPipedriveClients(extra);
    if (!clients) {
      return missingCredentialsResponse();
    }

    const { pipelinesApi } = clients;

    try {
      // @ts-ignore - Bypass incorrect TypeScript definition
      const response = await pipelinesApi.getPipeline(pipelineId);
      return buildTextResult(JSON.stringify(response.data, null, 2));
    } catch (error) {
      console.error(`Error fetching pipeline ${pipelineId}:`, error);
      return buildTextResult(
        `Error fetching pipeline ${pipelineId}: ${getErrorMessage(error)}`,
        true
      );
    }
  }
);

// Get all stages
server.tool(
  "get-stages",
  "Get all stages from Pipedrive",
  {},
  async (_, extra) => {
    const clients = getPipedriveClients(extra);
    if (!clients) {
      return missingCredentialsResponse();
    }

    const { pipelinesApi } = clients;

    try {
      // Since the stages are related to pipelines, we'll get all pipelines first
      const pipelinesResponse = await pipelinesApi.getPipelines();
      const pipelines = pipelinesResponse.data || [];
      
      // For each pipeline, fetch its stages
      const allStages = [];
      for (const pipeline of pipelines) {
        try {
          // @ts-ignore - Type definitions for getPipelineStages are incomplete
          const stagesResponse = await pipelinesApi.getPipelineStages(pipeline.id);
          const stagesData = Array.isArray(stagesResponse?.data)
            ? stagesResponse.data
            : [];

          if (stagesData.length > 0) {
            const pipelineStages = stagesData.map((stage: any) => ({
              ...stage,
              pipeline_name: pipeline.name
            }));
            allStages.push(...pipelineStages);
          }
        } catch (e) {
          console.error(`Error fetching stages for pipeline ${pipeline.id}:`, e);
        }
      }
      
      return buildTextResult(JSON.stringify(allStages, null, 2));
    } catch (error) {
      console.error("Error fetching stages:", error);
      return buildTextResult(
        `Error fetching stages: ${getErrorMessage(error)}`,
        true
      );
    }
  }
);

// Search leads
server.tool(
  "search-leads",
  "Search leads by term",
  {
    term: z.string().describe("Search term for leads")
  },
  async ({ term }, extra) => {
    const clients = getPipedriveClients(extra);
    if (!clients) {
      return missingCredentialsResponse();
    }

    const { leadsApi } = clients;

    try {
      // @ts-ignore - Bypass incorrect TypeScript definition
      const response = await leadsApi.searchLeads(term);
      return buildTextResult(JSON.stringify(response.data, null, 2));
    } catch (error) {
      console.error(`Error searching leads with term "${term}":`, error);
      return buildTextResult(
        `Error searching leads: ${getErrorMessage(error)}`,
        true
      );
    }
  }
);

// Generic search across item types
server.tool(
  "search-all",
  "Search across all item types (deals, persons, organizations, etc.)",
  {
    term: z.string().describe("Search term"),
    itemTypes: z.string().optional().describe("Comma-separated list of item types to search (deal,person,organization,product,file,activity,lead)")
  },
  async ({ term, itemTypes }, extra) => {
    const clients = getPipedriveClients(extra);
    if (!clients) {
      return missingCredentialsResponse();
    }

    const { itemSearchApi } = clients;

    try {
      const itemType = itemTypes; // Just rename the parameter
      const response = await itemSearchApi.searchItem({ 
        term,
        itemType 
      });
      return buildTextResult(JSON.stringify(response.data, null, 2));
    } catch (error) {
      console.error(`Error performing search with term "${term}":`, error);
      return buildTextResult(
        `Error performing search: ${getErrorMessage(error)}`,
        true
      );
    }
  }
);

// === PROMPTS ===

// Prompt for getting all deals
server.prompt(
  "list-all-deals",
  "List all deals in Pipedrive",
  {},
  () => ({
    messages: [{
      role: "user",
      content: {
        type: "text",
        text: "Please list all deals in my Pipedrive account, showing their title, value, status, and stage."
      }
    }]
  })
);

// Prompt for getting all persons
server.prompt(
  "list-all-persons",
  "List all persons in Pipedrive",
  {},
  () => ({
    messages: [{
      role: "user",
      content: {
        type: "text",
        text: "Please list all persons in my Pipedrive account, showing their name, email, phone, and organization."
      }
    }]
  })
);

// Prompt for getting all pipelines
server.prompt(
  "list-all-pipelines",
  "List all pipelines in Pipedrive",
  {},
  () => ({
    messages: [{
      role: "user",
      content: {
        type: "text",
        text: "Please list all pipelines in my Pipedrive account, showing their name and stages."
      }
    }]
  })
);

// Prompt for analyzing deals
server.prompt(
  "analyze-deals",
  "Analyze deals by stage",
  {},
  () => ({
    messages: [{
      role: "user",
      content: {
        type: "text",
        text: "Please analyze the deals in my Pipedrive account, grouping them by stage and providing total value for each stage."
      }
    }]
  })
);

// Prompt for analyzing contacts
server.prompt(
  "analyze-contacts",
  "Analyze contacts by organization",
  {},
  () => ({
    messages: [{
      role: "user",
      content: {
        type: "text",
        text: "Please analyze the persons in my Pipedrive account, grouping them by organization and providing a count for each organization."
      }
    }]
  })
);

// Prompt for analyzing leads
server.prompt(
  "analyze-leads",
  "Analyze leads by status",
  {},
  () => ({
    messages: [{
      role: "user",
      content: {
        type: "text",
        text: "Please search for all leads in my Pipedrive account and group them by status."
      }
    }]
  })
);

// Prompt for pipeline comparison
server.prompt(
  "compare-pipelines",
  "Compare different pipelines and their stages",
  {},
  () => ({
    messages: [{
      role: "user",
      content: {
        type: "text",
        text: "Please list all pipelines in my Pipedrive account and compare them by showing the stages in each pipeline."
      }
    }]
  })
);

// Prompt for finding high-value deals
server.prompt(
  "find-high-value-deals",
  "Find high-value deals",
  {},
  () => ({
    messages: [{
      role: "user",
      content: {
        type: "text",
        text: "Please identify the highest value deals in my Pipedrive account and provide information about which stage they're in and which person or organization they're associated with."
      }
    }]
  })
);

// Get transport type from environment variable (default to stdio)
const transportType = process.env.MCP_TRANSPORT || 'stdio';

if (transportType === 'sse') {
  // SSE transport - create HTTP server
  const port = parseInt(process.env.MCP_PORT || '3000', 10);
  const endpoint = process.env.MCP_ENDPOINT || '/message';

  // Store active transports by session ID
  const transports = new Map<string, SSEServerTransport>();

  const httpServer = http.createServer(async (req, res) => {
    const url = new URL(req.url!, `http://${req.headers.host}`);

    // Enable CORS
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Session-Id');

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    if (req.method === 'GET' && url.pathname === '/sse') {
      const authResult = verifyRequestAuthentication(req);
      if (!authResult.ok) {
        res.writeHead(authResult.status, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: authResult.message }));
        return;
      }

      // Establish SSE connection
      console.error('New SSE connection request');
      const transport = new SSEServerTransport(endpoint, res);

      const tenantIdQuery =
        url.searchParams.get('tenant') || url.searchParams.get('tenantId');
      if (tenantIdQuery) {
        setTenantForSession(transport.sessionId, tenantIdQuery);
      }

      // Store transport by session ID
      transports.set(transport.sessionId, transport);

      transport.onclose = () => {
        console.error(`SSE connection closed: ${transport.sessionId}`);
        transports.delete(transport.sessionId);
        clearTenantForSession(transport.sessionId);
      };

      try {
        await server.connect(transport);
        console.error(`SSE connection established: ${transport.sessionId}`);
      } catch (err) {
        console.error('Failed to establish SSE connection:', err);
        transports.delete(transport.sessionId);
      }
    } else if (req.method === 'POST' && url.pathname === endpoint) {
      const authResult = verifyRequestAuthentication(req);
      if (!authResult.ok) {
        res.writeHead(authResult.status, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: authResult.message }));
        return;
      }

      // Handle incoming message
      const sessionId = url.searchParams.get('sessionId') || req.headers['x-session-id'] as string;

      if (!sessionId) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Missing sessionId' }));
        return;
      }

      const transport = transports.get(sessionId);
      if (!transport) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Session not found' }));
        return;
      }

      req.on('error', err => {
        console.error('Error receiving POST message body:', err);
        if (!res.headersSent) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Invalid request body' }));
        }
      });

      try {
        await transport.handlePostMessage(req, res);
      } catch (err) {
        console.error('Error handling POST message:', err);
        if (!res.headersSent) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Internal server error' }));
        }
      }
    } else if (req.method === 'GET' && url.pathname === '/oauth/callback') {
      if (!isOAuthConfigured()) {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('OAuth is not configured on this server.');
        return;
      }

      const code = url.searchParams.get('code');
      const state = url.searchParams.get('state');

      if (!code) {
        res.writeHead(400, { 'Content-Type': 'text/plain' });
        res.end('Missing authorization code.');
        return;
      }

      const payload = state ? consumeOAuthState(state) : undefined;
      if (state && !payload) {
        res.writeHead(400, { 'Content-Type': 'text/plain' });
        res.end('Invalid or expired state.');
        return;
      }

      try {
        const oauthClient = createOAuthApiClient();
        await oauthClient.authorize(code);
        const oauthAuth = oauthClient.authentications.oauth2;
        const domain = oauthClient.basePath ? new URL(oauthClient.basePath).hostname : null;
        const accessToken = oauthAuth.accessToken;

        if (!domain) {
          throw new Error("Failed to determine Pipedrive domain from the OAuth response.");
        }

        if (!accessToken) {
          throw new Error("OAuth access token missing from the response.");
        }

        const oauthCredentials: OAuthCredentials = {
          type: "oauth",
          domain: normalizeDomain(domain),
          accessToken,
          refreshToken: oauthAuth.refreshToken,
          expiresAt: oauthAuth.expiresAt,
        };

        const providedTenant =
          url.searchParams.get('tenant') || url.searchParams.get('tenantId');

        const tenantId =
          payload?.tenantId ??
          providedTenant ??
          'default';

        if (payload?.sessionKey) {
          setTenantForSession(payload.sessionKey, tenantId);
        }

        storeTenantCredentials(tenantId, oauthCredentials);

        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end("<h1>Success!</h1><p>Your Pipedrive account is connected. You can return to your connector.</p>");
      } catch (error) {
        console.error("Pipedrive OAuth callback failed:", error);
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end("Failed to process OAuth callback. Check the server logs for details.");
      }
    } else {
      // Health check endpoint
      if (req.method === 'GET' && url.pathname === '/health') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'ok', transport: 'sse' }));
        return;
      }

      res.writeHead(404);
      res.end('Not found');
    }
  });

  httpServer.listen(port, () => {
    console.error(`Pipedrive MCP Server (SSE) listening on port ${port}`);
    console.error(`SSE endpoint: http://localhost:${port}/sse`);
    console.error(`Message endpoint: http://localhost:${port}${endpoint}`);
  });
} else {
  // Default: stdio transport
  const transport = new StdioServerTransport();
  server.connect(transport).catch(err => {
    console.error("Failed to start MCP server:", err);
    process.exit(1);
  });

  console.error("Pipedrive MCP Server started (stdio transport)");
}
