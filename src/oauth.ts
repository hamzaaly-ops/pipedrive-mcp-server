import * as pipedrive from "pipedrive";
import { getTenantToken } from "./db.js";

export function getAuthUrl() {
  const client_id = process.env.PIPEDRIVE_CLIENT_ID!;
  const base_url = process.env.APP_BASE_URL || "http://localhost:3000";
  return `https://oauth.pipedrive.com/oauth/authorize?client_id=${client_id}&redirect_uri=${base_url}/auth/callback`;
}

export async function authorizeUser(code: string) {
  const client_id = process.env.PIPEDRIVE_CLIENT_ID!;
  const client_secret = process.env.PIPEDRIVE_CLIENT_SECRET!;
  const base_url = process.env.APP_BASE_URL || "http://localhost:3000";
  const auth = Buffer.from(`${client_id}:${client_secret}`).toString('base64');

  const response = await fetch('https://oauth.pipedrive.com/oauth/token', {
    method: 'POST',
    headers: {
      'Authorization': `Basic ${auth}`,
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code: code,
      redirect_uri: `${base_url}/auth/callback`
    })
  });

  const data = await response.json();
  if (!response.ok) {
    throw new Error(`Failed to authorize: ${JSON.stringify(data)}`);
  }
  return data;
}

export async function getPipedriveUserInfo(accessToken: string) {
  const response = await fetch('https://api.pipedrive.com/v1/users/me', {
    headers: { 'Authorization': `Bearer ${accessToken}` }
  });
  const data = await response.json();
  if (!response.ok) {
    throw new Error(`User info fetch failed: ${JSON.stringify(data)}`);
  }
  return data.data;
}

export async function createTenantApiClient(tenantId: string) {
  const accessToken = await getTenantToken(tenantId);
  const apiClient = new pipedrive.ApiClient();
  apiClient.authentications.oauth2.accessToken = accessToken;
  return apiClient;
}
