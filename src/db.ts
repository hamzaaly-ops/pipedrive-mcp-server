import dotenv from 'dotenv';
dotenv.config();

import { createClient } from '@supabase/supabase-js';

const supabaseUrl = process.env.SUPABASE_URL || '';
const supabaseKey = process.env.SUPABASE_ANON_KEY || '';

export const supabase = createClient(supabaseUrl, supabaseKey);

export async function upsertTenant(tenantData: {
  pipedrive_company_id: number,
  access_token: string,
  refresh_token: string,
  expires_at: string
}): Promise<string> {
  const { data, error } = await supabase
    .from('tenants')
    .upsert(
      { 
        pipedrive_company_id: tenantData.pipedrive_company_id, 
        access_token: tenantData.access_token, 
        refresh_token: tenantData.refresh_token, 
        expires_at: tenantData.expires_at 
      },
      { onConflict: 'pipedrive_company_id' }
    )
    .select()
    .single();

  if (error) throw error;
  if (!data) throw new Error("Failed to insert tenant");
  return data.id;
}

export async function getTenantToken(tenantId: string): Promise<string> {
  const { data, error } = await supabase
    .from('tenants')
    .select('*')
    .eq('id', tenantId)
    .single();

  if (error || !data) throw new Error("Tenant not found");
  
  if (new Date(data.expires_at) < new Date()) {
    // Refresh token
    const client_id = process.env.PIPEDRIVE_CLIENT_ID!;
    const client_secret = process.env.PIPEDRIVE_CLIENT_SECRET!;
    const auth = Buffer.from(`${client_id}:${client_secret}`).toString('base64');
    
    const response = await fetch('https://oauth.pipedrive.com/oauth/token', {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${auth}`,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: data.refresh_token
      })
    });
    
    const tokenData = await response.json();
    if (!response.ok) throw new Error(`Refresh failed: ${JSON.stringify(tokenData)}`);
    
    const expiresAt = new Date(Date.now() + tokenData.expires_in * 1000).toISOString();
    await supabase.from('tenants').update({
      access_token: tokenData.access_token,
      refresh_token: tokenData.refresh_token,
      expires_at: expiresAt
    }).eq('id', tenantId);
    
    return tokenData.access_token;
  }
  
  return data.access_token;
}
