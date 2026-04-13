# Multi-Tenant Global Pipedrive MCP Server 

This is a Model Context Protocol (MCP) server that connects to the Pipedrive API via OAuth 2.0. It allows anyone with a Pipedrive account to authenticate via a web flow and fetch Pipedrive data securely without manually configuring API keys. Designed for global, multi-tenant use on platforms like Claude Desktop and AWS deployments.

## Features
- **OAuth 2.0 Authentication**: No hardcoded API keys. Users simply "Login with Pipedrive" across any instance.
- **Global Multi-Tenant support**: Scales well on AWS, managing tokens inside Supabase.
- **Dynamic Configuration**: Generates accurate MCP connection strings for clients.
- Read-only access to Deals, Persons, Organizations, Pipelines, and other standard Pipedrive APIs.

## Requirements
- Pipedrive Developer App (to obtain Client ID and Client Secret)
- Supabase Project (PostgreSQL)

## Supabase Database Setup 
Execute this SQL in your Supabase SQL Editor:
```sql
CREATE TABLE tenants (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  pipedrive_company_id BIGINT UNIQUE NOT NULL,
  access_token TEXT NOT NULL,
  refresh_token TEXT NOT NULL,
  expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

## Setup Env Variables
Copy `.env.example` to `.env` and fill in:
- `PIPEDRIVE_CLIENT_ID`: Your Pipedrive app Client ID.
- `PIPEDRIVE_CLIENT_SECRET`: Your Pipedrive app Client Secret.
- `APP_BASE_URL`: The domain where your MCP server will reside (e.g. `https://my-mcp.company.com` or `http://localhost:3000`).
- `SUPABASE_URL`: Your Supabase API URL.
- `SUPABASE_ANON_KEY`: Your Supabase anon key.

## Start the global server

1. Install dependencies:
```bash
npm install
```
2. Build the project:
```bash
npm run build
```
3. Start the project:
```bash
npm start
```

## Usage Flow / Onboarding
1. Once running, go to `http://localhost:3000/auth/login` (or your live domain equivalent) in your web browser.
2. Accept the Pipedrive auth consent screen.
3. You will be redirected to a success screen with your generated `tenantId`.
4. The page provides the `json` configuring string to be pasted in Claude Desktop:
```json
{
  "mcpServers": {
    "pipedrive-global": {
      "command": "npx",
      "args": [
        "-y",
        "@modelcontextprotocol/client-sse",
        "--url",
        "http://localhost:3000/sse?tenantId=YOUR-TENANT-ID"
      ]
    }
  }
}
```

## AWS Deployment instructions
1. Containerize the application (the provided `Dockerfile` still fundamentally works).
2. Deploy onto AWS AppRunner, AWS ECS, or AWS Elastic Beanstalk.
3. Expose Port 3000 mapping.
4. Add the aforementioned Environment Variables to the AWS Task/Environment Definitions securely.
5. In your Pipedrive Developer UI, remember to set your Callback URL to the exact `https://<YOUR-AWS-DOMAIN>/auth/callback`.
