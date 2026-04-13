import { getValidAccessToken } from './src/oauth.js';
import { getTenantStatus } from './src/db.js';
import * as pipedrive from 'pipedrive';

async function testConnection() {
  const tenantId = 'ce769eee-0c38-439d-84fc-8a8d2ca014ee';
  console.log(`Testing connection for tenant: ${tenantId}`);
  
  try {
    const token = await getValidAccessToken(tenantId);
    console.log(`Retrieved Token: ${token.substring(0, 10)}...`);
    
    const apiClient = new pipedrive.ApiClient();
    apiClient.basePath = 'https://api-proxy.pipedrive.com/api/v1';
    apiClient.authentications['oauth2'] = {
        type: 'oauth2',
        accessToken: token
    };

    const dealsApi = new pipedrive.DealsApi(apiClient);
    console.log('Fetching deals...');
    const deals = await dealsApi.getDeals({ limit: 1 });
    console.log('Success! Found deals:', deals.data.length);

  } catch (error: any) {
    if (error.response) {
      console.error('API Error Response:', JSON.stringify(error.response.body, null, 2));
    } else {
      console.error('Error:', error.message);
    }
  }
}

testConnection();
