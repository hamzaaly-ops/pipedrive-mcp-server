declare module 'pipedrive' {
  export class ApiClient {
    basePath: string;
    authentications: {
      api_key: {
        type: string;
        in: string;
        name: string;
        apiKey: string;
      };
      basic_authentication: {
        type: string;
      };
      oauth2: {
        type: string;
        accessToken?: string;
        refreshToken?: string;
        expiresAt?: number;
        host?: string;
        clientId?: string;
        clientSecret?: string;
        redirectUri?: string;
        tokenUpdateCallback?: (token: Record<string, unknown>) => void;
      };
    };
    defaultHeaders: Record<string, string>;
    timeout: number;
    constructor();
    buildAuthorizationUrl(): string;
    authorize(code: string): Promise<any>;
    refreshToken(): Promise<any>;
  }

  export class DealsApi {
    constructor(apiClient: ApiClient);
    getDeals(): Promise<any>;
    getDeal(params: { id: number }): Promise<any>;
    searchDeals(params: { term: string }): Promise<any>;
  }

  export class PersonsApi {
    constructor(apiClient: ApiClient);
    getPersons(): Promise<any>;
    getPerson(params: { id: number }): Promise<any>;
    searchPersons(params: { term: string }): Promise<any>;
  }

  export class OrganizationsApi {
    constructor(apiClient: ApiClient);
    getOrganizations(): Promise<any>;
    getOrganization(params: { id: number }): Promise<any>;
    searchOrganizations(params: { term: string }): Promise<any>;
  }

  export class PipelinesApi {
    constructor(apiClient: ApiClient);
    getPipelines(): Promise<any>;
    getPipeline(params: { id: number }): Promise<any>;
    getPipelineStages(params: { id: number }): Promise<any>;
  }

  export class ItemSearchApi {
    constructor(apiClient: ApiClient);
    searchItem(params: { term: string, itemType?: string }): Promise<any>;
  }

  export class LeadsApi {
    constructor(apiClient: ApiClient);
    searchLeads(params: { term: string }): Promise<any>;
  }

  export class ActivitiesApi {
    constructor(apiClient: ApiClient);
    getActivities(params?: Record<string, unknown>): Promise<any>;
  }

  export class NotesApi {
    constructor(apiClient: ApiClient);
    getNotes(params?: Record<string, unknown>): Promise<any>;
  }

  export class UsersApi {
    constructor(apiClient: ApiClient);
    getUsers(params?: Record<string, unknown>): Promise<any>;
  }
} 
