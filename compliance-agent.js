
const axios = require('axios');
const msal = require('@azure/msal-node');

// ============================================================================
// Configuration Helper
// ============================================================================

function buildConfig(credentials = {}) {
  return {
    auth: {
      clientId: credentials.clientId || process.env.AZURE_CLIENT_ID,
      clientSecret: credentials.clientSecret || process.env.AZURE_CLIENT_SECRET,
      tenantId: credentials.tenantId || process.env.AZURE_TENANT_ID,
    },
    resources: {
      defender: credentials.defenderResourceId || process.env.DEFENDER_RESOURCE_ID || 'https://api.securitycenter.microsoft.com',
      sentinel: credentials.sentinelWorkspaceId || process.env.SENTINEL_WORKSPACE_ID,
      sentinelResourceGroup: credentials.sentinelResourceGroup || process.env.SENTINEL_RESOURCE_GROUP,
      subscriptionId: credentials.subscriptionId || process.env.AZURE_SUBSCRIPTION_ID,
      firewallPolicy: credentials.firewallPolicy || process.env.FIREWALL_POLICY_NAME,
      firewallResourceGroup: credentials.firewallResourceGroup || process.env.FIREWALL_RESOURCE_GROUP,
    },
    monitoring: {
      pollingIntervalMinutes: 15,
      alertThresholds: {
        newDevices: 5,
        newIncidents: 1,
        riskyUsers: 3,
      }
    }
  };
}

// ============================================================================
// Authentication Manager with Auto-Refresh
// ============================================================================

class AuthManager {
  constructor(config) {
    if (!config.auth.clientId || !config.auth.clientSecret || !config.auth.tenantId) {
      throw new Error('Missing required auth credentials: clientId, clientSecret, tenantId');
    }
    console.log("configuration", config.auth.clientId, config.auth.tenantId, config.auth.clientSecret, config.resources);
    this.config = config;
    this.msalClient = new msal.ConfidentialClientApplication({
      auth: {
        clientId: config.auth.clientId,
        authority: `https://login.microsoftonline.com/${config.auth.tenantId}`,
        clientSecret: config.auth.clientSecret,
      }
    });
    this.tokens = {};
  }

  async getToken(scope) {
    const cacheKey = Array.isArray(scope) ? scope.join(',') : scope;
    
    // Check if token exists and is still valid (with 5 min buffer)
    if (this.tokens[cacheKey]) {
      const expiresAt = this.tokens[cacheKey].expiresAt;
      if (expiresAt && Date.now() < expiresAt - 300000) {
        return this.tokens[cacheKey].accessToken;
      }
    }

    // Request new token
    const scopes = Array.isArray(scope) ? scope : [scope];
    
    try {
      const result = await this.msalClient.acquireTokenByClientCredential({
        scopes,
      });

      this.tokens[cacheKey] = {
        accessToken: result.accessToken,
        expiresAt: result.expiresOn ? result.expiresOn.getTime() : Date.now() + 3600000,
      };
      
      console.log(`✅ Token acquired for scope: ${scopes[0].substring(0, 30)}...`);
      return result.accessToken;
    } catch (error) {
      console.error('❌ Token acquisition failed:', {
        error: error.errorCode || error.message,
        tenant: this.config.auth.tenantId.substring(0, 8) + '...',
        scopes: scopes
      });
      throw error;
    }
  }

  async getDefenderToken() {
    return this.getToken([`${this.config.resources.defender}/.default`]);
  }

  async getGraphToken() {
    return this.getToken(['https://graph.microsoft.com/.default']);
  }

  async getManagementToken() {
    return this.getToken(['https://management.azure.com/.default']);
  }
}

// ============================================================================
// API Client with Auto-Retry and Token Refresh
// ============================================================================

class ApiClient {
  constructor(authManager) {
    this.auth = authManager;
  }

  async request(url, options = {}, tokenType = 'management') {
    const maxRetries = 3;
    let lastError;

    for (let attempt = 0; attempt < maxRetries; attempt++) {
      try {
        // Get fresh token
        let token;
        switch (tokenType) {
          case 'defender':
            token = await this.auth.getDefenderToken();
            // console.log(`Using defender token for request to ${url}`, token);
            break;
          case 'graph':
            token = await this.auth.getGraphToken();
            // console.log(`Using graph token for request to ${url}`, token);
            break;
          default:
            token = await this.auth.getManagementToken();
            console.log(`Using management token for request to ${url}`, token);
        }

        const response = await axios({
          url,
          method: options.method || 'GET',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
            ...options.headers,
          },
          data: options.body,
          params: options.params,
          timeout: 180000,
        });

        return response.data;
      } catch (error) {
        lastError = error;
        
        // If token expired, retry immediately
        if (error.response?.status === 401) {
          console.log(`Token expired, refreshing... (attempt ${attempt + 1})`);
          continue;
        }
        
        // If rate limited, wait and retry
        if (error.response?.status === 429) {
          const retryAfter = error.response.headers['retry-after'] || 5;
          console.log(`Rate limited, waiting ${retryAfter}s...`);
          await new Promise(resolve => setTimeout(resolve, retryAfter * 1000));
          continue;
        }
        
        // For other errors, throw immediately
        throw error;
      }
    }

    throw lastError;
  }
}

// ============================================================================
// Feature 1: Compliance Reporting & Evidence Harvesting
// ============================================================================

class ComplianceReporter {
  constructor(apiClient, config) {
    this.api = apiClient;
    this.config = config;
  }

  // Defender endpoints
  async getDeviceInventory() {
    const url = `${this.config.resources.defender}/api/machines`;
    return this.api.request(url, {}, 'defender');
  }

  async getSpecificDeviceInventory(machineId) {
    const url = `${this.config.resources.defender}/api/machines/${machineId}`;
    return this.api.request(url, {}, 'defender');
  }

  async batchUpdateAlert(body) {
    const url = `${this.config.resources.defender}/api/alerts/batchUpdate`;
    return this.api.request(url, {
      method: 'POST',
      body
    }, 'defender');
  }

  async getDeviceHealth() {
    const url = `${this.config.resources.defender}/api/deviceavinfo`;
    return this.api.request(url, { method: 'GET' }, 'defender');
  }

  async getMachineTag(tag) {
    const url = `${this.config.resources.defender}/api/machines/findbytag?tag=${tag}&useStartsWithFilter=true`;
    return this.api.request(url, {}, 'defender');
  }

  async getSecurityAlerts(filters = {}) {
    const url = `${this.config.resources.defender}/api/alerts`;
    return this.api.request(url, { params: filters }, 'defender');
  }

  async CreateAlertByRefrence(body) {
    const url = `${this.config.resources.defender}/api/alerts/createAlertByReference`;
    return this.api.request(url, {
      method: 'POST',
      body
    }, 'defender');
  }

  async getVulnerabilities() {
    const url = `${this.config.resources.defender}/api/vulnerabilities`;
    return this.api.request(url, {}, 'defender');
  }

  async getSecurityRecommendations() {
    const url = `${this.config.resources.defender}/api/recommendations`;
    return this.api.request(url, {}, 'defender');
  }

  // Sentinel endpoints
  async getSentinelIncidents() {
    const url = `https://management.azure.com/subscriptions/${this.config.resources.subscriptionId}/resourceGroups/${this.config.resources.sentinelResourceGroup}/providers/Microsoft.OperationalInsights/workspaces/${this.config.resources.sentinel}/providers/Microsoft.SecurityInsights/incidents?api-version=2023-02-01`;
    return this.api.request(url);
  }

  async getIncidentAlerts(incidentId) {
    const url = `https://management.azure.com/subscriptions/${this.config.resources.subscriptionId}/resourceGroups/${this.config.resources.sentinelResourceGroup}/providers/Microsoft.OperationalInsights/workspaces/${this.config.resources.sentinel}/providers/Microsoft.SecurityInsights/incidents/${incidentId}/alerts?api-version=2023-02-01`;
    return this.api.request(url, { method: 'POST' });
  }

  async getIncidentEntities(incidentId) {
    const url = `https://management.azure.com/subscriptions/${this.config.resources.subscriptionId}/resourceGroups/${this.config.resources.sentinelResourceGroup}/providers/Microsoft.OperationalInsights/workspaces/${this.config.resources.sentinel}/providers/Microsoft.SecurityInsights/incidents/${incidentId}/entities?api-version=2023-02-01`;
    return this.api.request(url, { method: 'POST' });
  }

  // Firewall endpoints
  async getFirewallPolicies() {
    const url = `https://management.azure.com/subscriptions/${this.config.resources.subscriptionId}/resourceGroups/${this.config.resources.firewallResourceGroup}/providers/Microsoft.Network/firewallPolicies?api-version=2023-05-01`;
    return this.api.request(url);
  }

  async getRuleCollectionGroups() {
    const url = `https://management.azure.com/subscriptions/${this.config.resources.subscriptionId}/resourceGroups/${this.config.resources.firewallResourceGroup}/providers/Microsoft.Network/firewallPolicies/${this.config.resources.firewallPolicy}/ruleCollectionGroups?api-version=2023-05-01`;
    return this.api.request(url);
  }
  async listIdpsSignatures(filters = [], search = "", orderBy = null, resultsPerPage = 20, skip = 0) {
  const url = `https://management.azure.com/subscriptions/${this.config.resources.subscriptionId}/resourceGroups/${this.config.resources.firewallResourceGroup}/providers/Microsoft.Network/firewallPolicies/${this.config.resources.firewallPolicy}/listIdpsSignatures?api-version=2025-03-01`;
  
  const body = { 
    search, 
    resultsPerPage, 
    skip 
  };

  if (orderBy) {
    body.orderBy = orderBy;
  }

  if (filters && filters.length > 0) {
    body.filters = filters;
  }

  const response = await this.api.request(url, { 
    method: 'POST',
    body: body  
  });
  return response;
}

  async getSignatureOverrides() {
    const url = `https://management.azure.com/subscriptions/${this.config.resources.subscriptionId}/resourceGroups/${this.config.resources.firewallResourceGroup}/providers/Microsoft.Network/firewallPolicies/${this.config.resources.firewallPolicy}?api-version=2025-03-01`;
    return this.api.request(url, { method: 'GET' });
  }

  async updateSignatureOverrides(signatureMap = {}) {
    const id = `/subscriptions/${this.config.resources.subscriptionId}/resourceGroups/${this.config.resources.firewallResourceGroup}/providers/Microsoft.Network/firewallPolicies/${this.config.resources.firewallPolicy}/signatureOverrides/default`;
    const url = `https://management.azure.com${id}?api-version=2025-03-01`;

    const body = {
      id,
      name: "default",
      type: "Microsoft.Network/firewallPolicies/signatureOverrides",
      properties: {
        signatures: signatureMap
      }
    };

    return this.api.request(url, { method: 'PUT', body });
  }

  async getFirewallIpConfigurations() {
  const url = `https://management.azure.com/subscriptions/${this.config.resources.subscriptionId}/providers/Microsoft.Network/azureFirewalls?api-version=2025-03-01`;
  
  const response = await this.api.request(url, { method: 'GET' });
  
  // Extract IP configurations
  return {
    name: response.name,
    location: response.location,
    ipConfigurations: response.properties?.ipConfigurations || [],
    managementIpConfiguration: response.properties?.managementIpConfiguration,
    sku: response.sku,
    threatIntelMode: response.properties?.threatIntelMode,
    firewallPolicy: response.properties?.firewallPolicy
  };
}

async getNetworkSecurityGroups() {
  const url = `https://management.azure.com/subscriptions/${this.config.resources.subscriptionId}/providers/Microsoft.Network/networkSecurityGroups?api-version=2023-11-01`;
  return this.api.request(url, { method: 'GET' });
}

  async listIdpsFilterOptions(filterName) {
    const url = `https://management.azure.com/subscriptions/${this.config.resources.subscriptionId}/resourceGroups/${this.config.resources.firewallResourceGroup}/providers/Microsoft.Network/firewallPolicies/${this.config.resources.firewallPolicy}/listIdpsFilterOptions?api-version=2025-03-01`;

    const body = { filterName };
    return this.api.request(url, { method: 'POST' , body});
  }
 
  // Graph endpoints
  async getSignInLogs(filters = {}) {
  const filterParts = [];
  
  // Add user-provided filter if exists
  if (filters.$filter) {
    filterParts.push(filters.$filter);
  }
  
  // Add date range filter if provided, otherwise default to last 7 days
  if (filters.startDate && filters.endDate) {
    filterParts.push(`createdDateTime ge ${filters.startDate}`);
    filterParts.push(`createdDateTime le ${filters.endDate}`);
  } else {
    const days = filters.days || 7;
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - days);
    filterParts.push(`createdDateTime ge ${startDate.toISOString()}`);
  }
  
  // Build query parameters
  const queryParams = [];
  
  if (filterParts.length > 0) {
    queryParams.push(`$filter=${filterParts.join(' and ')}`);
  }
  
  // Add top parameter (Microsoft Graph default is 100, max is 999)
  if (filters.$top) {
    queryParams.push(`$top=${Math.min(filters.$top, 999)}`);
  }
  
  // Add orderby if specified
  if (filters.$orderby) {
    queryParams.push(`$orderby=${filters.$orderby}`);
  }
  
  const queryString = queryParams.length > 0 ? `?${queryParams.join('&')}` : '';
  const url = `https://graph.microsoft.com/v1.0/auditLogs/signIns${queryString}`;
  
  console.log(`📊 Fetching sign-ins from Graph API`);
  console.log(`URL: ${url}`);
  
  return this.api.request(url, {}, 'graph');
}

  async getDirectoryAudits(filters = {}) {
    const filterQuery = filters.$filter ? `?$filter=${filters.$filter}` : '';
    const url = `https://graph.microsoft.com/v1.0/auditLogs/directoryAudits${filterQuery}`;
    return this.api.request(url, {}, 'graph');
  }

  async getUserAuthMethods(userId) {
    const url = `https://graph.microsoft.com/v1.0/users/${userId}/authentication/methods`;
    return this.api.request(url, {}, 'graph');
  }

  async getConditionalAccessPolicies() {
    const url = `https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies`;
    return this.api.request(url, {}, 'graph');
  }

  async collectInvestigationPackage(machineId, body = {}) {
    const url = `${this.config.resources.defender}/api/machines/${machineId}/collectInvestigationPackage`;
    return this.api.request(url, { method: "POST", body }, "defender");
  }
  
  async getRiskyUsers() {
    const url = `https://graph.microsoft.com/v1.0/identityProtection/riskyUsers`;
    return this.api.request(url, {}, 'graph');
  }

  async getUsersWithMfaStatus() {
  try {
    // Get all users
    const usersUrl = `https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName,accountEnabled`;
    const usersResponse = await this.api.request(usersUrl, {}, 'graph');
    const users = usersResponse.value || [];
    
    console.log(`📊 Checking MFA status for ${users.length} users...`);
    
    const usersWithMfaStatus = [];
    
    // Check MFA for each user (limit to avoid rate limiting)
    const limitedUsers = users.slice(0, 50); // Check first 50 users
    
    for (const user of limitedUsers) {
      if (!user.accountEnabled) continue; // Skip disabled users
      
      try {
        const authMethods = await this.getUserAuthMethods(user.id);
        const methods = authMethods.value || [];
        
        // Check if user has MFA methods (anything other than just password)
        const hasMfa = methods.some(method => 
          method['@odata.type'] !== '#microsoft.graph.passwordAuthenticationMethod'
        );
        
        usersWithMfaStatus.push({
          userId: user.id,
          displayName: user.displayName,
          userPrincipalName: user.userPrincipalName,
          hasMfa,
          authMethods: methods.map(m => m['@odata.type'])
        });
        
      } catch (error) {
        console.warn(`⚠️  Could not check MFA for user ${user.displayName}:`, error.message);
        // Skip this user
      }
    }
    
    console.log(`✅ Checked MFA status for ${usersWithMfaStatus.length} users`);
    return usersWithMfaStatus;
    
  } catch (error) {
    console.warn('⚠️  Could not get users with MFA status:', error.message);
    return [];
  }
}

  async generateComplianceReport() {
    console.log('🔍 Starting compliance evidence collection...');
    
    const evidence = {
      timestamp: new Date().toISOString(),
    };

    // Defender APIs
    try {
      evidence.devices = await this.getDeviceInventory();
    } catch (error) {
      console.warn('⚠️  Could not get devices:', error.response?.status, error.message);
      evidence.devices = { value: [] };
    }

    try {
      evidence.alerts = await this.getSecurityAlerts();
    } catch (error) {
      console.warn('⚠️  Could not get alerts:', error.response?.status, error.message);
      evidence.alerts = { value: [] };
    }

    try {
      evidence.vulnerabilities = await this.getVulnerabilities();
    } catch (error) {
      console.warn('⚠️  Could not get vulnerabilities:', error.response?.status, error.message);
      evidence.vulnerabilities = { value: [] };
    }

    try {
      evidence.recommendations = await this.getSecurityRecommendations();
    } catch (error) {
      console.warn('⚠️  Could not get recommendations:', error.response?.status, error.message);
      evidence.recommendations = { value: [] };
    }

    // Sentinel APIs (skip if not configured)
    if (this.config.resources.sentinel && this.config.resources.sentinelResourceGroup) {
      try {
        evidence.incidents = await this.getSentinelIncidents();
      } catch (error) {
        console.warn('⚠️  Could not get Sentinel incidents:', error.response?.status, error.message);
        evidence.incidents = { value: [] };
      }
    } else {
      console.log('ℹ️  Sentinel not configured, skipping...');
      evidence.incidents = { value: [] };
    }

    // Firewall APIs (skip if not configured)
     if (this.config.resources.firewallPolicy && this.config.resources.firewallResourceGroup) {
    try {
      evidence.firewallPolicies = await this.getFirewallPolicies();
    } catch (error) {
      console.warn('⚠️  Could not get firewall policies:', error.message);
      evidence.firewallPolicies = { value: [] };
    }

    try {
      evidence.firewallRuleCollections = await this.getRuleCollectionGroups();
    } catch (error) {
      console.warn('⚠️  Could not get firewall rule collections:', error.message);
      evidence.firewallRuleCollections = { value: [] };
    }

    // ADD THIS - IDPS Signatures
    try {
      console.log('🔥 Fetching firewall IDPS signatures...');
      evidence.idpsSignatures = await this.listIdpsSignatures(
        [], // no filters - get all
        "", // no search
        { field: "severity", order: "Descending" }, // order by severity
        100, // get more results
        0
      );
    } catch (error) {
      console.warn('⚠️  Could not get IDPS signatures:', error.message);
      evidence.idpsSignatures = { matchingRecordsCount: 0, signatures: [] };
    }

    // ADD THIS - Signature Overrides
    try {
      console.log('🔥 Fetching firewall signature overrides...');
      evidence.signatureOverrides = await this.getSignatureOverrides();
    } catch (error) {
      console.warn('⚠️  Could not get signature overrides:', error.message);
      evidence.signatureOverrides = { properties: { signatures: {} } };
    }

  } else {
    evidence.firewallPolicies = { value: [] };
    evidence.firewallRuleCollections = { value: [] };
    evidence.idpsSignatures = { matchingRecordsCount: 0, signatures: [] };
    evidence.signatureOverrides = { properties: { signatures: {} } };
  }

    // Graph APIs
    try {
      console.log('📊 Fetching sign-in logs from Graph API...');
      evidence.signIns = await this.getSignInLogs();
    } catch (error) {
      console.warn('⚠️  Could not get sign-in logs:', error.response?.status, error.message);
      evidence.signIns = { value: [] };
    }

    try {
      evidence.directoryAudits = await this.getDirectoryAudits();
    } catch (error) {
      console.warn('⚠️  Could not get directory audits:', error.response?.status, error.message);
      evidence.directoryAudits = { value: [] };
    }

    try {
      evidence.caPolicies = await this.getConditionalAccessPolicies();
    } catch (error) {
      console.warn('⚠️  Could not get CA policies:', error.response?.status, error.message);
      evidence.caPolicies = { value: [] };
    }

    try {
      evidence.riskyUsers = await this.getRiskyUsers();
    } catch (error) {
      console.warn('⚠️  Could not get risky users:', error.response?.status, error.message);
      evidence.riskyUsers = { value: [] };
    }

     try {
    console.log('🔐 Checking MFA compliance for users...');
    evidence.usersWithMfaStatus = await this.getUsersWithMfaStatus();
    } catch (error) {
    console.warn('⚠️  Could not get users MFA status:', error.message);
    evidence.usersWithMfaStatus = [];
    }

    // Generate report with whatever data we got
    const report = {
      metadata: {
        generatedAt: evidence.timestamp,
        framework: 'UAE IA / ISO 27001 / NESA',
        totalControls: 847,
      },
      summary: {
        devicesProtected: evidence.devices?.value?.filter(d => d.healthStatus === 'Active').length || 0,
        devicesTotal: evidence.devices?.value?.length || 0,
        activeAlerts: evidence.alerts?.value?.filter(a => a.status === 'New').length || 0,
        criticalVulnerabilities: evidence.vulnerabilities?.value?.filter(v => v.severity === 'Critical').length || 0,
        mfaCompliance: this.calculateMfaCompliance(evidence.usersWithMfaStatus),
        firewallThreatsDetected: evidence.idpsSignatures?.matchingRecordsCount || 0,
        firewallSignatureOverrides: Object.keys(evidence.signatureOverrides?.properties?.signatures || {}).length,
      },
      evidence,
    };

    console.log('✅ Compliance report generated (with available data)');
    return report;
  }

  calculateMfaCompliance(usersWithMfaStatus) {
  if (!usersWithMfaStatus || usersWithMfaStatus.length === 0) {
    return {
      compliant: 0,
      nonCompliant: 0,
      percentage: 0,
      totalUsers: 0,
      details: 'No user MFA data available',
      users: []
    };
  }

  const compliant = usersWithMfaStatus.filter(u => u.hasMfa).length;
  const nonCompliant = usersWithMfaStatus.length - compliant;
  const percentage = Math.round((compliant / usersWithMfaStatus.length) * 100);

  return {
    compliant,
    nonCompliant,
    percentage,
    totalUsers: usersWithMfaStatus.length,
    details: `${compliant} out of ${usersWithMfaStatus.length} users have MFA enabled`,
    users: usersWithMfaStatus // Include detailed user data
  };
}
}

// ============================================================================
// Feature 2: Automated Remediation
// ============================================================================

class RemediationEngine {
  constructor(apiClient, config) {
    this.api = apiClient;
    this.config = config;
  }

  async isolateMachine(machineId, comment = 'Automated isolation due to security threat') {
    const url = `${this.config.resources.defender}/api/machines/${machineId}/isolate`;
    return this.api.request(url, {
      method: 'POST',
      body: { Comment: comment, IsolationType: 'Full' }
    }, 'defender');
  }

  async unisolateMachine(machineId, comment = 'Device remediated and cleared') {
    const url = `${this.config.resources.defender}/api/machines/${machineId}/unisolate`;
    return this.api.request(url, {
      method: 'POST',
      body: { Comment: comment }
    }, 'defender');
  }

  async runAntiVirusScan(machineId, scanType = 'Full') {
    const url = `${this.config.resources.defender}/api/machines/${machineId}/runAntiVirusScan`;
    return this.api.request(url, {
      method: 'POST',
      body: { Comment: 'Automated security scan', ScanType: scanType }
    }, 'defender');
  }

  async quarantineFile(machineId, filePath, comment = 'Malicious file detected') {
    const url = `${this.config.resources.defender}/api/machines/${machineId}/stopAndQuarantineFile`;
    return this.api.request(url, {
      method: 'POST',
      body: { Comment: comment, FilePath: filePath }
    }, 'defender');
  }

  async restrictCodeExecution(machineId) {
    const url = `${this.config.resources.defender}/api/machines/${machineId}/restrictCodeExecution`;
    return this.api.request(url, {
      method: 'POST',
      body: { Comment: 'Restricting untrusted apps' }
    }, 'defender');
  }

  async collectInvestigationPackage(machineId, body = {}) {
    const url = `${this.config.resources.defender}/api/machines/${machineId}/collectInvestigationPackage`;
    return this.api.request(url, { method: "POST", body }, "defender");
  }

  async unrestrictCodeExecution(machineId, body = {}) {
    const url = `${this.config.resources.defender}/api/machines/${machineId}/unrestrictCodeExecution`;
    return this.api.request(url, { method: "POST", body }, "defender");
  }

  async offboardMachine(machineId, body = {}) {
    const url = `${this.config.resources.defender}/api/machines/${machineId}/offboard`;
    return this.api.request(url, { method: "POST", body }, "defender");
  }

  async runLiveResponse(machineId, body) {
    const url = `${this.config.resources.defender}/api/machines/${machineId}/runliveresponse`;
    return this.api.request(url, { method: "POST", body }, "defender");
  }

  async blockIndicator(indicatorValue, indicatorType, action = 'Block', title = 'Automated threat block') {
    const url = `${this.config.resources.defender}/api/indicators`;
    return this.api.request(url, {
      method: 'POST',
      body: {
        indicatorValue,
        indicatorType,
        action,
        title,
        description: 'Automated threat intelligence block',
        severity: 'High',
      }
    }, 'defender');
  }

  async updateIncident(incidentId, updates) {
    const url = `https://management.azure.com/subscriptions/${this.config.resources.subscriptionId}/resourceGroups/${this.config.resources.sentinelResourceGroup}/providers/Microsoft.OperationalInsights/workspaces/${this.config.resources.sentinel}/providers/Microsoft.SecurityInsights/incidents/${incidentId}?api-version=2023-02-01`;
    return this.api.request(url, {
      method: 'PUT',
      body: { properties: updates }
    });
  }

  async runPlaybook(incidentId, logicAppResourceId) {
    const url = `https://management.azure.com/subscriptions/${this.config.resources.subscriptionId}/resourceGroups/${this.config.resources.sentinelResourceGroup}/providers/Microsoft.OperationalInsights/workspaces/${this.config.resources.sentinel}/providers/Microsoft.SecurityInsights/incidents/${incidentId}/runPlaybook?api-version=2023-02-01`;
    return this.api.request(url, {
      method: 'POST',
      body: { logicAppsResourceId: logicAppResourceId }
    });
  }

  async updateFirewallRules(ruleCollectionGroupName, rules) {
    const url = `https://management.azure.com/subscriptions/${this.config.resources.subscriptionId}/resourceGroups/${this.config.resources.firewallResourceGroup}/providers/Microsoft.Network/firewallPolicies/${this.config.resources.firewallPolicy}/ruleCollectionGroups/${ruleCollectionGroupName}?api-version=2023-05-01`;
    return this.api.request(url, {
      method: 'PUT',
      body: { properties: { ruleCollections: rules } }
    });
  }

  async addMfaPhoneMethod(userId, phoneNumber) {
    const url = `https://graph.microsoft.com/v1.0/users/${userId}/authentication/phoneMethods`;
    return this.api.request(url, {
      method: 'POST',
      body: { phoneNumber, phoneType: 'mobile' }
    }, 'graph');
  }

  async resetUserPassword(userId) {
    const url = `https://graph.microsoft.com/v1.0/users/${userId}`;
    return this.api.request(url, {
      method: 'PATCH',
      body: { passwordProfile: { forceChangePasswordNextSignIn: true } }
    }, 'graph');
  }

  async disableUserAccount(userId) {
    const url = `https://graph.microsoft.com/v1.0/users/${userId}`;
    return this.api.request(url, {
      method: 'PATCH',
      body: { accountEnabled: false }
    }, 'graph');
  }

  async revokeUserSessions(userId) {
    const url = `https://graph.microsoft.com/v1.0/users/${userId}/revokeSignInSessions`;
    return this.api.request(url, { method: 'POST' }, 'graph');
  }

  async createConditionalAccessPolicy(policy) {
    const url = `https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies`;
    return this.api.request(url, {
      method: 'POST',
      body: policy
    }, 'graph');
  }

  async confirmUserCompromised(userId) {
    const url = `https://graph.microsoft.com/v1.0/identityProtection/riskyUsers/confirmCompromised`;
    return this.api.request(url, {
      method: 'POST',
      body: { userIds: [userId] }
    }, 'graph');
  }

  async addUserToGroup(userId, groupId) {
    const url = `https://graph.microsoft.com/v1.0/groups/${groupId}/members/$ref`;
    return this.api.request(url, {
      method: 'POST',
      body: { '@odata.id': `https://graph.microsoft.com/v1.0/users/${userId}` }
    }, 'graph');
  }

  async autoRemediate(findings) {
    console.log('🔧 Starting automated remediation...');
    const results = [];

    for (const finding of findings) {
      try {
        let result;
        
        switch (finding.type) {
          case 'COMPROMISED_DEVICE':
            result = await this.isolateMachine(finding.deviceId);
            results.push({ finding, action: 'isolated', result });
            break;
            
          case 'MISSING_MFA':
            results.push({ finding, action: 'ticket_created', note: 'Manual MFA enrollment required' });
            break;
            
          case 'COMPROMISED_USER':
            await this.disableUserAccount(finding.userId);
            await this.revokeUserSessions(finding.userId);
            result = await this.resetUserPassword(finding.userId);
            results.push({ finding, action: 'user_disabled', result });
            break;
            
          case 'MALICIOUS_IP':
            result = await this.blockIndicator(finding.ipAddress, 'IpAddress');
            results.push({ finding, action: 'ip_blocked', result });
            break;
            
          case 'HIGH_SEVERITY_INCIDENT':
            result = await this.updateIncident(finding.incidentId, {
              status: 'Active',
              severity: 'High',
              owner: { assignedTo: 'security-team@company.com' }
            });
            results.push({ finding, action: 'incident_escalated', result });
            break;
        }
      } catch (error) {
        results.push({ finding, action: 'failed', error: error.message });
      }
    }

    console.log(`✅ Remediation complete: ${results.length} actions taken`);
    return results;
  }
}

// ============================================================================
// Feature 3: Continuous Monitoring & Drift Detection
// ============================================================================

class ContinuousMonitor {
  constructor(apiClient, reporter, remediator) {
    this.api = apiClient;
    this.reporter = reporter;
    this.remediator = remediator;
    this.baseline = null;
    this.isRunning = false;
  }

  async setBaseline() {
    console.log('📊 Establishing compliance baseline...');
    this.baseline = await this.reporter.generateComplianceReport();
    console.log('✅ Baseline established');
    return this.baseline;
  }

  async detectDrift() {
    console.log('🔍 Checking for configuration drift...');
    const current = await this.reporter.generateComplianceReport();
    
    const drift = {
      timestamp: new Date().toISOString(),
      changes: [],
      findings: [],
    };

    const newDevices = this.findNewDevices(current.evidence.devices, this.baseline.evidence.devices);
    if (newDevices.length > 0) {
      drift.changes.push({
        type: 'NEW_DEVICES',
        count: newDevices.length,
        devices: newDevices,
      });
    }

    const newIncidents = this.findNewIncidents(current.evidence.incidents, this.baseline.evidence.incidents);
    if (newIncidents.length > 0) {
      drift.changes.push({
        type: 'NEW_INCIDENTS',
        count: newIncidents.length,
        incidents: newIncidents,
      });
      
      for (const incident of newIncidents.filter(i => i.properties?.severity === 'High')) {
        drift.findings.push({
          type: 'HIGH_SEVERITY_INCIDENT',
          incidentId: incident.name,
          severity: incident.properties.severity,
        });
      }
    }

    const newRiskyUsers = this.findNewRiskyUsers(current.evidence.riskyUsers, this.baseline.evidence.riskyUsers);
    if (newRiskyUsers.length > 0) {
      drift.changes.push({
        type: 'RISKY_USERS',
        count: newRiskyUsers.length,
        users: newRiskyUsers,
      });
      
      for (const user of newRiskyUsers.filter(u => u.riskLevel === 'high')) {
        drift.findings.push({
          type: 'COMPROMISED_USER',
          userId: user.id,
          riskLevel: user.riskLevel,
        });
      }
    }

    const newAlerts = this.findNewAlerts(current.evidence.alerts, this.baseline.evidence.alerts);
    if (newAlerts.length > 0) {
      drift.changes.push({
        type: 'NEW_ALERTS',
        count: newAlerts.length,
        alerts: newAlerts.slice(0, 10),
      });
    }

    console.log(`✅ Drift detection complete: ${drift.changes.length} changes found`);
    return drift;
  }

  findNewDevices(current, baseline) {
    if (!baseline?.value) return current?.value || [];
    const baselineIds = new Set(baseline.value.map(d => d.id));
    return (current?.value || []).filter(d => !baselineIds.has(d.id));
  }

  findNewIncidents(current, baseline) {
    if (!baseline?.value) return current?.value || [];
    const baselineIds = new Set(baseline.value.map(i => i.name));
    return (current?.value || []).filter(i => !baselineIds.has(i.name));
  }

  findNewRiskyUsers(current, baseline) {
    if (!baseline?.value) return current?.value || [];
    const baselineIds = new Set(baseline.value.map(u => u.id));
    return (current?.value || []).filter(u => !baselineIds.has(u.id));
  }

  findNewAlerts(current, baseline) {
    if (!baseline?.value) return current?.value || [];
    const baselineIds = new Set(baseline.value.map(a => a.id));
    return (current?.value || []).filter(a => !baselineIds.has(a.id));
  }

  async monitoringLoop() {
    if (this.isRunning) {
      console.log('⚠️  Monitoring already running');
      return;
    }

    this.isRunning = true;
    console.log('🚀 Starting continuous monitoring...');

    while (this.isRunning) {
      try {
        const drift = await this.detectDrift();

        if (drift.findings.length > 0) {
          console.log(`⚠️  Found ${drift.findings.length} issues requiring remediation`);
          await this.remediator.autoRemediate(drift.findings);
        }

        if (drift.changes.length > 0) {
          this.sendAlerts(drift);
        }

        this.baseline = await this.reporter.generateComplianceReport();

      } catch (error) {
        console.error('❌ Monitoring error:', error.message);
      }

      const waitMs = 15 * 60 * 1000;
      console.log(`⏳ Next check in 15 minutes...`);
      await new Promise(resolve => setTimeout(resolve, waitMs));
    }
  }

  sendAlerts(drift) {
    console.log('🚨 DRIFT ALERT:', JSON.stringify(drift, null, 2));
  }

  stop() {
    console.log('🛑 Stopping continuous monitoring...');
    this.isRunning = false;
  }
}

// ============================================================================
// Main Agent Orchestrator - NOW ACCEPTS CREDENTIALS
// ============================================================================

class ComplianceAgent {
  constructor(credentials = {}) {
    this.config = buildConfig(credentials);
    this.auth = new AuthManager(this.config);
    this.api = new ApiClient(this.auth);
    this.reporter = new ComplianceReporter(this.api, this.config);
    this.remediator = new RemediationEngine(this.api, this.config);
    this.monitor = new ContinuousMonitor(this.api, this.reporter, this.remediator);
  }

  async initialize() {
    console.log('🤖 Azure Compliance Agent initializing...');
    await this.monitor.setBaseline();
    console.log('✅ Agent ready');
  }

  async generateReport() {
    return this.reporter.generateComplianceReport();
  }

  async remediate(findings) {
    return this.remediator.autoRemediate(findings);
  }

  async startMonitoring() {
    return this.monitor.monitoringLoop();
  }

  stopMonitoring() {
    this.monitor.stop();
  }

  async checkDrift() {
    return this.monitor.detectDrift();
  }
}

// ============================================================================
// Export
// ============================================================================

module.exports = {
  ComplianceAgent,
  ComplianceReporter,
  RemediationEngine,
  ContinuousMonitor,
  AuthManager,
  ApiClient,
};