// ============================================================================
// Azure Compliance Agent - Complete Implementation
// Features: Compliance Reporting, Automated Remediation, Continuous Monitoring
// ============================================================================

const axios = require('axios');
const msal = require('@azure/msal-node');
require('dotenv').config();
// ============================================================================
// Configuration
// ============================================================================

const config = {
  auth: {
    clientId: process.env.AZURE_CLIENT_ID,
    clientSecret: process.env.AZURE_CLIENT_SECRET,
    tenantId: process.env.AZURE_TENANT_ID,
  },
  resources: {
    defender: process.env.DEFENDER_RESOURCE_ID || 'https://api.securitycenter.microsoft.com',
    sentinel: process.env.SENTINEL_WORKSPACE_ID,
    sentinelResourceGroup: process.env.SENTINEL_RESOURCE_GROUP,
    subscriptionId: process.env.AZURE_SUBSCRIPTION_ID,
    firewallPolicy: process.env.FIREWALL_POLICY_NAME,
    firewallResourceGroup: process.env.FIREWALL_RESOURCE_GROUP,
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

// ============================================================================
// Authentication Manager with Auto-Refresh
// ============================================================================

class AuthManager {
  constructor() {
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
    const result = await this.msalClient.acquireTokenByClientCredential({
      scopes,
    });

    this.tokens[cacheKey] = {
      accessToken: result.accessToken,
      expiresAt: result.expiresOn ? result.expiresOn.getTime() : Date.now() + 3600000,
    };
    console.log("access token", result.accessToken);
    return result.accessToken;
  }

  async getDefenderToken() {
    return this.getToken([`${config.resources.defender}/.default`]);
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
            break;
          case 'graph':
            token = await this.auth.getGraphToken();
            break;
          default:
            token = await this.auth.getManagementToken();
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
  constructor(apiClient) {
    this.api = apiClient;
  }

  // Defender endpoints
  async getDeviceInventory() {
    const url = `${config.resources.defender}/api/machines`;
    return this.api.request(url, {}, 'defender');
  }
  async getSpecificDeviceInventory(machineId) {
    const url = `${config.resources.defender}/api/machines/${machineId}`;
    return this.api.request(url, {}, 'defender');
  }

  async batchUpdateAlert(body) {
  const url = `${config.resources.defender}/api/alerts/batchUpdate`;
  return this.api.request(url, {
    method: 'POST',
    body
  }, 'defender');
}


  async getDeviceHealth() {
    const url = `${config.resources.defender}/api/deviceavinfo`;
    return this.api.request(url, { method: 'GET' }, 'defender');
  }

  async getMachineTag(tag){
    const url = `${config.resources.defender}/api/machines/findbytag?tag=${tag}&useStartsWithFilter={true/false}`;
    return this.api.request(url, {}, 'defender');
  }

  async getSecurityAlerts(filters = {}) {
    const url = `${config.resources.defender}/api/alerts`;
    return this.api.request(url, { params: filters }, 'defender');
  }

  async CreateAlertByRefrence(body) {
  const url = `${config.resources.defender}/api/alerts/createAlertByReference`;
  return this.api.request(url, {
    method: 'POST',
    body
  }, 'defender');
}

  async getVulnerabilities() {
    const url = `${config.resources.defender}/api/vulnerabilities`;
    return this.api.request(url, {}, 'defender');
  }

  async getSecurityRecommendations() {
    const url = `${config.resources.defender}/api/recommendations`;
    return this.api.request(url, {}, 'defender');
  }

  // Sentinel endpoints
  async getSentinelIncidents() {
    const url = `https://management.azure.com/subscriptions/${config.resources.subscriptionId}/resourceGroups/${config.resources.sentinelResourceGroup}/providers/Microsoft.OperationalInsights/workspaces/${config.resources.sentinel}/providers/Microsoft.SecurityInsights/incidents?api-version=2023-02-01`;
    return this.api.request(url);
  }

  async getIncidentAlerts(incidentId) {
    const url = `https://management.azure.com/subscriptions/${config.resources.subscriptionId}/resourceGroups/${config.resources.sentinelResourceGroup}/providers/Microsoft.OperationalInsights/workspaces/${config.resources.sentinel}/providers/Microsoft.SecurityInsights/incidents/${incidentId}/alerts?api-version=2023-02-01`;
    return this.api.request(url, { method: 'POST' });
  }

  async getIncidentEntities(incidentId) {
    const url = `https://management.azure.com/subscriptions/${config.resources.subscriptionId}/resourceGroups/${config.resources.sentinelResourceGroup}/providers/Microsoft.OperationalInsights/workspaces/${config.resources.sentinel}/providers/Microsoft.SecurityInsights/incidents/${incidentId}/entities?api-version=2023-02-01`;
    return this.api.request(url, { method: 'POST' });
  }

  // Firewall endpoints
  async getFirewallPolicies() {
    const url = `https://management.azure.com/subscriptions/${config.resources.subscriptionId}/resourceGroups/${config.resources.firewallResourceGroup}/providers/Microsoft.Network/firewallPolicies?api-version=2023-05-01`;
    return this.api.request(url);
  }

  async getRuleCollectionGroups() {
    const url = `https://management.azure.com/subscriptions/${config.resources.subscriptionId}/resourceGroups/${config.resources.firewallResourceGroup}/providers/Microsoft.Network/firewallPolicies/${config.resources.firewallPolicy}/ruleCollectionGroups?api-version=2023-05-01`;
    return this.api.request(url);
  }

  // Graph endpoints
  async getSignInLogs(filters = {}) {
    const filterQuery = filters.$filter ? `?$filter=${filters.$filter}` : '';
    const url = `https://graph.microsoft.com/v1.0/auditLogs/signIns${filterQuery}`;
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
  const url = `${config.resources.defender}/api/machines/${machineId}/collectInvestigationPackage`;
  return this.api.request(url, { method: "POST", body }, "defender");
  }
  
  async getRiskyUsers() {
    const url = `https://graph.microsoft.com/v1.0/identityProtection/riskyUsers`;
    return this.api.request(url, {}, 'graph');
  }

  
  // Generate compliance report
  // async generateComplianceReport() {
  //   console.log('🔍 Starting compliance evidence collection...');
    
  //   const evidence = {
  //     timestamp: new Date().toISOString(),
  //     devices: await this.getDeviceInventory(),
  //     alerts: await this.getSecurityAlerts(),
  //     vulnerabilities: await this.getVulnerabilities(),
  //     recommendations: await this.getSecurityRecommendations(),
  //     incidents: await this.getSentinelIncidents(),
  //     firewallPolicies: await this.getFirewallPolicies(),
  //     signIns: await this.getSignInLogs(),
  //     directoryAudits: await this.getDirectoryAudits(),
  //     caPolicies: await this.getConditionalAccessPolicies(),
  //     riskyUsers: await this.getRiskyUsers(),
  //   };

  //   // Map to compliance controls (simplified example)
  //   const report = {
  //     metadata: {
  //       generatedAt: evidence.timestamp,
  //       framework: 'UAE IA / ISO 27001 / NESA',
  //       totalControls: 847,
  //     },
  //     summary: {
  //       devicesProtected: evidence.devices?.value?.filter(d => d.healthStatus === 'Active').length || 0,
  //       devicesTotal: evidence.devices?.value?.length || 0,
  //       activeAlerts: evidence.alerts?.value?.filter(a => a.status === 'New').length || 0,
  //       criticalVulnerabilities: evidence.vulnerabilities?.value?.filter(v => v.severity === 'Critical').length || 0,
  //       mfaCompliance: this.calculateMfaCompliance(evidence),
  //     },
  //     evidence,
  //   };

  //   console.log('✅ Compliance report generated');
  //   return report;
  // }
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
  if (config.resources.sentinel && config.resources.sentinelResourceGroup) {
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

  // Firewall APIs (skip if not configured) - COMMENTED OUT
  if (config.resources.firewallPolicy && config.resources.firewallResourceGroup) {
    try {
      evidence.firewallPolicies = await this.getFirewallPolicies();
    } catch (error) {
      console.warn('⚠️  Could not get firewall policies:', error.message);
      evidence.firewallPolicies = { value: [] };
    }
  } else {
    evidence.firewallPolicies = { value: [] };
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
      mfaCompliance: this.calculateMfaCompliance(evidence),
    },
    evidence,
  };

  console.log('✅ Compliance report generated (with available data)');
  return report;
}

  calculateMfaCompliance(evidence) {
    // Placeholder - would need to fetch all users and check auth methods
    return {
      compliant: 0,
      nonCompliant: 0,
      percentage: 0,
    };
  }
}

// ============================================================================
// Feature 2: Automated Remediation
// ============================================================================

class RemediationEngine {
  constructor(apiClient) {
    this.api = apiClient;
  }

  // Defender remediation actions
  async isolateMachine(machineId, comment = 'Automated isolation due to security threat') {
    const url = `${config.resources.defender}/api/machines/${machineId}/isolate`;
    return this.api.request(url, {
      method: 'POST',
      body: { Comment: comment, IsolationType: 'Full' }
    }, 'defender');
  }

  async unisolateMachine(machineId, comment = 'Device remediated and cleared') {
    const url = `${config.resources.defender}/api/machines/${machineId}/unisolate`;
    return this.api.request(url, {
      method: 'POST',
      body: { Comment: comment }
    }, 'defender');
  }

  async runAntiVirusScan(machineId, scanType = 'Full') {
    const url = `${config.resources.defender}/api/machines/${machineId}/runAntiVirusScan`;
    return this.api.request(url, {
      method: 'POST',
      body: { Comment: 'Automated security scan', ScanType: scanType }
    }, 'defender');
  }

  async quarantineFile(machineId, filePath, comment = 'Malicious file detected') {
    const url = `${config.resources.defender}/api/machines/${machineId}/stopAndQuarantineFile`;
    return this.api.request(url, {
      method: 'POST',
      body: { Comment: comment, FilePath: filePath }
    }, 'defender');
  }

  async restrictCodeExecution(machineId) {
    const url = `${config.resources.defender}/api/machines/${machineId}/restrictCodeExecution`;
    return this.api.request(url, {
      method: 'POST',
      body: { Comment: 'Restricting untrusted apps' }
    }, 'defender');
  }

  async collectInvestigationPackage(machineId, body = {}) {
  const url = `${config.resources.defender}/api/machines/${machineId}/collectInvestigationPackage`;
  return this.api.request(url, { method: "POST", body }, "defender");
}

async unrestrictCodeExecution(machineId, body = {}) {
  const url = `${config.resources.defender}/api/machines/${machineId}/unrestrictCodeExecution`;
  return this.api.request(url, { method: "POST", body }, "defender");
}

async offboardMachine(machineId, body = {}) {
  const url = `${config.resources.defender}/api/machines/${machineId}/offboard`;
  return this.api.request(url, { method: "POST", body }, "defender");
}

async runLiveResponse(machineId, body) {
  const url = `${config.resources.defender}/api/machines/${machineId}/runliveresponse`;
  return this.api.request(url, { method: "POST", body }, "defender");
}

  async blockIndicator(indicatorValue, indicatorType, action = 'Block', title = 'Automated threat block') {
    const url = `${config.resources.defender}/api/indicators`;
    return this.api.request(url, {
      method: 'POST',
      body: {
        indicatorValue,
        indicatorType, // 'IpAddress', 'DomainName', 'FileSha256'
        action, // 'Alert', 'Block', 'Allowed'
        title,
        description: 'Automated threat intelligence block',
        severity: 'High',
      }
    }, 'defender');
  }

  // Sentinel remediation actions
  async updateIncident(incidentId, updates) {
    const url = `https://management.azure.com/subscriptions/${config.resources.subscriptionId}/resourceGroups/${config.resources.sentinelResourceGroup}/providers/Microsoft.OperationalInsights/workspaces/${config.resources.sentinel}/providers/Microsoft.SecurityInsights/incidents/${incidentId}?api-version=2023-02-01`;
    return this.api.request(url, {
      method: 'PUT',
      body: { properties: updates }
    });
  }

  async runPlaybook(incidentId, logicAppResourceId) {
    const url = `https://management.azure.com/subscriptions/${config.resources.subscriptionId}/resourceGroups/${config.resources.sentinelResourceGroup}/providers/Microsoft.OperationalInsights/workspaces/${config.resources.sentinel}/providers/Microsoft.SecurityInsights/incidents/${incidentId}/runPlaybook?api-version=2023-02-01`;
    return this.api.request(url, {
      method: 'POST',
      body: { logicAppsResourceId: logicAppResourceId }
    });
  }

  // Firewall remediation actions
  async updateFirewallRules(ruleCollectionGroupName, rules) {
    const url = `https://management.azure.com/subscriptions/${config.resources.subscriptionId}/resourceGroups/${config.resources.firewallResourceGroup}/providers/Microsoft.Network/firewallPolicies/${config.resources.firewallPolicy}/ruleCollectionGroups/${ruleCollectionGroupName}?api-version=2023-05-01`;
    return this.api.request(url, {
      method: 'PUT',
      body: { properties: { ruleCollections: rules } }
    });
  }

  // Graph remediation actions
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

  // Orchestration: Auto-remediate based on findings
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
            // This would need phone number - typically create ticket instead
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

    // Check for new unprotected devices
    const newDevices = this.findNewDevices(current.evidence.devices, this.baseline.evidence.devices);
    if (newDevices.length > 0) {
      drift.changes.push({
        type: 'NEW_DEVICES',
        count: newDevices.length,
        devices: newDevices,
      });
    }

    // Check for new high-severity incidents
    const newIncidents = this.findNewIncidents(current.evidence.incidents, this.baseline.evidence.incidents);
    if (newIncidents.length > 0) {
      drift.changes.push({
        type: 'NEW_INCIDENTS',
        count: newIncidents.length,
        incidents: newIncidents,
      });
      
      // Auto-remediate high severity
      for (const incident of newIncidents.filter(i => i.properties?.severity === 'High')) {
        drift.findings.push({
          type: 'HIGH_SEVERITY_INCIDENT',
          incidentId: incident.name,
          severity: incident.properties.severity,
        });
      }
    }

    // Check for newly risky users
    const newRiskyUsers = this.findNewRiskyUsers(current.evidence.riskyUsers, this.baseline.evidence.riskyUsers);
    if (newRiskyUsers.length > 0) {
      drift.changes.push({
        type: 'RISKY_USERS',
        count: newRiskyUsers.length,
        users: newRiskyUsers,
      });
      
      // Flag for remediation
      for (const user of newRiskyUsers.filter(u => u.riskLevel === 'high')) {
        drift.findings.push({
          type: 'COMPROMISED_USER',
          userId: user.id,
          riskLevel: user.riskLevel,
        });
      }
    }

    // Check for new critical alerts
    const newAlerts = this.findNewAlerts(current.evidence.alerts, this.baseline.evidence.alerts);
    if (newAlerts.length > 0) {
      drift.changes.push({
        type: 'NEW_ALERTS',
        count: newAlerts.length,
        alerts: newAlerts.slice(0, 10), // Limit output
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
        // Detect drift
        const drift = await this.detectDrift();

        // Auto-remediate findings
        if (drift.findings.length > 0) {
          console.log(`⚠️  Found ${drift.findings.length} issues requiring remediation`);
          await this.remediator.autoRemediate(drift.findings);
        }

        // Send alerts if thresholds exceeded
        if (drift.changes.length > 0) {
          this.sendAlerts(drift);
        }

        // Update baseline
        this.baseline = await this.reporter.generateComplianceReport();

      } catch (error) {
        console.error('❌ Monitoring error:', error.message);
      }

      // Wait for next interval
      const waitMs = config.monitoring.pollingIntervalMinutes * 60 * 1000;
      console.log(`⏳ Next check in ${config.monitoring.pollingIntervalMinutes} minutes...`);
      await new Promise(resolve => setTimeout(resolve, waitMs));
    }
  }

  sendAlerts(drift) {
    // Placeholder - would integrate with alerting system
    console.log('🚨 DRIFT ALERT:', JSON.stringify(drift, null, 2));
  }

  stop() {
    console.log('🛑 Stopping continuous monitoring...');
    this.isRunning = false;
  }
}

// ============================================================================
// Main Agent Orchestrator
// ============================================================================

class ComplianceAgent {
  constructor() {
    this.auth = new AuthManager();
    this.api = new ApiClient(this.auth);
    this.reporter = new ComplianceReporter(this.api);
    this.remediator = new RemediationEngine(this.api);
    this.monitor = new ContinuousMonitor(this.api, this.reporter, this.remediator);
  }

  async initialize() {
    console.log('🤖 Azure Compliance Agent initializing...');
    await this.monitor.setBaseline();
    console.log('✅ Agent ready');
  }

  // Public API
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
// Usage Example
// ============================================================================

async function main() {
  try {
    // Initialize agent
    const agent = new ComplianceAgent();
    await agent.initialize();

    // Generate compliance report
    const report = await agent.generateReport();
    console.log('Compliance Summary:', report.summary);

    // Check for drift
    const drift = await agent.checkDrift();
    console.log('Drift detected:', drift.changes.length, 'changes');

    // Start continuous monitoring (runs indefinitely)
    // await agent.startMonitoring();

  } catch (error) {
    console.error('Error:', error.message);
  }
}

// Export for use as module
module.exports = {
  ComplianceAgent,
  ComplianceReporter,
  RemediationEngine,
  ContinuousMonitor,
  AuthManager,
  ApiClient,
};

// Run if executed directly
if (require.main === module) {
  main();
}