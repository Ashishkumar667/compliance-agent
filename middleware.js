// ============================================================================
// Header-Based Authentication Middleware
// Allows users to pass Azure credentials via headers instead of .env
// ============================================================================

const { ComplianceAgent } = require('./compliance-agent');
require('dotenv').config();

// Cache agents per tenant to avoid re-initialization
const agentCache = new Map();
const CACHE_TTL = 30 * 60 * 1000; // 30 minutes

// ============================================================================
// Extract and Validate Headers
// ============================================================================



function extractCredentials(req) {
  const getValidValue = (headerValue, envValue) => {
    // If header has a real value (not undefined/null/empty string), use it
    if (headerValue && headerValue !== 'undefined' && headerValue !== 'null' && headerValue.trim() !== '') {
      return headerValue;
    }
    // Otherwise fall back to env
     return envValue || undefined;
  }

  const credentials = {
    clientId: req.headers['x-azure-client-id'] || process.env.AZURE_CLIENT_ID,
    clientSecret: req.headers['x-azure-client-secret'] || process.env.AZURE_CLIENT_SECRET,
    tenantId: req.headers['x-azure-tenant-id'] || process.env.AZURE_TENANT_ID,
    subscriptionId: req.headers['x-azure-subscription-id'] || process.env.AZURE_SUBSCRIPTION_ID,
    
    // Optional: Sentinel configuration
    sentinelWorkspaceId: getValidValue(req.headers['x-sentinel-workspace-id'], process.env.SENTINEL_WORKSPACE_ID),
    sentinelResourceGroup: getValidValue(req.headers['x-sentinel-resource-group'], process.env.SENTINEL_RESOURCE_GROUP),
    
    // Optional: Firewall configuration
    firewallPolicy: getValidValue(req.headers['x-firewall-policy'], process.env.FIREWALL_POLICY_NAME),
    firewallResourceGroup: getValidValue(req.headers['x-firewall-resource-group'], process.env.FIREWALL_RESOURCE_GROUP),
    // Optional: Defender resource ID
    defenderResourceId: req.headers['x-defender-resource-id'] || process.env.DEFENDER_RESOURCE_ID,
  };

  return credentials;
}

function validateCredentials(credentials) {
  const required = ['clientId', 'clientSecret', 'tenantId'];
  const missing = required.filter(field => !credentials[field]);
  
  if (missing.length > 0) {
    throw new Error(`Missing required credentials: ${missing.join(', ')}. ` +
      `Provide via headers (x-azure-client-id, x-azure-client-secret, x-azure-tenant-id) ` +
      `or environment variables.`);
  }
  
  return true;
}

// ============================================================================
// Agent Factory with Caching
// ============================================================================

function getCacheKey(credentials) {
  // Create unique key based on tenant + client
  return `${credentials.tenantId}:${credentials.clientId}`;
}

async function getOrCreateAgent(credentials) {
  const cacheKey = getCacheKey(credentials);
  
  // Check cache
  const cached = agentCache.get(cacheKey);
  if (cached && (Date.now() - cached.timestamp < CACHE_TTL)) {
    console.log(`♻️  Using cached agent for tenant: ${credentials.tenantId.substring(0, 8)}...`);
    return cached.agent;
  }

  // Create new agent with custom config
  console.log(`🔨 Creating new agent for tenant: ${credentials.tenantId.substring(0, 8)}...`);
  
  try {
    // Create agent with passed credentials
    const agent = new ComplianceAgent(credentials);
    await agent.initialize();
    
    // Cache the agent
    agentCache.set(cacheKey, {
      agent,
      timestamp: Date.now(),
      credentials: {
        tenantId: credentials.tenantId,
        clientId: credentials.clientId,
      }
    });
    
    console.log(`✅ Agent created and cached for tenant: ${credentials.tenantId.substring(0, 8)}...`);
    return agent;
    
  } catch (error) {
    console.error(`❌ Failed to create agent for tenant ${credentials.tenantId}:`, error.message);
    throw error;
  }
}

// ============================================================================
// Middleware Function
// ============================================================================

async function authenticateRequest(req, res, next) {
  try {
    // Extract credentials from headers or env
    const credentials = extractCredentials(req);
    
    // Validate required fields
    validateCredentials(credentials);
    
    // Get or create agent for this tenant
    const agent = await getOrCreateAgent(credentials);
    
    // Attach agent to request object
    req.complianceAgent = agent;
    req.credentials = {
      tenantId: credentials.tenantId,
      clientId: credentials.clientId,
    };
    
    next();
  } catch (error) {
    console.error('Authentication error:', error.message);
    return res.status(401).json({
      success: false,
      error: error.message,
      hint: 'Provide Azure credentials via headers: x-azure-client-id, x-azure-client-secret, x-azure-tenant-id',
      timestamp: new Date().toISOString(),
    });
  }
}

// ============================================================================
// Cache Management
// ============================================================================

function clearCache(tenantId = null) {
  if (tenantId) {
    // Clear specific tenant
    const keysToDelete = [];
    for (const [key, value] of agentCache.entries()) {
      if (value.credentials.tenantId === tenantId) {
        keysToDelete.push(key);
      }
    }
    keysToDelete.forEach(key => agentCache.delete(key));
    console.log(`🗑️  Cleared cache for tenant: ${tenantId}`);
  } else {
    // Clear all
    agentCache.clear();
    console.log('🗑️  Cleared entire agent cache');
  }
}

function getCacheStats() {
  const stats = {
    totalCached: agentCache.size,
    tenants: []
  };
  
  for (const [key, value] of agentCache.entries()) {
    stats.tenants.push({
      tenantId: value.credentials.tenantId,
      clientId: value.credentials.clientId,
      cachedAt: new Date(value.timestamp).toISOString(),
      age: Math.floor((Date.now() - value.timestamp) / 1000) + 's',
    });
  }
  
  return stats;
}

// Periodic cleanup of expired cache entries
setInterval(() => {
  const now = Date.now();
  const keysToDelete = [];
  
  for (const [key, value] of agentCache.entries()) {
    if (now - value.timestamp > CACHE_TTL) {
      keysToDelete.push(key);
    }
  }
  
  if (keysToDelete.length > 0) {
    keysToDelete.forEach(key => agentCache.delete(key));
    console.log(`🧹 Cleaned up ${keysToDelete.length} expired cache entries`);
  }
}, 10 * 60 * 1000); // Every 10 minutes

// ============================================================================
// Export
// ============================================================================

module.exports = {
  authenticateRequest,
  extractCredentials,
  validateCredentials,
  clearCache,
  getCacheStats,
};