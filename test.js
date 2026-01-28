// ============================================================================
// Azure Compliance Agent - REST API Server
// Exposes all compliance features via REST endpoints
// Includes 24/7 background monitoring
// NOW WITH HEADER-BASED AUTHENTICATION
// ============================================================================

const express = require('express');
const helmet = require('helmet');
const morgan = require('morgan');
const axios = require('axios');
const { authenticateRequest, clearCache, getCacheStats } = require('./middleware');
require('dotenv').config();

// ============================================================================
// Server Configuration
// ============================================================================

const app = express();
const PORT = process.env.PORT || 3000;

// Global monitoring state (per tenant tracking)
const monitoringTasks = new Map(); // tenant -> monitoringTask
const monitoringStatuses = new Map(); // tenant -> status

// ============================================================================
// Middleware
// ============================================================================

app.use(helmet());
app.use(express.json({ limit: '50mb' }));
app.use(morgan('combined'));

// Apply authentication middleware to all /api routes
app.use('/api', authenticateRequest);

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(err.status || 500).json({
    success: false,
    error: err.message || 'Internal server error',
    timestamp: new Date().toISOString(),
  });
});

// ============================================================================
// Helper Functions
// ============================================================================

// xAI Grok Summarization Helper
async function summarizeWithGrok(data, context = 'devices') {
  if (!process.env.XAI_API_KEY) {
    console.warn('⚠️  XAI_API_KEY not set, skipping AI summarization');
    return null;
  }

  try {
    const prompt = `You are a cybersecurity analyst. Analyze this Azure ${context} data and provide:

1. **Executive Summary** (2-3 sentences)
2. **Key Findings** (bullet points)
3. **Risk Assessment** (High/Medium/Low with brief explanation)
4. **Top Recommendations** (3-5 actionable items)

Data to analyze:
\`\`\`json
${JSON.stringify(data, null, 2).substring(0, 50000)}
\`\`\`

Respond in clean JSON format:
{
  "summary": "...",
  "findings": ["...", "..."],
  "riskLevel": "High|Medium|Low",
  "riskExplanation": "...",
  "recommendations": ["...", "..."]
}`;

    const response = await axios.post(
  "https://api.x.ai/v1/responses",
  {
    model: "grok-4-1-fast-non-reasoning",
    input: prompt,
    temperature: 0.3
  },
  {
    headers: {
      Authorization: `Bearer ${process.env.XAI_API_KEY}`,
      "Content-Type": "application/json"
    },
    timeout: 30000
  }
);

    console.log("Grok ai response", response.data);
   const message = response.data.output[0];

if (!message || !Array.isArray(message.content)) {
  throw new Error("Invalid Grok response structure");
}

const textBlock = message.content.find(c => c.type === "output_text");

if (!textBlock || typeof textBlock.text !== "string") {
  throw new Error("No output_text found in Grok response");
}

const cleanContent = textBlock.text
  .replace(/```json\n?/gi, "")
  .replace(/```\n?/gi, "")
  .trim();

return JSON.parse(cleanContent);

  } catch (error) {
    console.error('❌ Grok summarization failed:', error.message);
    return null;
  }
}

// Check if response should be summarized (based on size threshold)
function shouldSummarize(req, dataLength) {
  // Check if client explicitly requests summarization
  if (req.query.summarize === 'true' || req.headers['x-summarize'] === 'true') {
    return true;
  }
  
  // Auto-summarize if data is large (default: 100 items)
  const threshold = parseInt(req.query.summarize_threshold) || 100;
  return dataLength > threshold;
}


function getMonitoringStatus(tenantId) {
  if (!monitoringStatuses.has(tenantId)) {
    monitoringStatuses.set(tenantId, {
      isRunning: false,
      startedAt: null,
      lastCheckAt: null,
      checksPerformed: 0,
      issuesFound: 0,
      remediationsApplied: 0,
      errors: [],
    });
  }
  return monitoringStatuses.get(tenantId);
}

// 24/7 Background Monitoring Function (per tenant)
async function startBackgroundMonitoring(agent, tenantId) {
  const status = getMonitoringStatus(tenantId);
  
  if (status.isRunning) {
    console.log(`⚠️  Background monitoring already running for tenant: ${tenantId}`);
    return;
  }

  status.isRunning = true;
  status.startedAt = new Date().toISOString();
  
  console.log(`🚀 Starting 24/7 background monitoring for tenant: ${tenantId}...`);

  // Run monitoring in background (non-blocking)
  const monitoringTask = (async () => {
    const pollingInterval = (process.env.MONITORING_INTERVAL_MINUTES || 15) * 60 * 1000;
    
    while (status.isRunning) {
      try {
        status.lastCheckAt = new Date().toISOString();
        status.checksPerformed++;

        console.log(`[${new Date().toISOString()}] 🔍 Running scheduled compliance check #${status.checksPerformed} for ${tenantId}`);

        // Detect drift
        const drift = await agent.checkDrift();
        
        if (drift.findings.length > 0) {
          console.log(`⚠️  Found ${drift.findings.length} security issues`);
          status.issuesFound += drift.findings.length;

          // Auto-remediate
          const remediationResults = await agent.remediate(drift.findings);
          const successfulRemediations = remediationResults.filter(r => r.action !== 'failed').length;
          status.remediationsApplied += successfulRemediations;

          console.log(`✅ Applied ${successfulRemediations} automated remediations`);

          // Log failures
          const failures = remediationResults.filter(r => r.action === 'failed');
          if (failures.length > 0) {
            console.error('❌ Remediation failures:', failures);
          }
        } else {
          console.log('✅ No drift detected, environment compliant');
        }

      } catch (error) {
        console.error('❌ Monitoring error:', error.message);
        status.errors.push({
          timestamp: new Date().toISOString(),
          error: error.message,
          stack: error.stack,
        });
        
        // Keep only last 50 errors
        if (status.errors.length > 50) {
          status.errors = status.errors.slice(-50);
        }
      }

      // Wait for next interval
      console.log(`⏳ Next check in ${process.env.MONITORING_INTERVAL_MINUTES || 15} minutes...`);
      await new Promise(resolve => setTimeout(resolve, pollingInterval));
    }
  })();

  monitoringTasks.set(tenantId, monitoringTask);
}

function stopBackgroundMonitoring(tenantId) {
  const status = getMonitoringStatus(tenantId);
  
  if (!status.isRunning) {
    console.log(`⚠️  Background monitoring not running for tenant: ${tenantId}`);
    return;
  }

  console.log(`🛑 Stopping background monitoring for tenant: ${tenantId}...`);
  status.isRunning = false;
  monitoringTasks.delete(tenantId);
}

// ============================================================================
// API Routes
// ============================================================================

// Health check (no auth required)
app.get('/health', (req, res) => {
  res.json({
    success: true,
    status: 'healthy',
    timestamp: new Date().toISOString(),
    cacheStats: getCacheStats(),
  });
});

// Cache management endpoints
app.post('/admin/cache/clear', (req, res) => {
  const { tenantId } = req.body;
  clearCache(tenantId);
  res.json({
    success: true,
    message: tenantId ? `Cache cleared for tenant: ${tenantId}` : 'All cache cleared',
    timestamp: new Date().toISOString(),
  });
});

app.get('/admin/cache/stats', (req, res) => {
  res.json({
    success: true,
    data: getCacheStats(),
    timestamp: new Date().toISOString(),
  });
});

// ============================================================================
// Feature 1: Compliance Reporting Endpoints
// ============================================================================

/**
 * GET /api/compliance/report
 * Generate full compliance report with evidence from all sources
 */
app.get('/api/compliance/report', async (req, res, next) => {
  try {
    const agent = req.complianceAgent;
    const report = await agent.generateReport();

    let data = [];

    // Handle all common shapes
    if (Array.isArray(report)) {
      data = report;
    } 
    else if (report && Array.isArray(report.data)) {
      data = report.data;
    }
    else if (report && Array.isArray(report.value)) {
      data = report.value;
    }
    else if (report && typeof report === 'object') {
      data = report;
    }

    res.json({
      success: true,
      data,
      tenant: req.credentials.tenantId,
      timestamp: new Date().toISOString(),
    });

  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/compliance/devices
 * Get device inventory and health status
 */
app.get('/api/compliance/devices', async (req, res, next) => {
  try {
    const agent = req.complianceAgent;
    const devices = await agent.reporter.getDeviceInventory();

    let data = [];

    // Handle all possible structures
    if (Array.isArray(devices)) {
      data = devices;
    } else if (devices && Array.isArray(devices.data)) {
      data = devices.data;
    } else if (devices && Array.isArray(devices.value)) {
      data = devices.value;
    } else if (devices && typeof devices === 'object') {
      data = Object.values(devices);
    }

    if (shouldSummarize(req, data.length)) {
      console.log(`🤖 Summarizing ${data.length} devices with Grok AI...`);
      
      const summary = await summarizeWithGrok(data, 'devices');
      
      if (summary) {
        return res.json({
          success: true,
          summarized: true,
          aiSummary: summary,
          stats: {
            totalDevices: data.length,
            activeDevices: data.filter(d => d.healthStatus === 'Active').length,
            riskyDevices: data.filter(d => d.riskScore === 'High').length,
          },
          tenant: req.credentials.tenantId,
          timestamp: new Date().toISOString(),
          note: 'AI-generated summary. Use ?summarize=false to get full data.',
        });
      }
    }

    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 5000;

    const startIndex = (page - 1) * limit;
    const endIndex = page * limit;

    const paginated = data.slice(startIndex, endIndex);

    res.json({
      success: true,
      data: paginated,
      pagination: {
        page,
        limit,
        total: data.length,
        pages: Math.ceil(data.length / limit),
      },
      tenant: req.credentials.tenantId,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

app.get('/api/compliance/devices/:id', async (req, res, next) => {
  try {
    const agent = req.complianceAgent;
    const device = await agent.reporter.getSpecificDeviceInventory(req.params.id);
    res.json({
      success: true,
      data: device,
      tenant: req.credentials.tenantId,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/compliance/alerts/batch-update
 * Batch update Defender alerts
 */
app.post('/api/compliance/alerts/batch-update', async (req, res, next) => {
  try {
    const agent = req.complianceAgent;
    const payload = req.body;

    if (!payload || !Array.isArray(payload.alertIds) || payload.alertIds.length === 0) {
      return res.status(400).json({
        success: false,
        message: "alertIds[] is required and must contain at least one alert ID"
      });
    }

    const result = await agent.reporter.batchUpdateAlert(payload);

    let data = [];
    if (Array.isArray(result)) data = result;
    else if (result?.data) data = result.data;
    else if (result?.value) data = result.value;
    else if (typeof result === "object") data = result;

    res.json({
      success: true,
      data,
      tenant: req.credentials.tenantId,
      timestamp: new Date().toISOString(),
    });

  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/compliance/alerts
 * Get security alerts with optional filters
 */
app.get('/api/compliance/alerts', async (req, res, next) => {
  try {
    const agent = req.complianceAgent;
    const filters = {};

    if (req.query.status) {
      filters.$filter = `status eq '${req.query.status}'`;
    }

    if (req.query.severity) {
      filters.$filter = filters.$filter
        ? `${filters.$filter} and severity eq '${req.query.severity}'`
        : `severity eq '${req.query.severity}'`;
    }

    const alerts = await agent.reporter.getSecurityAlerts(filters);

    let data = [];

    if (Array.isArray(alerts)) {
      data = alerts;
    } 
    else if (alerts && Array.isArray(alerts.data)) {
      data = alerts.data;
    }
    else if (alerts && Array.isArray(alerts.value)) {
      data = alerts.value;
    }
    else if (alerts && Array.isArray(alerts.alerts)) {
      data = alerts.alerts;
    }
    else if (alerts && typeof alerts === "object") {
      data = Object.values(alerts);
    }

    res.json({
      success: true,
      data,
      filtersApplied: filters,
      tenant: req.credentials.tenantId,
      timestamp: new Date().toISOString(),
    });

  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/compliance/createalertbyref
 * Create alert by reference
 */
app.post('/api/compliance/createalertbyref', async (req, res, next) => {
  try {
    const agent = req.complianceAgent;
    const payload = req.body;

    if (!payload || !payload.machineId) {
      return res.status(400).json({
        success: false,
        message: "machineId is required"
      });
    }

    const created = await agent.reporter.CreateAlertByRefrence(payload);

    let data = [];

    if (Array.isArray(created)) data = created;
    else if (created?.data) data = created.data;
    else if (created?.value) data = created.value;
    else if (typeof created === "object") data = created;

    res.json({
      success: true,
      data,
      tenant: req.credentials.tenantId,
      timestamp: new Date().toISOString(),
    });

  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/compliance/incidents
 * Get Sentinel security incidents
 */
app.get('/api/compliance/incidents', async (req, res, next) => {
  try {
    const agent = req.complianceAgent;
    const incidents = await agent.reporter.getSentinelIncidents();
    
    res.json({
      success: true,
      data: incidents,
      tenant: req.credentials.tenantId,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/compliance/incidents/:id/details
 * Get incident alerts and entities
 */
app.get('/api/compliance/incidents/:id/details', async (req, res, next) => {
  try {
    const agent = req.complianceAgent;
    const [alerts, entities] = await Promise.all([
      agent.reporter.getIncidentAlerts(req.params.id),
      agent.reporter.getIncidentEntities(req.params.id),
    ]);
    
    res.json({
      success: true,
      data: { alerts, entities },
      tenant: req.credentials.tenantId,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/compliance/machines/:id/collect-investigation
 */
app.post('/api/compliance/machines/:id/collect-investigation', async (req, res, next) => {
  try {
    const agent = req.complianceAgent;
    const comment = req.body.Comment;
    const result = await agent.reporter.collectInvestigationPackage(req.params.id, comment);
    console.log('Investigation package result:', result)

    res.json({
      success: true,
      data: result,
      tenant: req.credentials.tenantId,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    next(err);
  }
});

/**
 * POST /api/compliance/deviceHealth
 */
app.post('/api/compliance/deviceHealth', async (req, res, next) => {
  try {
    const agent = req.complianceAgent;
    const result = await agent.reporter.getDeviceHealth();

    res.json({
      success: true,
      data: result,
      tenant: req.credentials.tenantId,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/compliance/recommendations
 * Get security recommendations
 */
app.get('/api/compliance/recommendations', async (req, res, next) => {
  try {
    const agent = req.complianceAgent;
    const recommendations = await agent.reporter.getSecurityRecommendations();

    let data = [];

    if (Array.isArray(recommendations)) data = recommendations;
    else if (recommendations?.data) data = recommendations.data;
    else if (recommendations?.value) data = recommendations.value;
    else if (typeof recommendations === "object") data = Object.values(recommendations);

    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 2500;

    const paginated = data.slice((page - 1) * limit, page * limit);

    res.json({
      success: true,
      data: paginated,
      pagination: {
        page,
        limit,
        total: data.length,
        pages: Math.ceil(data.length / limit),
      },
      tenant: req.credentials.tenantId,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/compliance/machine/tags
 */
app.get('/api/compliance/machine/tags', async(req, res, next) => {
  try {
    const agent = req.complianceAgent;
    const tag = req.query.tag;
    if(!tag){
        return res.status(400).json({
            success: false,
            error: 'tag query parameter is required',
            timestamp: new Date().toISOString(),
        });
    }
    const tags = await agent.reporter.getMachineTag(tag);

    res.json({
      success: true,
      data: tags,
      tenant: req.credentials.tenantId,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/compliance/vulnerabilities
 */
app.get('/api/compliance/vulnerabilities', async (req, res, next) => {
  try {
    const agent = req.complianceAgent;
    const summarizer = req.query.summarizer;
    const vulns = await agent.reporter.getVulnerabilities();

    let data = [];

    if (Array.isArray(vulns)) data = vulns;
    else if (Array.isArray(vulns?.value)) data = vulns.value;
    else if (Array.isArray(vulns?.data)) data = vulns.data;
    else if (typeof vulns === "object") data = Object.values(vulns);

    // Apply severity filter if provided
    if (req.query.severity) {
      data = data.filter(v => 
        v.severity && v.severity.toLowerCase() === req.query.severity.toLowerCase()
      );
    }
    if(summarizer == "true"){
      console.log(`🤖 Summarizing ${data.length} vulnerabilities with Grok AI...`);
    // Check if we should summarize
    if (shouldSummarize(req, data.length)) {
      console.log(`🤖 Summarizing ${data.length} vulnerabilities with Grok AI...`);
      
      const summary = await summarizeWithGrok(data.slice(0, 500), 'vulnerabilities'); // Limit to first 500 for AI
      
      if (summary) {
        return res.json({
          success: true,
          summarized: true,
          aiSummary: summary,
          stats: {
            totalVulnerabilities: data.length,
            critical: data.filter(v => v.severity === 'Critical').length,
            high: data.filter(v => v.severity === 'High').length,
            medium: data.filter(v => v.severity === 'Medium').length,
            low: data.filter(v => v.severity === 'Low').length,
          },
          tenant: req.credentials.tenantId,
          timestamp: new Date().toISOString(),
          note: 'AI-generated summary based on first 500 items. Use ?summarize=false for full data.',
        });
      }
    }
 }
    // Pagination with validation
    const page = Math.max(parseInt(req.query.page) || 1, 1);
    const limit = Math.min(Math.max(parseInt(req.query.limit) || 100, 1), 5000);
    
    const totalPages = Math.ceil(data.length / limit);
    
    // Validate page number
    const validPage = Math.min(page, Math.max(totalPages, 1));
    
    const startIndex = (validPage - 1) * limit;
    const endIndex = startIndex + limit;
    const paginated = data.slice(startIndex, endIndex);

    // Build response with navigation links
    const baseUrl = `${req.protocol}://${req.get('host')}${req.path}`;
    const queryParams = new URLSearchParams();
    if (req.query.severity) queryParams.set('severity', req.query.severity);
    queryParams.set('limit', limit.toString());

    const links = {
      self: `${baseUrl}?${queryParams.toString()}&page=${validPage}`,
      first: `${baseUrl}?${queryParams.toString()}&page=1`,
      last: `${baseUrl}?${queryParams.toString()}&page=${totalPages}`,
    };

    if (validPage > 1) {
      links.prev = `${baseUrl}?${queryParams.toString()}&page=${validPage - 1}`;
    }
    if (validPage < totalPages) {
      links.next = `${baseUrl}?${queryParams.toString()}&page=${validPage + 1}`;
    }

    res.json({
      success: true,
      data: paginated,
      pagination: {
        page: validPage,
        limit,
        total: data.length,
        totalPages,
        hasNext: validPage < totalPages,
        hasPrev: validPage > 1,
        from: startIndex + 1,
        to: Math.min(endIndex, data.length),
      },
      links,
      tenant: req.credentials.tenantId,
      timestamp: new Date().toISOString(),
    });

  } catch (error) {
    next(error);
  }
});


/**
 * GET /api/compliance/risky-users
 */
app.get('/api/compliance/risky-users', async (req, res, next) => {
  try {
    const agent = req.complianceAgent;
    const riskyUsers = await agent.reporter.getRiskyUsers();
        
    res.json({
      success: true,
      data: riskyUsers,
      tenant: req.credentials.tenantId,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/compliance/firewall-policies
 */
app.get('/api/compliance/firewall-policies', async (req, res, next) => {
  try {
    const agent = req.complianceAgent;
    const [policies, rules] = await Promise.all([
      agent.reporter.getFirewallPolicies(),
      agent.reporter.getRuleCollectionGroups(),
    ]);
    
    res.json({
      success: true,
      data: { policies, rules },
      tenant: req.credentials.tenantId,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

app.post('/api/compliance/firewall/idps/signatures', async (req, res, next) => {
  try {
    const agent = req.complianceAgent;

    const {
      filters = [],
      search = "",
      orderBy = null,
      resultsPerPage = 20,
      skip = 0
    } = req.body;

    const signatures = await agent.reporter.listIdpsSignatures(
      filters,
      search,
      orderBy,
      resultsPerPage,
      skip
    );
    console.log('Signatures response:', signatures);
    res.json({
      success: true,
      data: signatures,
      tenant: req.credentials.tenantId,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    next(error);
  }
});

app.get('/api/compliance/firewall/ip-configurations', async (req, res, next) => {
  try {
    const agent = req.complianceAgent;
    
    const config = await agent.reporter.getFirewallIpConfigurations();
    
    res.json({
      success: true,
      data: config,
      tenant: req.credentials.tenantId,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Firewall IP config error:', error.message);
    next(error);
  }
});

app.get('/api/compliance/network-security-groups', async (req, res, next) => {
  try {
    const agent = req.complianceAgent;
    
    console.log('🛡️  Fetching all Network Security Groups...');
    
    const nsgs = await agent.reporter.getNetworkSecurityGroups();
    
    res.json({
      success: true,
      data: nsgs,
      count: nsgs.value?.length || 0,
      tenant: req.credentials.tenantId,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('NSG list error:', error.message);
    next(error);
  }
});

app.get('/api/compliance/firewall/idps/signature-overrides', async (req, res, next) => {
  try {
    const agent = req.complianceAgent;

    const overrides = await agent.reporter.getSignatureOverrides();

    res.json({
      success: true,
      data: overrides,
      tenant: req.credentials.tenantId,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    next(error);
  }
});

app.put('/api/compliance/firewall/idps/signature-overrides', async (req, res, next) => {
  try {
    const agent = req.complianceAgent;

    const { signatures = {} } = req.body;

    const response = await agent.reporter.updateSignatureOverrides(signatures);

    res.json({
      success: true,
      data: response,
      tenant: req.credentials.tenantId,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    next(error);
  }
});

app.post('/api/compliance/firewall/idps/filter-options', async (req, res, next) => {
  try {
    const agent = req.complianceAgent;

    const { filterName } = req.body;

    const options = await agent.reporter.listIdpsFilterOptions(filterName);

    res.json({
      success: true,
      data: options,
      tenant: req.credentials.tenantId,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/compliance/sign-ins
 */
app.get('/api/compliance/sign-ins', async (req, res, next) => {
  // Increase timeout for this route to 4 minutes
  req.setTimeout(240000);
  res.setTimeout(240000);
  
  try {
    const agent = req.complianceAgent;
    const filters = {};
    
    // Parse date range if provided
    if (req.query.startDate && req.query.endDate) {
      filters.startDate = new Date(req.query.startDate).toISOString();
      filters.endDate = new Date(req.query.endDate).toISOString();
    } else if (req.query.days) {
      filters.days = parseInt(req.query.days);
    }
    
    // Add risk level filter
    if (req.query.riskLevel) {
      filters.$filter = `riskLevelDuringSignIn eq '${req.query.riskLevel}'`;
    }
    
    // Add top (limit)
    if (req.query.limit) {
      filters.$top = parseInt(req.query.limit);
    }
    
    // Add orderby
    if (req.query.orderby) {
      filters.$orderby = req.query.orderby;
    }
    
    console.log('Fetching sign-ins with filters:', filters);
    
    const startTime = Date.now();
    const signIns = await agent.reporter.getSignInLogs(filters);
    const duration = Date.now() - startTime;
    
    console.log(`✅ Sign-ins fetched in ${duration}ms:`, {
      count: signIns?.value?.length || 0,
      hasNextLink: !!signIns?.['@odata.nextLink']
    });
    
    res.json({
      success: true,
      data: signIns,
      count: signIns?.value?.length || 0,
      hasMore: !!signIns?.['@odata.nextLink'],
      nextLink: signIns?.['@odata.nextLink'],
      duration: `${duration}ms`,
      tenant: req.credentials.tenantId,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    console.error('Sign-ins API error:', {
      message: error.message,
      code: error.code,
      status: error.response?.status
    });
    
    if (error.message.includes('timed out')) {
      return res.status(504).json({
        success: false,
        error: 'Request timed out',
        message: 'The query took too long to complete',
        suggestion: 'Try using a smaller date range or add a limit parameter',
        examples: {
          'Last 1 day': '/api/compliance/sign-ins?days=1',
          'With limit': '/api/compliance/sign-ins?days=7&limit=100',
          'Date range': '/api/compliance/sign-ins?startDate=2024-01-01&endDate=2024-01-07'
        }
      });
    }
    
    next(error);
  }
});

app.get('/api/compliance/mfa-reports', async( req, res, next) => {
  try {
    const agent = req.complianceAgent;
    const mfaReports = await agent.reporter.getUsersWithMfaStatus();

    res.json({
      success: true,
      data: mfaReports,
      tenant: req.credentials.tenantId,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
})
/**
 * GET /api/compliance/directory-audits
 */
app.get('/api/compliance/directory-audits', async (req, res, next) => {
  try {
    const agent = req.complianceAgent;

    const filters = {};
    if (req.query.category)
      filters.$filter = `category eq '${req.query.category}'`;

    const audits = await agent.reporter.getDirectoryAudits(filters);

    let data = [];

    if (Array.isArray(audits)) data = audits;
    else if (audits?.data) data = audits.data;
    else if (audits?.value) data = audits.value;
    else if (typeof audits === "object") data = Object.values(audits);

    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 5000;

    const paginated = data.slice((page - 1) * limit, page * limit);

    res.json({
      success: true,
      data: paginated,
      pagination: {
        page,
        limit,
        total: data.length,
        pages: Math.ceil(data.length / limit),
      },
      tenant: req.credentials.tenantId,
      timestamp: new Date().toISOString(),
    });

  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/compliance/conditional-access
 */
app.get('/api/compliance/conditional-access', async (req, res, next) => {
  try {
    const agent = req.complianceAgent;
    const caPolicies = await agent.reporter.getConditionalAccessPolicies();

    let data = [];

    if (Array.isArray(caPolicies)) data = caPolicies;
    else if (caPolicies?.data) data = caPolicies.data;
    else if (caPolicies?.value) data = caPolicies.value;
    else if (typeof caPolicies === "object") data = Object.values(caPolicies);

    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 5000;

    const paginated = data.slice((page - 1) * limit, page * limit);

    res.json({
      success: true,
      data: paginated,
      pagination: {
        page,
        limit,
        total: data.length,
        pages: Math.ceil(data.length / limit),
      },
      tenant: req.credentials.tenantId,
      timestamp: new Date().toISOString(),
    });

  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/compliance/users/:id/auth-methods
 */
app.get('/api/compliance/users/:id/auth-methods', async (req, res, next) => {
  try {
    const agent = req.complianceAgent;
    const methods = await agent.reporter.getUserAuthMethods(req.params.id);

    let data = [];

    if (Array.isArray(methods)) data = methods;
    else if (methods?.data) data = methods.data;
    else if (methods?.value) data = methods.value;
    else if (typeof methods === "object") data = Object.values(methods);

    res.json({
      success: true,
      data,
      tenant: req.credentials.tenantId,
      timestamp: new Date().toISOString(),
    });

  } catch (error) {
    next(error);
  }
});

// ============================================================================
// Feature 2: Automated Remediation Endpoints
// ============================================================================

/**
 * POST /api/remediation/isolate-device
 */
app.post('/api/remediation/isolate-device', async (req, res, next) => {
  try {
    const { machineId, comment } = req.body;
    
    if (!machineId) {
      return res.status(400).json({
        success: false,
        error: 'machineId is required',
      });
    }
    
    const agent = req.complianceAgent;
    const result = await agent.remediator.isolateMachine(machineId, comment);
    
    res.json({
      success: true,
      data: result,
      message: 'Device isolated successfully',
      tenant: req.credentials.tenantId,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/remediation/unisolate-device
 */
app.post('/api/remediation/unisolate-device', async (req, res, next) => {
  try {
    const { machineId, comment } = req.body;
    
    if (!machineId) {
      return res.status(400).json({
        success: false,
        error: 'machineId is required',
      });
    }
    
    const agent = req.complianceAgent;
    const result = await agent.remediator.unisolateMachine(machineId, comment);
    
    res.json({
      success: true,
      data: result,
      message: 'Device released from isolation',
      tenant: req.credentials.tenantId,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/remediation/scan-device
 */
app.post('/api/remediation/scan-device', async (req, res, next) => {
  try {
    const { machineId, scanType = 'Full' } = req.body;
    
    if (!machineId) {
      return res.status(400).json({
        success: false,
        error: 'machineId is required',
      });
    }
    
    const agent = req.complianceAgent;
    const result = await agent.remediator.runAntiVirusScan(machineId, scanType);
    
    res.json({
      success: true,
      data: result,
      message: 'Antivirus scan initiated',
      tenant: req.credentials.tenantId,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/remediation/block-indicator
 */
app.post('/api/remediation/block-indicator', async (req, res, next) => {
  try {
    const { indicatorValue, indicatorType, title } = req.body;
    
    if (!indicatorValue || !indicatorType) {
      return res.status(400).json({
        success: false,
        error: 'indicatorValue and indicatorType are required',
      });
    }
    
    const agent = req.complianceAgent;
    const result = await agent.remediator.blockIndicator(
      indicatorValue,
      indicatorType,
      'Block',
      title || 'Automated threat block'
    );
    
    res.json({
      success: true,
      data: result,
      message: 'Threat indicator blocked',
      tenant: req.credentials.tenantId,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/remediation/disable-user
 */
app.post('/api/remediation/disable-user', async (req, res, next) => {
  try {
    const { userId } = req.body;
    
    if (!userId) {
      return res.status(400).json({
        success: false,
        error: 'userId is required',
      });
    }
    
    const agent = req.complianceAgent;
    const result = await agent.remediator.disableUserAccount(userId);
    
    res.json({
      success: true,
      data: result,
      message: 'User account disabled',
      tenant: req.credentials.tenantId,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/remediation/revoke-sessions
 */
app.post('/api/remediation/revoke-sessions', async (req, res, next) => {
  try {
    const { userId } = req.body;
    
    if (!userId) {
      return res.status(400).json({
        success: false,
        error: 'userId is required',
      });
    }
    
    const agent = req.complianceAgent;
    const result = await agent.remediator.revokeUserSessions(userId);
    
    res.json({
      success: true,
      data: result,
      message: 'User sessions revoked',
      tenant: req.credentials.tenantId,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/remediation/auto-remediate
 */
app.post('/api/remediation/auto-remediate', async (req, res, next) => {
  try {
    const { findings } = req.body;
    
    if (!findings || !Array.isArray(findings)) {
      return res.status(400).json({
        success: false,
        error: 'findings array is required',
      });
    }
    
    const agent = req.complianceAgent;
    const results = await agent.remediate(findings);
    
    res.json({
      success: true,
      data: results,
      message: `Processed ${results.length} remediations`,
      tenant: req.credentials.tenantId,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/remediation/quarantine-file
 */
app.post('/api/remediation/quarantine-file', async (req, res, next) => {
  try {
    const { machineId, filePath, comment } = req.body;

    if (!machineId || !filePath) {
      return res.status(400).json({
        success: false,
        error: 'machineId and filePath are required'
      });
    }

    const agent = req.complianceAgent;
    const result = await agent.remediator.quarantineFile(machineId, filePath, comment);

    res.json({
      success: true,
      data: result,
      message: "File quarantined successfully",
      tenant: req.credentials.tenantId,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/remediation/restrict-execution
 */
app.post('/api/remediation/restrict-execution', async (req, res, next) => {
  try {
    const { machineId } = req.body;

    if (!machineId) {
      return res.status(400).json({
        success: false,
        error: 'machineId is required'
      });
    }

    const agent = req.complianceAgent;
    const result = await agent.remediator.restrictCodeExecution(machineId);

    res.json({
      success: true,
      data: result,
      message: "Code execution restricted",
      tenant: req.credentials.tenantId,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/remediation/unrestrict-execution
 */
app.post('/api/remediation/unrestrict-execution', async (req, res, next) => {
  try {
    const { machineId } = req.body;

    if (!machineId) {
      return res.status(400).json({
        success: false,
        error: 'machineId is required'
      });
    }

    const agent = req.complianceAgent;
    const result = await agent.remediator.unrestrictCodeExecution(machineId);

    res.json({
      success: true,
      data: result,
      message: "Execution restriction removed",
      tenant: req.credentials.tenantId,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/remediation/collect-investigation
 */
app.post('/api/remediation/collect-investigation', async (req, res, next) => {
  try {
    const { machineId } = req.body;

    if (!machineId) {
      return res.status(400).json({
        success: false,
        error: 'machineId is required'
      });
    }

    const agent = req.complianceAgent;
    const result = await agent.remediator.collectInvestigationPackage(machineId);

    res.json({
      success: true,
      data: result,
      message: "Investigation package collection initiated",
      tenant: req.credentials.tenantId,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/remediation/offboard-device
 */
app.post('/api/remediation/offboard-device', async (req, res, next) => {
  try {
    const { machineId } = req.body;

    if (!machineId) {
      return res.status(400).json({
        success: false,
        error: 'machineId is required'
      });
    }

    const agent = req.complianceAgent;
    const result = await agent.remediator.offboardMachine(machineId);

    res.json({
      success: true,
      data: result,
      message: "Device offboarding initiated",
      tenant: req.credentials.tenantId,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/remediation/live-response
 */
app.post('/api/remediation/live-response', async (req, res, next) => {
  try {
    const { machineId, commands } = req.body;

    if (!machineId || !commands) {
      return res.status(400).json({
        success: false,
        error: 'machineId and commands array are required'
      });
    }

    const agent = req.complianceAgent;
    const result = await agent.remediator.runLiveResponse(machineId, { commands });

    res.json({
      success: true,
      data: result,
      message: "Live response executed",
      tenant: req.credentials.tenantId,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/remediation/add-mfa-phone
 */
app.post('/api/remediation/add-mfa-phone', async (req, res, next) => {
  try {
    const { userId, phoneNumber } = req.body;

    if (!userId || !phoneNumber) {
      return res.status(400).json({
        success: false,
        error: 'userId and phoneNumber are required'
      });
    }

    const agent = req.complianceAgent;
    const result = await agent.remediator.addMfaPhoneMethod(userId, phoneNumber);

    res.json({
      success: true,
      data: result,
      message: "MFA phone method added",
      tenant: req.credentials.tenantId,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/remediation/reset-password
 */
app.post('/api/remediation/reset-password', async (req, res, next) => {
  try {
    const { userId } = req.body;

    if (!userId) {
      return res.status(400).json({
        success: false,
        error: "userId is required"
      });
    }

    const agent = req.complianceAgent;
    const result = await agent.remediator.resetUserPassword(userId);

    res.json({
      success: true,
      data: result,
      message: "User password reset",
      tenant: req.credentials.tenantId,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/remediation/create-ca-policy
 */
app.post('/api/remediation/create-ca-policy', async (req, res, next) => {
  try {
    const policy = req.body;

    if (!policy) {
      return res.status(400).json({
        success: false,
        error: "policy body is required"
      });
    }

    const agent = req.complianceAgent;
    const result = await agent.remediator.createConditionalAccessPolicy(policy);

    res.json({
      success: true,
      data: result,
      message: "Conditional Access policy created",
      tenant: req.credentials.tenantId,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/remediation/confirm-compromised
 */
app.post('/api/remediation/confirm-compromised', async (req, res, next) => {
  try {
    const { userId } = req.body;

    if (!userId) {
      return res.status(400).json({
        success: false,
        error: "userId is required"
      });
    }

    const agent = req.complianceAgent;
    const result = await agent.remediator.confirmUserCompromised(userId);

    res.json({
      success: true,
      data: result,
      message: "User marked as compromised",
      tenant: req.credentials.tenantId,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/remediation/add-user-to-group
 */
app.post('/api/remediation/add-user-to-group', async (req, res, next) => {
  try {
    const { userId, groupId } = req.body;

    if (!userId || !groupId) {
      return res.status(400).json({
        success: false,
        error: "userId and groupId are required"
      });
    }

    const agent = req.complianceAgent;
    const result = await agent.remediator.addUserToGroup(userId, groupId);

    res.json({
      success: true,
      data: result,
      message: "User added to group",
      tenant: req.credentials.tenantId,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

// ============================================================================
// Feature 3: Continuous Monitoring Endpoints
// ============================================================================

/**
 * GET /api/monitoring/status
 */
app.get('/api/monitoring/status', (req, res) => {
  const status = getMonitoringStatus(req.credentials.tenantId);
  
  res.json({
    success: true,
    data: status,
    tenant: req.credentials.tenantId,
    timestamp: new Date().toISOString(),
  });
});

/**
 * POST /api/monitoring/start
 */
app.post('/api/monitoring/start', async (req, res, next) => {
  try {
    const agent = req.complianceAgent;
    const tenantId = req.credentials.tenantId;
    
    await startBackgroundMonitoring(agent, tenantId);
    
    res.json({
      success: true,
      message: '24/7 monitoring started',
      status: getMonitoringStatus(tenantId),
      tenant: tenantId,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/monitoring/stop
 */
app.post('/api/monitoring/stop', (req, res) => {
  const tenantId = req.credentials.tenantId;
  stopBackgroundMonitoring(tenantId);
  
  res.json({
    success: true,
    message: 'Monitoring stopped',
    status: getMonitoringStatus(tenantId),
    tenant: tenantId,
    timestamp: new Date().toISOString(),
  });
});

/**
 * GET /api/monitoring/drift
 */
app.get('/api/monitoring/drift', async (req, res, next) => {
  try {
    const agent = req.complianceAgent;
    const drift = await agent.checkDrift();
    
    res.json({
      success: true,
      data: drift,
      tenant: req.credentials.tenantId,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/monitoring/baseline
 */
app.post('/api/monitoring/baseline', async (req, res, next) => {
  try {
    const agent = req.complianceAgent;
    const baseline = await agent.monitor.setBaseline();
    
    res.json({
      success: true,
      data: baseline,
      message: 'Compliance baseline established',
      tenant: req.credentials.tenantId,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

// ============================================================================
// Server Startup
// ============================================================================

async function startServer() {
  try {
    // Start Express server
    app.listen(PORT, () => {
      console.log(`
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║        🛡️  Azure Compliance Agent REST API Server            ║
║                                                                ║
║        Status: RUNNING                                         ║
║        Port: ${PORT}                                             ║
║        Auth Mode: HEADER-BASED (Multi-Tenant)                  ║
║                                                                ║
║        Required Headers:                                       ║
║        - x-azure-client-id                                     ║
║        - x-azure-client-secret                                 ║
║        - x-azure-tenant-id                                     ║
║        - x-azure-subscription-id (optional)                    ║
║                                                                ║
║        API Documentation:                                      ║
║        - GET  /health                                          ║
║        - GET  /api/compliance/report                           ║
║        - GET  /api/compliance/devices                          ║
║        - GET  /api/compliance/alerts                           ║
║        - GET  /api/compliance/incidents                        ║
║        - GET  /api/compliance/vulnerabilities                  ║
║        - GET  /api/compliance/risky-users                      ║
║        - POST /api/remediation/isolate-device                  ║
║        - POST /api/remediation/block-indicator                 ║
║        - POST /api/remediation/disable-user                    ║
║        - POST /api/remediation/auto-remediate                  ║
║        - GET  /api/monitoring/status                           ║
║        - POST /api/monitoring/start                            ║
║        - POST /api/monitoring/stop                             ║
║        - GET  /api/monitoring/drift                            ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
      `);
    });

  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
}

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('🛑 SIGTERM received, shutting down gracefully...');
  // Stop all monitoring tasks
  for (const [tenantId, _] of monitoringTasks) {
    stopBackgroundMonitoring(tenantId);
  }
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('🛑 SIGINT received, shutting down gracefully...');
  // Stop all monitoring tasks
  for (const [tenantId, _] of monitoringTasks) {
    stopBackgroundMonitoring(tenantId);
  }
  process.exit(0);
});

// Start the server
startServer();

module.exports = app;