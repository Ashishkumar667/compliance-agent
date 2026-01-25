// ============================================================================
// Azure Compliance Agent - REST API Server
// Exposes all compliance features via REST endpoints
// Includes 24/7 background monitoring
// ============================================================================

const express = require('express');
const helmet = require('helmet');
const morgan = require('morgan');
const { ComplianceAgent } = require('./compliance-agent');

// ============================================================================
// Server Configuration
// ============================================================================

const app = express();
const PORT = process.env.PORT || 3000;

// Global agent instance (singleton)
let complianceAgent = null;
let monitoringTask = null;
let monitoringStatus = {
  isRunning: false,
  startedAt: null,
  lastCheckAt: null,
  checksPerformed: 0,
  issuesFound: 0,
  remediationsApplied: 0,
  errors: [],
};

// ============================================================================
// Middleware
// ============================================================================

app.use(helmet());
app.use(express.json({ limit: '50mb' }));
app.use(morgan('combined'));

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

async function ensureAgentInitialized() {
  if (!complianceAgent) {
    complianceAgent = new ComplianceAgent();
    await complianceAgent.initialize();
  }
  return complianceAgent;
}

// 24/7 Background Monitoring Function
async function startBackgroundMonitoring() {
  if (monitoringStatus.isRunning) {
    console.log('⚠️  Background monitoring already running');
    return;
  }

  const agent = await ensureAgentInitialized();
  monitoringStatus.isRunning = true;
  monitoringStatus.startedAt = new Date().toISOString();
  
  console.log('🚀 Starting 24/7 background monitoring...');

  // Run monitoring in background (non-blocking)
  monitoringTask = (async () => {
    const pollingInterval = (process.env.MONITORING_INTERVAL_MINUTES || 15) * 60 * 1000;
    
    while (monitoringStatus.isRunning) {
      try {
        monitoringStatus.lastCheckAt = new Date().toISOString();
        monitoringStatus.checksPerformed++;

        console.log(`[${new Date().toISOString()}] 🔍 Running scheduled compliance check #${monitoringStatus.checksPerformed}`);

        // Detect drift
        const drift = await agent.checkDrift();
        
        if (drift.findings.length > 0) {
          console.log(`⚠️  Found ${drift.findings.length} security issues`);
          monitoringStatus.issuesFound += drift.findings.length;

          // Auto-remediate
          const remediationResults = await agent.remediate(drift.findings);
          const successfulRemediations = remediationResults.filter(r => r.action !== 'failed').length;
          monitoringStatus.remediationsApplied += successfulRemediations;

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
        monitoringStatus.errors.push({
          timestamp: new Date().toISOString(),
          error: error.message,
          stack: error.stack,
        });
        
        // Keep only last 50 errors
        if (monitoringStatus.errors.length > 50) {
          monitoringStatus.errors = monitoringStatus.errors.slice(-50);
        }
      }

      // Wait for next interval
      console.log(`⏳ Next check in ${process.env.MONITORING_INTERVAL_MINUTES || 15} minutes...`);
      await new Promise(resolve => setTimeout(resolve, pollingInterval));
    }
  })();
}

function stopBackgroundMonitoring() {
  if (!monitoringStatus.isRunning) {
    console.log('⚠️  Background monitoring not running');
    return;
  }

  console.log('🛑 Stopping background monitoring...');
  monitoringStatus.isRunning = false;
  monitoringTask = null;
}

// ============================================================================
// API Routes
// ============================================================================

// Health check
app.get('/health', (req, res) => {
  res.json({
    success: true,
    status: 'healthy',
    timestamp: new Date().toISOString(),
    monitoring: monitoringStatus,
  });
});

// ============================================================================
// Feature 1: Compliance Reporting Endpoints
// ============================================================================

/**
 * GET /api/compliance/report
 * Generate full compliance report with evidence from all sources
 */
// app.get('/api/compliance/report', async (req, res, next) => {
//   try {
//     const agent = await ensureAgentInitialized();
//     const report = await agent.generateReport();
    
//     res.json({
//       success: true,
//       data: report,
//       timestamp: new Date().toISOString(),
//     });
//   } catch (error) {
//     next(error);
//   }
// });

app.get('/api/compliance/report', async (req, res, next) => {
  try {
    const agent = await ensureAgentInitialized();
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
      data = Object.values(report);
    }

    res.json({
      success: true,
      data,
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
    const agent = await ensureAgentInitialized();
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
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});
app.get('/api/compliance/devices/:id', async (req, res, next) => {
  try {
    const agent = await ensureAgentInitialized();
    const device = await agent.reporter.getSpecificDeviceInventory(req.params.id);
    res.json({
      success: true,
      data: device,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/compliance/alerts
 * Get security alerts
 * Query params: ?status=New&severity=High
 */

/**
 * POST /api/compliance/alerts/batch-update
 * Batch update Defender alerts (status, classification, determination, assignedTo, comments)
 */
app.post('/api/compliance/alerts/batch-update', async (req, res, next) => {
  try {
    const agent = await ensureAgentInitialized();

    const payload = req.body;

    // Basic validation (optional but recommended)
    if (!payload || !Array.isArray(payload.alertIds) || payload.alertIds.length === 0) {
      return res.status(400).json({
        success: false,
        message: "alertIds[] is required and must contain at least one alert ID"
      });
    }

    // Call your reporter function (already defined)
    const result = await agent.reporter.batchUpdateAlert(payload);

    // Normalize response (in case API returns irregular Defender shape)
    let data = [];
    if (Array.isArray(result)) data = result;
    else if (result?.data) data = result.data;
    else if (result?.value) data = result.value;
    else if (typeof result === "object") data = result;

    res.json({
      success: true,
      data,
      timestamp: new Date().toISOString(),
    });

  } catch (error) {
    next(error);
  }
});


app.get('/api/compliance/alerts', async (req, res, next) => {
  try {
    const agent = await ensureAgentInitialized();
    const filters = {};

    // Build the OData filter dynamically
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

    // Robust normalization
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
      timestamp: new Date().toISOString(),
    });

  } catch (error) {
    next(error);
  }
});

app.post('/api/compliance/createalertbyref', async (req, res, next) => {
  try {
    const agent = await ensureAgentInitialized();

    const payload = req.body;

    // Basic validation
    if (!payload || !payload.machineId) {
      return res.status(400).json({
        success: false,
        message: "machineId is required"
      });
    }

    const created = await agent.reporter.CreateAlertByRefrence(payload);

    // Normalize (Defender APIs sometimes wrap responses)
    let data = [];

    if (Array.isArray(created)) data = created;
    else if (created?.data) data = created.data;
    else if (created?.value) data = created.value;
    else if (typeof created === "object") data = created;

    res.json({
      success: true,
      data,
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
    const agent = await ensureAgentInitialized();
    const incidents = await agent.reporter.getSentinelIncidents();
    
    res.json({
      success: true,
      data: incidents,
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
    const agent = await ensureAgentInitialized();
    const [alerts, entities] = await Promise.all([
      agent.reporter.getIncidentAlerts(req.params.id),
      agent.reporter.getIncidentEntities(req.params.id),
    ]);
    
    res.json({
      success: true,
      data: { alerts, entities },
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});


app.post('/api/compliance/machines/:id/collect-investigation', async (req, res, next) => {
  try {
    const agent = await ensureAgentInitialized();
    const result = await agent.reporter.collectInvestigationPackage(req.params.id, req.body);

    res.json({
      success: true,
      data: result,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    next(err);
  }
});

app.post('/api/compliance/deviceHealth', async (req, res, next) => {
  try {
    const agent = await ensureAgentInitialized();
    const result = await agent.reporter.getDeviceHealth();

    res.json({
      success: true,
      data: result,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/compliance/vulnerabilities
 * Get known vulnerabilities
 */
app.get('/api/compliance/recommendations', async (req, res, next) => {
  try {
    const agent = await ensureAgentInitialized();
    const recommendations = await agent.reporter.getSecurityRecommendations();

    let data = [];

    if (Array.isArray(recommendations)) data = recommendations;
    else if (recommendations?.data) data = recommendations.data;
    else if (recommendations?.value) data = recommendations.value;
    else if (typeof recommendations === "object") data = Object.values(recommendations);

    const page = parseInt(req.query.page) || 2;
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
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

app.get('/api/compliance/machine/tags', async( req, res, next) => {
  try {
    const agent = await ensureAgentInitialized();
    const tags = await agent.reporter.getMachineTag();

    res.json({
      success: true,
      data: tags,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
})
app.get('/api/compliance/vulnerabilities', async (req, res, next) => {
  try {
    const agent = await ensureAgentInitialized();
    const vulns = await agent.reporter.getVulnerabilities();

    let data = [];

    if (Array.isArray(vulns)) data = vulns;
    else if (vulns?.data) data = vulns.data;
    else if (vulns?.value) data = vulns.value;
    else if (typeof vulns === "object") data = Object.values(vulns);

    const page = parseInt(req.query.page) || 2;
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
      timestamp: new Date().toISOString(),
    });

  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/compliance/risky-users
 * Get users flagged as risky
 */
app.get('/api/compliance/risky-users', async (req, res, next) => {
  try {
    const agent = await ensureAgentInitialized();
    const riskyUsers = await agent.reporter.getRiskyUsers();
    
    res.json({
      success: true,
      data: riskyUsers,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/compliance/firewall-policies
 * Get firewall policies and rules
 */
app.get('/api/compliance/firewall-policies', async (req, res, next) => {
  try {
    const agent = await ensureAgentInitialized();
    const [policies, rules] = await Promise.all([
      agent.reporter.getFirewallPolicies(),
      agent.reporter.getRuleCollectionGroups(),
    ]);
    
    res.json({
      success: true,
      data: { policies, rules },
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/compliance/sign-ins
 * Get sign-in logs
 * Query params: ?riskLevel=high
 */
app.get('/api/compliance/sign-ins', async (req, res, next) => {
  try {
    const agent = await ensureAgentInitialized();
    const filters = {};
    
    if (req.query.riskLevel) {
      filters.$filter = `riskLevel eq '${req.query.riskLevel}'`;
    }
    
    const signIns = await agent.reporter.getSignInLogs(filters);
    
    res.json({
      success: true,
      data: signIns,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});


app.get('/api/compliance/directory-audits', async (req, res, next) => {
  try {
    const agent = await ensureAgentInitialized();

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
      timestamp: new Date().toISOString(),
    });

  } catch (error) {
    next(error);
  }
});


// ============================================================================
// 11. GRAPH — CONDITIONAL ACCESS POLICIES (MISSING → NOW ADDED)
// ============================================================================
app.get('/api/compliance/conditional-access', async (req, res, next) => {
  try {
    const agent = await ensureAgentInitialized();
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
      timestamp: new Date().toISOString(),
    });

  } catch (error) {
    next(error);
  }
});


// ============================================================================
// 12. GRAPH — USER AUTH METHODS (MISSING → NOW ADDED)
// ============================================================================
app.get('/api/compliance/users/:id/auth-methods', async (req, res, next) => {
  try {
    const agent = await ensureAgentInitialized();
    const methods = await agent.reporter.getUserAuthMethods(req.params.id);

    let data = [];

    if (Array.isArray(methods)) data = methods;
    else if (methods?.data) data = methods.data;
    else if (methods?.value) data = methods.value;
    else if (typeof methods === "object") data = Object.values(methods);

    res.json({
      success: true,
      data,
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
 * Isolate a compromised device
 * Body: { "machineId": "abc123", "comment": "Ransomware detected" }
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
    
    const agent = await ensureAgentInitialized();
    const result = await agent.remediator.isolateMachine(machineId, comment);
    
    res.json({
      success: true,
      data: result,
      message: 'Device isolated successfully',
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/remediation/unisolate-device
 * Release device from isolation
 * Body: { "machineId": "abc123" }
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
    
    const agent = await ensureAgentInitialized();
    const result = await agent.remediator.unisolateMachine(machineId, comment);
    
    res.json({
      success: true,
      data: result,
      message: 'Device released from isolation',
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/remediation/scan-device
 * Run antivirus scan on device
 * Body: { "machineId": "abc123", "scanType": "Full" }
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
    
    const agent = await ensureAgentInitialized();
    const result = await agent.remediator.runAntiVirusScan(machineId, scanType);
    
    res.json({
      success: true,
      data: result,
      message: 'Antivirus scan initiated',
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/remediation/block-indicator
 * Block malicious IP/domain/file hash
 * Body: { "indicatorValue": "1.2.3.4", "indicatorType": "IpAddress", "title": "C2 Server" }
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
    
    const agent = await ensureAgentInitialized();
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
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/remediation/disable-user
 * Disable compromised user account
 * Body: { "userId": "user@domain.com" }
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
    
    const agent = await ensureAgentInitialized();
    const result = await agent.remediator.disableUserAccount(userId);
    
    res.json({
      success: true,
      data: result,
      message: 'User account disabled',
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/remediation/revoke-sessions
 * Revoke all active sessions for a user
 * Body: { "userId": "user@domain.com" }
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
    
    const agent = await ensureAgentInitialized();
    const result = await agent.remediator.revokeUserSessions(userId);
    
    res.json({
      success: true,
      data: result,
      message: 'User sessions revoked',
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/remediation/auto-remediate
 * Auto-remediate multiple findings
 * Body: { "findings": [{ "type": "COMPROMISED_DEVICE", "deviceId": "abc123" }] }
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
    
    const agent = await ensureAgentInitialized();
    const results = await agent.remediate(findings);
    
    res.json({
      success: true,
      data: results,
      message: `Processed ${results.length} remediations`,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

app.post('/api/remediation/quarantine-file', async (req, res, next) => {
  try {
    const { machineId, filePath, comment } = req.body;

    if (!machineId || !filePath) {
      return res.status(400).json({
        success: false,
        error: 'machineId and filePath are required'
      });
    }

    const agent = await ensureAgentInitialized();
    const result = await agent.remediator.quarantineFile(machineId, filePath, comment);

    res.json({
      success: true,
      data: result,
      message: "File quarantined successfully",
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});


app.post('/api/remediation/restrict-execution', async (req, res, next) => {
  try {
    const { machineId } = req.body;

    if (!machineId) {
      return res.status(400).json({
        success: false,
        error: 'machineId is required'
      });
    }

    const agent = await ensureAgentInitialized();
    const result = await agent.remediator.restrictCodeExecution(machineId);

    res.json({
      success: true,
      data: result,
      message: "Code execution restricted",
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});


app.post('/api/remediation/unrestrict-execution', async (req, res, next) => {
  try {
    const { machineId } = req.body;

    if (!machineId) {
      return res.status(400).json({
        success: false,
        error: 'machineId is required'
      });
    }

    const agent = await ensureAgentInitialized();
    const result = await agent.remediator.unrestrictCodeExecution(machineId);

    res.json({
      success: true,
      data: result,
      message: "Execution restriction removed",
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

app.post('/api/remediation/collect-investigation', async (req, res, next) => {
  try {
    const { machineId } = req.body;

    if (!machineId) {
      return res.status(400).json({
        success: false,
        error: 'machineId is required'
      });
    }

    const agent = await ensureAgentInitialized();
    const result = await agent.remediator.collectInvestigationPackage(machineId);

    res.json({
      success: true,
      data: result,
      message: "Investigation package collection initiated",
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});


app.post('/api/remediation/offboard-device', async (req, res, next) => {
  try {
    const { machineId } = req.body;

    if (!machineId) {
      return res.status(400).json({
        success: false,
        error: 'machineId is required'
      });
    }

    const agent = await ensureAgentInitialized();
    const result = await agent.remediator.offboardMachine(machineId);

    res.json({
      success: true,
      data: result,
      message: "Device offboarding initiated",
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

app.post('/api/remediation/live-response', async (req, res, next) => {
  try {
    const { machineId, commands } = req.body;

    if (!machineId || !commands) {
      return res.status(400).json({
        success: false,
        error: 'machineId and commands array are required'
      });
    }

    const agent = await ensureAgentInitialized();
    const result = await agent.remediator.runLiveResponse(machineId, { commands });

    res.json({
      success: true,
      data: result,
      message: "Live response executed",
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

app.post('/api/remediation/add-mfa-phone', async (req, res, next) => {
  try {
    const { userId, phoneNumber } = req.body;

    if (!userId || !phoneNumber) {
      return res.status(400).json({
        success: false,
        error: 'userId and phoneNumber are required'
      });
    }

    const agent = await ensureAgentInitialized();
    const result = await agent.remediator.addMfaPhoneMethod(userId, phoneNumber);

    res.json({
      success: true,
      data: result,
      message: "MFA phone method added",
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

app.post('/api/remediation/reset-password', async (req, res, next) => {
  try {
    const { userId } = req.body;

    if (!userId) {
      return res.status(400).json({
        success: false,
        error: "userId is required"
      });
    }

    const agent = await ensureAgentInitialized();
    const result = await agent.remediator.resetUserPassword(userId);

    res.json({
      success: true,
      data: result,
      message: "User password reset",
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

app.post('/api/remediation/create-ca-policy', async (req, res, next) => {
  try {
    const policy = req.body;

    if (!policy) {
      return res.status(400).json({
        success: false,
        error: "policy body is required"
      });
    }

    const agent = await ensureAgentInitialized();
    const result = await agent.remediator.createConditionalAccessPolicy(policy);

    res.json({
      success: true,
      data: result,
      message: "Conditional Access policy created",
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

app.post('/api/remediation/confirm-compromised', async (req, res, next) => {
  try {
    const { userId } = req.body;

    if (!userId) {
      return res.status(400).json({
        success: false,
        error: "userId is required"
      });
    }

    const agent = await ensureAgentInitialized();
    const result = await agent.remediator.confirmUserCompromised(userId);

    res.json({
      success: true,
      data: result,
      message: "User marked as compromised",
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

app.post('/api/remediation/add-user-to-group', async (req, res, next) => {
  try {
    const { userId, groupId } = req.body;

    if (!userId || !groupId) {
      return res.status(400).json({
        success: false,
        error: "userId and groupId are required"
      });
    }

    const agent = await ensureAgentInitialized();
    const result = await agent.remediator.addUserToGroup(userId, groupId);

    res.json({
      success: true,
      data: result,
      message: "User added to group",
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
 * Get current monitoring status
 */
app.get('/api/monitoring/status', (req, res) => {
  res.json({
    success: true,
    data: monitoringStatus,
    timestamp: new Date().toISOString(),
  });
});

/**
 * POST /api/monitoring/start
 * Start 24/7 background monitoring
 */
app.post('/api/monitoring/start', async (req, res, next) => {
  try {
    await startBackgroundMonitoring();
    
    res.json({
      success: true,
      message: '24/7 monitoring started',
      status: monitoringStatus,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/monitoring/stop
 * Stop background monitoring
 */
app.post('/api/monitoring/stop', (req, res) => {
  stopBackgroundMonitoring();
  
  res.json({
    success: true,
    message: 'Monitoring stopped',
    status: monitoringStatus,
    timestamp: new Date().toISOString(),
  });
});

/**
 * GET /api/monitoring/drift
 * Check for configuration drift (on-demand)
 */
app.get('/api/monitoring/drift', async (req, res, next) => {
  try {
    const agent = await ensureAgentInitialized();
    const drift = await agent.checkDrift();
    
    res.json({
      success: true,
      data: drift,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/monitoring/baseline
 * Set new compliance baseline
 */
app.post('/api/monitoring/baseline', async (req, res, next) => {
  try {
    const agent = await ensureAgentInitialized();
    const baseline = await agent.monitor.setBaseline();
    
    res.json({
      success: true,
      data: baseline,
      message: 'Compliance baseline established',
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
    // Initialize agent on startup
    // console.log('🚀 Initializing Compliance Agent...');
    // await ensureAgentInitialized();
    // console.log('✅ Agent initialized successfully');

    // Auto-start 24/7 monitoring if configured
    if (process.env.AUTO_START_MONITORING === 'true') {
      console.log('🔄 Auto-starting 24/7 monitoring...');
      await startBackgroundMonitoring();
    }

    // Start Express server
    app.listen(PORT, () => {
      console.log(`
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║        🛡️  Azure Compliance Agent REST API Server            ║
║                                                                ║
║        Status: RUNNING                                         ║
║        Port: ${PORT}                                             ║
║        Monitoring: ${monitoringStatus.isRunning ? 'ACTIVE (24/7)' : 'STOPPED'}                               ║
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
  stopBackgroundMonitoring();
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('🛑 SIGINT received, shutting down gracefully...');
  stopBackgroundMonitoring();
  process.exit(0);
});

// Start the server
startServer();

module.exports = app;