import React, { useState, useEffect, useRef } from 'react';
import { Search, Shield, AlertTriangle, CheckCircle, XCircle, Clock, Zap, Target, Eye, Code, Server, Globe, Lock, Unlock, Bug, Activity, Download, Play, Pause, RotateCcw } from 'lucide-react';

const VulnScanner = () => {
  const [scanTarget, setScanTarget] = useState('');
  const [scanType, setScanType] = useState('comprehensive');
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [scanHistory, setScanHistory] = useState([]);
  const [currentScan, setCurrentScan] = useState(null);
  const [scanLogs, setScanLogs] = useState([]);
  const [selectedTab, setSelectedTab] = useState('scanner');
  const logEndRef = useRef(null);

  // Vulnerability database with CVSS scores and descriptions
  const vulnDatabase = {
    'SQL Injection': {
      severity: 'Critical',
      cvss: 9.8,
      description: 'Application is vulnerable to SQL injection attacks',
      remediation: 'Use parameterized queries and input validation',
      cwe: 'CWE-89'
    },
    'Cross-Site Scripting (XSS)': {
      severity: 'High',
      cvss: 8.7,
      description: 'Stored XSS vulnerability found in user input fields',
      remediation: 'Implement proper input sanitization and CSP headers',
      cwe: 'CWE-79'
    },
    'Insecure Direct Object References': {
      severity: 'High',
      cvss: 8.1,
      description: 'Direct object references without proper authorization',
      remediation: 'Implement proper access controls and object validation',
      cwe: 'CWE-639'
    },
    'Security Misconfiguration': {
      severity: 'Medium',
      cvss: 6.5,
      description: 'Server misconfiguration exposing sensitive information',
      remediation: 'Review and harden server configuration',
      cwe: 'CWE-16'
    },
    'Broken Authentication': {
      severity: 'Critical',
      cvss: 9.3,
      description: 'Weak authentication mechanisms detected',
      remediation: 'Implement strong authentication and session management',
      cwe: 'CWE-287'
    },
    'Sensitive Data Exposure': {
      severity: 'High',
      cvss: 7.5,
      description: 'Sensitive data transmitted without encryption',
      remediation: 'Implement HTTPS and encrypt sensitive data',
      cwe: 'CWE-200'
    },
    'XML External Entities (XXE)': {
      severity: 'High',
      cvss: 8.2,
      description: 'XML parser vulnerable to external entity attacks',
      remediation: 'Disable XML external entity processing',
      cwe: 'CWE-611'
    },
    'Insufficient Logging': {
      severity: 'Low',
      cvss: 3.1,
      description: 'Inadequate logging and monitoring capabilities',
      remediation: 'Implement comprehensive logging and monitoring',
      cwe: 'CWE-778'
    },
    'CSRF Vulnerability': {
      severity: 'Medium',
      cvss: 6.1,
      description: 'Cross-Site Request Forgery protection missing',
      remediation: 'Implement CSRF tokens and same-site cookies',
      cwe: 'CWE-352'
    },
    'Outdated Components': {
      severity: 'Medium',
      cvss: 5.9,
      description: 'Using components with known vulnerabilities',
      remediation: 'Update all components to latest secure versions',
      cwe: 'CWE-1104'
    }
  };

  const scanTypes = {
    'quick': { name: 'Quick Scan', duration: 15, checks: ['Basic port scan', 'Common vulnerabilities'] },
    'comprehensive': { name: 'Comprehensive Scan', duration: 45, checks: ['Full port scan', 'Vulnerability assessment', 'SSL/TLS analysis', 'Web application testing'] },
    'web-app': { name: 'Web Application', duration: 30, checks: ['OWASP Top 10', 'XSS detection', 'SQL injection', 'Authentication flaws'] },
    'network': { name: 'Network Security', duration: 25, checks: ['Port scanning', 'Service enumeration', 'Network configuration'] },
    'ssl-tls': { name: 'SSL/TLS Analysis', duration: 10, checks: ['Certificate validation', 'Cipher suite analysis', 'Protocol vulnerabilities'] }
  };

  useEffect(() => {
    if (logEndRef.current) {
      logEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [scanLogs]);

  const addLog = (message, type = 'info') => {
    const timestamp = new Date().toLocaleTimeString();
    setScanLogs(prev => [...prev, { timestamp, message, type }]);
  };

  const simulateScan = async () => {
    if (!scanTarget.trim()) {
      addLog('Error: Please enter a target to scan', 'error');
      return;
    }

    if (isScanning) {
      return;
    }

    setIsScanning(true);
    setScanProgress(0);
    setVulnerabilities([]);
    setScanLogs([]);
    
    let isCancelled = false;
    
    const scanId = `SCAN-${Date.now()}`;
    const scanConfig = scanTypes[scanType];
    
    addLog(`Starting ${scanConfig.name} for ${scanTarget}`, 'info');
    addLog(`Scan ID: ${scanId}`, 'info');
    addLog('Initializing scan modules...', 'info');

    const newScan = {
      id: scanId,
      target: scanTarget,
      type: scanType,
      startTime: new Date(),
      status: 'running',
      progress: 0
    };
    
    setCurrentScan(newScan);

    // Simulate scanning phases
    const phases = [
      { name: 'Host Discovery', duration: 2000, progress: 15 },
      { name: 'Port Scanning', duration: 3000, progress: 35 },
      { name: 'Service Detection', duration: 2500, progress: 55 },
      { name: 'Vulnerability Assessment', duration: 4000, progress: 80 },
      { name: 'Report Generation', duration: 1500, progress: 100 }
    ];

    try {
      for (const phase of phases) {
        if (isCancelled) break;
        
        addLog(`${phase.name} in progress...`, 'info');
        
        // Simulate phase duration with progress updates
        const steps = 10;
        const stepDuration = phase.duration / steps;
        const progressIncrement = (phase.progress - scanProgress) / steps;
        
        for (let i = 0; i < steps; i++) {
          if (isCancelled) break;
          
          await new Promise(resolve => setTimeout(resolve, stepDuration));
          setScanProgress(prev => Math.min(prev + progressIncrement, phase.progress));
          
          // Add some discoveries during scanning
          if (phase.name === 'Port Scanning' && i === 5) {
            addLog('Open ports detected: 22, 80, 443, 3306', 'success');
          }
          if (phase.name === 'Service Detection' && i === 7) {
            addLog('Services identified: SSH, HTTP, HTTPS, MySQL', 'success');
          }
          if (phase.name === 'Vulnerability Assessment' && i === 3) {
            addLog('Analyzing OWASP Top 10 vulnerabilities...', 'info');
          }
        }
        
        if (!isCancelled) {
          addLog(`${phase.name} completed`, 'success');
        }
      }

      if (!isCancelled) {
        // Generate vulnerabilities based on scan type
        const foundVulns = generateVulnerabilities(scanType);
        setVulnerabilities(foundVulns);
        
        foundVulns.forEach(vuln => {
          addLog(`${vuln.severity} vulnerability found: ${vuln.name}`, 'warning');
        });

        const completedScan = {
          ...newScan,
          endTime: new Date(),
          status: 'completed',
          progress: 100,
          vulnerabilities: foundVulns.length,
          criticalCount: foundVulns.filter(v => v.severity === 'Critical').length,
          highCount: foundVulns.filter(v => v.severity === 'High').length
        };

        setScanHistory(prev => [completedScan, ...prev.slice(0, 9)]);
        setCurrentScan(completedScan);
        setScanProgress(100);
        
        addLog(`Scan completed. Found ${foundVulns.length} vulnerabilities`, 'success');
        addLog('Report ready for download', 'info');
      }
    } catch (error) {
      addLog(`Scan error: ${error.message}`, 'error');
    } finally {
      setIsScanning(false);
    }

    // Cleanup function for cancellation
    return () => {
      isCancelled = true;
    };
  };

  const generateVulnerabilities = (scanType) => {
    const vulnNames = Object.keys(vulnDatabase);
    const numVulns = scanType === 'quick' ? 
      Math.floor(Math.random() * 3) + 1 : 
      Math.floor(Math.random() * 6) + 2;
    
    const selectedVulns = [];
    const usedNames = new Set();
    
    for (let i = 0; i < numVulns; i++) {
      let vulnName;
      do {
        vulnName = vulnNames[Math.floor(Math.random() * vulnNames.length)];
      } while (usedNames.has(vulnName));
      
      usedNames.add(vulnName);
      const vulnData = vulnDatabase[vulnName];
      
      selectedVulns.push({
        id: `VULN-${Date.now()}-${i}`,
        name: vulnName,
        severity: vulnData.severity,
        cvss: vulnData.cvss,
        description: vulnData.description,
        remediation: vulnData.remediation,
        cwe: vulnData.cwe,
        location: generateLocation(),
        discoveredAt: new Date()
      });
    }
    
    return selectedVulns.sort((a, b) => {
      const severityOrder = { 'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1 };
      return severityOrder[b.severity] - severityOrder[a.severity];
    });
  };

  const generateLocation = () => {
    const locations = [
      '/admin/login.php',
      '/api/users',
      '/upload/index.jsp',
      '/search?q=',
      '/profile/edit',
      '/payment/process',
      '/config/database.xml',
      '/includes/auth.inc'
    ];
    return locations[Math.floor(Math.random() * locations.length)];
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'Critical': return 'text-red-600 bg-red-100 border-red-200';
      case 'High': return 'text-orange-600 bg-orange-100 border-orange-200';
      case 'Medium': return 'text-yellow-600 bg-yellow-100 border-yellow-200';
      case 'Low': return 'text-green-600 bg-green-100 border-green-200';
      default: return 'text-gray-600 bg-gray-100 border-gray-200';
    }
  };

  const getSeverityIcon = (severity) => {
    switch (severity) {
      case 'Critical': return <XCircle className="h-4 w-4" />;
      case 'High': return <AlertTriangle className="h-4 w-4" />;
      case 'Medium': return <Clock className="h-4 w-4" />;
      case 'Low': return <CheckCircle className="h-4 w-4" />;
      default: return <Eye className="h-4 w-4" />;
    }
  };

  const exportReport = () => {
    const report = {
      scanId: currentScan?.id,
      target: scanTarget,
      scanType: scanType,
      timestamp: new Date().toISOString(),
      vulnerabilities: vulnerabilities,
      summary: {
        total: vulnerabilities.length,
        critical: vulnerabilities.filter(v => v.severity === 'Critical').length,
        high: vulnerabilities.filter(v => v.severity === 'High').length,
        medium: vulnerabilities.filter(v => v.severity === 'Medium').length,
        low: vulnerabilities.filter(v => v.severity === 'Low').length
      }
    };
    
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `vuln-report-${currentScan?.id || 'latest'}.json`;
    a.click();
    URL.revokeObjectURL(url);
    
    addLog('Report exported successfully', 'success');
  };

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-gray-900 text-white shadow-lg">
        <div className="px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="p-2 bg-blue-600 rounded-lg">
                <Shield className="h-6 w-6" />
              </div>
              <div>
                <h1 className="text-xl font-bold">VulnGuard Scanner</h1>
                <p className="text-sm text-gray-400">Advanced Vulnerability Assessment Platform</p>
              </div>
            </div>
            <div className="flex items-center space-x-4">
              <div className="text-right text-sm">
                <div className="text-white">Security Level: Professional</div>
                <div className="text-gray-400">Version 2.1.0</div>
              </div>
              <div className="w-3 h-3 bg-green-500 rounded-full animate-pulse" />
            </div>
          </div>
        </div>
      </header>

      {/* Navigation */}
      <nav className="bg-white shadow-sm border-b">
        <div className="px-6">
          <div className="flex space-x-8">
            {[
              { id: 'scanner', label: 'Vulnerability Scanner', icon: Search },
              { id: 'results', label: 'Scan Results', icon: Bug },
              { id: 'history', label: 'Scan History', icon: Clock },
              { id: 'reports', label: 'Reports', icon: Download }
            ].map(({ id, label, icon: Icon }) => (
              <button
                key={id}
                onClick={() => setSelectedTab(id)}
                className={`flex items-center space-x-2 py-4 px-2 border-b-2 font-medium text-sm transition-colors ${
                  selectedTab === id
                    ? 'border-blue-500 text-blue-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700'
                }`}
              >
                <Icon className="h-4 w-4" />
                <span>{label}</span>
              </button>
            ))}
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="p-6">
        {selectedTab === 'scanner' && (
          <div className="max-w-4xl mx-auto space-y-6">
            {/* Scan Configuration */}
            <div className="bg-white rounded-lg shadow-md">
              <div className="p-6 border-b border-gray-200">
                <h2 className="text-lg font-semibold flex items-center">
                  <Target className="h-5 w-5 mr-2 text-blue-600" />
                  Scan Configuration
                </h2>
              </div>
              <div className="p-6 space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Target URL or IP Address
                  </label>
                  <input
                    type="text"
                    value={scanTarget}
                    onChange={(e) => setScanTarget(e.target.value)}
                    placeholder="https://example.com or 192.168.1.1"
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                    disabled={isScanning}
                  />
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Scan Type
                  </label>
                  <select
                    value={scanType}
                    onChange={(e) => setScanType(e.target.value)}
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                    disabled={isScanning}
                  >
                    {Object.entries(scanTypes).map(([key, config]) => (
                      <option key={key} value={key}>
                        {config.name} (~{config.duration}s)
                      </option>
                    ))}
                  </select>
                </div>

                <div className="bg-gray-50 p-4 rounded-lg">
                  <h4 className="font-medium text-gray-700 mb-2">Scan Includes:</h4>
                  <ul className="text-sm text-gray-600 space-y-1">
                    {scanTypes[scanType].checks.map((check, index) => (
                      <li key={index} className="flex items-center">
                        <CheckCircle className="h-4 w-4 text-green-500 mr-2" />
                        {check}
                      </li>
                    ))}
                  </ul>
                </div>

                <button
                  onClick={simulateScan}
                  disabled={isScanning || !scanTarget.trim()}
                  className="w-full bg-blue-600 text-white py-3 px-4 rounded-md hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed flex items-center justify-center space-x-2 transition-colors"
                >
                  {isScanning ? (
                    <>
                      <Pause className="h-4 w-4 animate-spin" />
                      <span>Scanning... {Math.round(scanProgress)}%</span>
                    </>
                  ) : (
                    <>
                      <Play className="h-4 w-4" />
                      <span>Start Vulnerability Scan</span>
                    </>
                  )}
                </button>

                {isScanning && (
                  <div className="space-y-2">
                    <div className="flex justify-between text-sm">
                      <span>Scan Progress</span>
                      <span>{Math.round(scanProgress)}%</span>
                    </div>
                    <div className="w-full bg-gray-200 rounded-full h-2">
                      <div
                        className="bg-blue-600 h-2 rounded-full transition-all duration-300"
                        style={{ width: `${scanProgress}%` }}
                      />
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* Real-time Logs */}
            <div className="bg-white rounded-lg shadow-md">
              <div className="p-6 border-b border-gray-200">
                <h2 className="text-lg font-semibold flex items-center">
                  <Activity className="h-5 w-5 mr-2 text-blue-600" />
                  Scan Logs
                </h2>
              </div>
              <div className="p-4">
                <div className="bg-gray-900 rounded-lg p-4 h-64 overflow-y-auto font-mono text-sm">
                  {scanLogs.length === 0 ? (
                    <div className="text-gray-500 text-center py-8">
                      No scan logs yet. Start a scan to see real-time progress.
                    </div>
                  ) : (
                    scanLogs.map((log, index) => (
                      <div key={index} className={`mb-1 ${
                        log.type === 'error' ? 'text-red-400' :
                        log.type === 'warning' ? 'text-yellow-400' :
                        log.type === 'success' ? 'text-green-400' :
                        'text-gray-300'
                      }`}>
                        <span className="text-gray-500">[{log.timestamp}]</span> {log.message}
                      </div>
                    ))
                  )}
                  <div ref={logEndRef} />
                </div>
              </div>
            </div>
          </div>
        )}

        {selectedTab === 'results' && (
          <div className="max-w-6xl mx-auto space-y-6">
            {/* Results Summary */}
            {vulnerabilities.length > 0 && (
              <>
                <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                  <div className="bg-white rounded-lg shadow-md p-6">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm font-medium text-gray-600">Total Vulnerabilities</p>
                        <p className="text-2xl font-bold text-gray-800">{vulnerabilities.length}</p>
                      </div>
                      <Bug className="h-8 w-8 text-blue-600" />
                    </div>
                  </div>
                  
                  <div className="bg-white rounded-lg shadow-md p-6">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm font-medium text-gray-600">Critical</p>
                        <p className="text-2xl font-bold text-red-600">
                          {vulnerabilities.filter(v => v.severity === 'Critical').length}
                        </p>
                      </div>
                      <XCircle className="h-8 w-8 text-red-600" />
                    </div>
                  </div>
                  
                  <div className="bg-white rounded-lg shadow-md p-6">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm font-medium text-gray-600">High</p>
                        <p className="text-2xl font-bold text-orange-600">
                          {vulnerabilities.filter(v => v.severity === 'High').length}
                        </p>
                      </div>
                      <AlertTriangle className="h-8 w-8 text-orange-600" />
                    </div>
                  </div>
                  
                  <div className="bg-white rounded-lg shadow-md p-6">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm font-medium text-gray-600">Average CVSS</p>
                        <p className="text-2xl font-bold text-gray-800">
                          {vulnerabilities.length > 0 ? 
                            (vulnerabilities.reduce((sum, v) => sum + v.cvss, 0) / vulnerabilities.length).toFixed(1) 
                            : '0.0'}
                        </p>
                      </div>
                      <Shield className="h-8 w-8 text-gray-600" />
                    </div>
                  </div>
                </div>

                {/* Vulnerability List */}
                <div className="bg-white rounded-lg shadow-md">
                  <div className="p-6 border-b border-gray-200 flex justify-between items-center">
                    <h2 className="text-lg font-semibold">Vulnerability Details</h2>
                    <button
                      onClick={exportReport}
                      className="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700 flex items-center space-x-2"
                    >
                      <Download className="h-4 w-4" />
                      <span>Export Report</span>
                    </button>
                  </div>
                  <div className="divide-y divide-gray-200">
                    {vulnerabilities.map((vuln) => (
                      <div key={vuln.id} className="p-6">
                        <div className="flex items-start justify-between mb-3">
                          <div className="flex items-center space-x-3">
                            <div className={`p-2 rounded-full border ${getSeverityColor(vuln.severity)}`}>
                              {getSeverityIcon(vuln.severity)}
                            </div>
                            <div>
                              <h3 className="font-semibold text-gray-800">{vuln.name}</h3>
                              <p className="text-sm text-gray-500">{vuln.location}</p>
                            </div>
                          </div>
                          <div className="text-right">
                            <span className={`px-3 py-1 rounded-full text-xs font-medium border ${getSeverityColor(vuln.severity)}`}>
                              {vuln.severity}
                            </span>
                            <div className="text-sm text-gray-500 mt-1">CVSS: {vuln.cvss}</div>
                          </div>
                        </div>
                        
                        <div className="ml-14 space-y-3">
                          <div>
                            <h4 className="font-medium text-gray-700">Description</h4>
                            <p className="text-sm text-gray-600">{vuln.description}</p>
                          </div>
                          
                          <div>
                            <h4 className="font-medium text-gray-700">Remediation</h4>
                            <p className="text-sm text-gray-600">{vuln.remediation}</p>
                          </div>
                          
                          <div className="flex items-center space-x-4 text-xs text-gray-500">
                            <span>CWE: {vuln.cwe}</span>
                            <span>Discovered: {vuln.discoveredAt.toLocaleString()}</span>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </>
            )}
            
            {vulnerabilities.length === 0 && (
              <div className="bg-white rounded-lg shadow-md p-12 text-center">
                <Search className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-gray-900 mb-2">No Scan Results</h3>
                <p className="text-gray-500">Run a vulnerability scan to see results here.</p>
              </div>
            )}
          </div>
        )}

        {selectedTab === 'history' && (
          <div className="max-w-4xl mx-auto">
            <div className="bg-white rounded-lg shadow-md">
              <div className="p-6 border-b border-gray-200">
                <h2 className="text-lg font-semibold">Scan History</h2>
              </div>
              <div className="divide-y divide-gray-200">
                {scanHistory.length === 0 ? (
                  <div className="p-12 text-center">
                    <Clock className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                    <h3 className="text-lg font-medium text-gray-900 mb-2">No Scan History</h3>
                    <p className="text-gray-500">Your completed scans will appear here.</p>
                  </div>
                ) : (
                  scanHistory.map((scan) => (
                    <div key={scan.id} className="p-6">
                      <div className="flex items-center justify-between">
                        <div>
                          <h3 className="font-semibold text-gray-800">{scan.target}</h3>
                          <p className="text-sm text-gray-500">
                            {scanTypes[scan.type].name} • {scan.startTime.toLocaleString()}
                          </p>
                        </div>
                        <div className="text-right">
                          <div className="flex items-center space-x-2 mb-1">
                            <span className="text-sm font-medium">
                              {scan.vulnerabilities} vulnerabilities
                            </span>
                            {scan.criticalCount > 0 && (
                              <span className="px-2 py-1 bg-red-100 text-red-600 text-xs rounded-full">
                                {scan.criticalCount} Critical
                              </span>
                            )}
                          </div>
                          <div className="text-xs text-gray-500">{scan.id}</div>
                        </div>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        )}

        {selectedTab === 'reports' && (
          <div className="max-w-4xl mx-auto">
            <div className="bg-white rounded-lg shadow-md">
              <div className="p-6 border-b border-gray-200">
                <h2 className="text-lg font-semibold">Security Reports</h2>
              </div>
              <div className="p-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div className="border rounded-lg p-6">
                    <h3 className="font-semibold mb-2">Vulnerability Report</h3>
                    <p className="text-sm text-gray-600 mb-4">
                      Detailed vulnerability assessment with remediation steps
                    </p>
                    <button 
                      onClick={exportReport}
                      disabled={vulnerabilities.length === 0}
                      className="w-full bg-blue-600 text-white py-2 px-4 rounded-md hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed flex items-center justify-center space-x-2 transition-colors"
                    >
                      <Download className="h-4 w-4" />
                      <span>Generate Report</span>
                    </button>
                  </div>
                  
                  <div className="border rounded-lg p-6">
                    <h3 className="font-semibold mb-2">Executive Summary</h3>
                    <p className="text-sm text-gray-600 mb-4">
                      High-level security assessment for management
                    </p>
                    <button 
                      disabled={vulnerabilities.length === 0}
                      className="w-full bg-green-600 text-white py-2 px-4 rounded-md hover:bg-green-700 disabled:bg-gray-400 disabled:cursor-not-allowed flex items-center justify-center space-x-2 transition-colors"
                    >
                      <Download className="h-4 w-4" />
                      <span>Generate Summary</span>
                    </button>
                  </div>
                  
                  <div className="border rounded-lg p-6">
                    <h3 className="font-semibold mb-2">Compliance Report</h3>
                    <p className="text-sm text-gray-600 mb-4">
                      OWASP, NIST, and industry compliance assessment
                    </p>
                    <button 
                      disabled={vulnerabilities.length === 0}
                      className="w-full bg-purple-600 text-white py-2 px-4 rounded-md hover:bg-purple-700 disabled:bg-gray-400 disabled:cursor-not-allowed flex items-center justify-center space-x-2 transition-colors"
                    >
                      <Download className="h-4 w-4" />
                      <span>Generate Compliance</span>
                    </button>
                  </div>
                  
                  <div className="border rounded-lg p-6">
                    <h3 className="font-semibold mb-2">Remediation Plan</h3>
                    <p className="text-sm text-gray-600 mb-4">
                      Prioritized action plan with timelines
                    </p>
                    <button 
                      disabled={vulnerabilities.length === 0}
                      className="w-full bg-orange-600 text-white py-2 px-4 rounded-md hover:bg-orange-700 disabled:bg-gray-400 disabled:cursor-not-allowed flex items-center justify-center space-x-2 transition-colors"
                    >
                      <Download className="h-4 w-4" />
                      <span>Generate Plan</span>
                    </button>
                  </div>
                </div>
                
                {vulnerabilities.length === 0 && (
                  <div className="mt-6 p-4 bg-yellow-50 border border-yellow-200 rounded-lg">
                    <div className="flex items-center">
                      <AlertTriangle className="h-5 w-5 text-yellow-600 mr-2" />
                      <span className="text-sm text-yellow-800">
                        Complete a vulnerability scan to generate reports
                      </span>
                    </div>
                  </div>
                )}
                
                <div className="mt-8">
                  <h3 className="font-semibold mb-4">Recent Reports</h3>
                  <div className="space-y-3">
                    {[
                      { name: 'Security Assessment - example.com', date: '2024-08-03 14:30', type: 'Vulnerability Report', size: '2.4 MB' },
                      { name: 'Executive Summary - api.example.com', date: '2024-08-02 09:15', type: 'Executive Summary', size: '156 KB' },
                      { name: 'OWASP Compliance - shop.example.com', date: '2024-08-01 16:45', type: 'Compliance Report', size: '890 KB' }
                    ].map((report, index) => (
                      <div key={index} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                        <div className="flex items-center space-x-3">
                          <div className="p-2 bg-blue-100 rounded">
                            <Download className="h-4 w-4 text-blue-600" />
                          </div>
                          <div>
                            <div className="font-medium text-sm">{report.name}</div>
                            <div className="text-xs text-gray-500">{report.type} • {report.size}</div>
                          </div>
                        </div>
                        <div className="text-xs text-gray-500">{report.date}</div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}
      </main>
      
      {/* Footer */}
      <footer className="bg-gray-900 text-white p-6 mt-12">
        <div className="max-w-6xl mx-auto grid grid-cols-1 md:grid-cols-3 gap-8">
          <div>
            <h3 className="font-semibold mb-3">VulnGuard Scanner</h3>
            <p className="text-sm text-gray-400">
              Professional-grade vulnerability assessment platform for comprehensive security testing.
            </p>
          </div>
          
          <div>
            <h3 className="font-semibold mb-3">Scan Capabilities</h3>
            <ul className="text-sm text-gray-400 space-y-1">
              <li>OWASP Top 10 Detection</li>
              <li>Network Port Scanning</li>
              <li>SSL/TLS Configuration Analysis</li>
              <li>Web Application Testing</li>
              <li>API Security Assessment</li>
            </ul>
          </div>
          
          <div>
            <h3 className="font-semibold mb-3">Compliance Standards</h3>
            <ul className="text-sm text-gray-400 space-y-1">
              <li>NIST Cybersecurity Framework</li>
              <li>OWASP Security Guidelines</li>
              <li>PCI DSS Requirements</li>
              <li>ISO 27001 Standards</li>
              <li>GDPR Security Measures</li>
            </ul>
          </div>
        </div>
        
        <div className="max-w-6xl mx-auto mt-8 pt-8 border-t border-gray-800 flex items-center justify-between">
          <div className="text-sm text-gray-400">
            © 2024 VulnGuard Scanner. Professional Security Assessment Platform.
          </div>
          <div className="flex items-center space-x-4 text-sm text-gray-400">
            <span>Version 2.1.0</span>
            <span>•</span>
            <span>CVE Database Updated</span>
            <span>•</span>
            <div className="flex items-center space-x-1">
              <div className="w-2 h-2 bg-green-500 rounded-full"></div>
              <span>Online</span>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default VulnScanner;