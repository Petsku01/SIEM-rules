import React, { useState, useEffect } from 'react';
import { Shield, AlertTriangle, Eye, Lock, Zap, Users, Server, Activity, TrendingUp, TrendingDown, Bell, CheckCircle, XCircle, Clock, Globe, Wifi, Database, Terminal } from 'lucide-react';

const SOCDashboard = () => {
  const [currentTime, setCurrentTime] = useState(new Date());
  const [threats, setThreats] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [networkStats, setNetworkStats] = useState({});
  const [selectedTab, setSelectedTab] = useState('overview');

  // Simulate real-time data updates
  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentTime(new Date());
      generateThreatData();
      generateIncidentData();
      generateNetworkStats();
    }, 3000);

    // Initial data generation
    generateThreatData();
    generateIncidentData();
    generateNetworkStats();

    return () => clearInterval(timer);
  }, []);

  const generateThreatData = () => {
    const threatTypes = ['Malware', 'Phishing', 'DDoS', 'Brute Force', 'SQL Injection', 'XSS', 'Insider Threat'];
    const sources = ['Firewall', 'IDS/IPS', 'Endpoint', 'SIEM', 'Email Gateway', 'Web Proxy'];
    const severities = ['Critical', 'High', 'Medium', 'Low'];
    
    const newThreats = Array.from({ length: Math.floor(Math.random() * 3) + 1 }, () => ({
      id: Math.random().toString(36).substr(2, 9),
      type: threatTypes[Math.floor(Math.random() * threatTypes.length)],
      source: sources[Math.floor(Math.random() * sources.length)],
      severity: severities[Math.floor(Math.random() * severities.length)],
      ip: `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
      timestamp: new Date(),
      blocked: Math.random() > 0.3
    }));

    setThreats(prev => [...newThreats, ...prev].slice(0, 50));
  };

  const generateIncidentData = () => {
    const incidentTypes = ['Security Breach', 'Policy Violation', 'System Compromise', 'Data Leak', 'Unauthorized Access'];
    const statuses = ['Open', 'In Progress', 'Resolved', 'Closed'];
    
    if (Math.random() > 0.7) {
      const newIncident = {
        id: `INC-${Math.random().toString(36).substr(2, 6).toUpperCase()}`,
        type: incidentTypes[Math.floor(Math.random() * incidentTypes.length)],
        status: statuses[Math.floor(Math.random() * statuses.length)],
        priority: ['P1', 'P2', 'P3', 'P4'][Math.floor(Math.random() * 4)],
        assignee: ['John Doe', 'Jane Smith', 'Mike Johnson', 'Sarah Wilson'][Math.floor(Math.random() * 4)],
        created: new Date(),
        description: 'Automated detection of suspicious activity requiring investigation'
      };
      
      setIncidents(prev => [newIncident, ...prev].slice(0, 20));
    }
  };

  const generateNetworkStats = () => {
    setNetworkStats({
      totalConnections: Math.floor(Math.random() * 10000) + 5000,
      blockedAttempts: Math.floor(Math.random() * 500) + 100,
      dataTransfer: (Math.random() * 100 + 50).toFixed(2),
      activeUsers: Math.floor(Math.random() * 1000) + 500,
      systemHealth: Math.floor(Math.random() * 30) + 70,
      threatLevel: Math.floor(Math.random() * 5) + 1
    });
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'Critical': return 'text-red-600 bg-red-100';
      case 'High': return 'text-orange-600 bg-orange-100';
      case 'Medium': return 'text-yellow-600 bg-yellow-100';
      case 'Low': return 'text-green-600 bg-green-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'Open': return 'text-red-600 bg-red-100';
      case 'In Progress': return 'text-blue-600 bg-blue-100';
      case 'Resolved': return 'text-green-600 bg-green-100';
      case 'Closed': return 'text-gray-600 bg-gray-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const StatCard = ({ title, value, icon: Icon, trend, color = 'blue' }) => {
    const colorClasses = {
      blue: { bg: 'bg-blue-100', text: 'text-blue-600', border: 'border-blue-500' },
      red: { bg: 'bg-red-100', text: 'text-red-600', border: 'border-red-500' },
      orange: { bg: 'bg-orange-100', text: 'text-orange-600', border: 'border-orange-500' },
      green: { bg: 'bg-green-100', text: 'text-green-600', border: 'border-green-500' }
    };
    
    const currentColor = colorClasses[color] || colorClasses.blue;
    
    return (
      <div className={`bg-white rounded-lg shadow-md p-6 border-l-4 ${currentColor.border}`}>
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm font-medium text-gray-600">{title}</p>
            <p className="text-2xl font-bold text-gray-800">{value}</p>
          </div>
          <div className={`p-3 rounded-full ${currentColor.bg}`}>
            <Icon className={`h-6 w-6 ${currentColor.text}`} />
          </div>
        </div>
        {trend !== undefined && trend !== 0 && (
          <div className="flex items-center mt-2">
            {trend > 0 ? (
              <TrendingUp className="h-4 w-4 text-green-500 mr-1" />
            ) : (
              <TrendingDown className="h-4 w-4 text-red-500 mr-1" />
            )}
            <span className={`text-sm ${trend > 0 ? 'text-green-600' : 'text-red-600'}`}>
              {Math.abs(trend)}% from last hour
            </span>
          </div>
        )}
      </div>
    );
  };

  const ThreatMap = () => (
    <div className="bg-white rounded-lg shadow-md p-6">
      <h3 className="text-lg font-semibold mb-4 flex items-center">
        <Globe className="h-5 w-5 mr-2 text-blue-600" />
        Global Threat Map
      </h3>
      <div className="relative bg-gray-900 rounded-lg p-8 h-64 overflow-hidden">
        <div className="absolute inset-0 flex items-center justify-center">
          <div className="text-green-400 font-mono text-sm space-y-1">
            <div className="animate-pulse">├── Monitoring 247 global endpoints...</div>
            <div className="animate-pulse delay-100">├── Active threats detected: {threats.length}</div>
            <div className="animate-pulse delay-200">├── Blocked connections: {networkStats.blockedAttempts}</div>
            <div className="animate-pulse delay-300">└── System status: SECURE</div>
          </div>
        </div>
        {Array.from({ length: 20 }).map((_, i) => (
          <div
            key={i}
            className="absolute w-2 h-2 bg-red-500 rounded-full animate-ping"
            style={{
              left: `${Math.random() * 90}%`,
              top: `${Math.random() * 80}%`,
              animationDelay: `${Math.random() * 2}s`
            }}
          />
        ))}
      </div>
    </div>
  );

  const ThreatIntelligence = () => (
    <div className="bg-white rounded-lg shadow-md p-6">
      <h3 className="text-lg font-semibold mb-4 flex items-center">
        <Shield className="h-5 w-5 mr-2 text-blue-600" />
        Real-Time Threat Intelligence
      </h3>
      <div className="space-y-3 max-h-80 overflow-y-auto">
        {threats.slice(0, 10).map((threat) => (
          <div key={threat.id} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
            <div className="flex items-center space-x-3">
              <div className={`w-3 h-3 rounded-full ${threat.blocked ? 'bg-green-500' : 'bg-red-500'}`} />
              <div>
                <div className="font-medium text-sm">{threat.type}</div>
                <div className="text-xs text-gray-500">{threat.ip} • {threat.source}</div>
              </div>
            </div>
            <div className="flex items-center space-x-2">
              <span className={`px-2 py-1 rounded-full text-xs font-medium ${getSeverityColor(threat.severity)}`}>
                {threat.severity}
              </span>
              <span className="text-xs text-gray-500">
                {threat.timestamp.toLocaleTimeString()}
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );

  const IncidentResponse = () => (
    <div className="bg-white rounded-lg shadow-md p-6">
      <h3 className="text-lg font-semibold mb-4 flex items-center">
        <Bell className="h-5 w-5 mr-2 text-blue-600" />
        Incident Response Queue
      </h3>
      <div className="space-y-3 max-h-80 overflow-y-auto">
        {incidents.map((incident) => (
          <div key={incident.id} className="border rounded-lg p-4">
            <div className="flex items-center justify-between mb-2">
              <div className="font-medium text-sm">{incident.id}</div>
              <span className={`px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(incident.status)}`}>
                {incident.status}
              </span>
            </div>
            <div className="text-sm text-gray-600 mb-2">{incident.type}</div>
            <div className="flex items-center justify-between text-xs text-gray-500">
              <span>Assigned: {incident.assignee}</span>
              <span>{incident.priority}</span>
              <span>{incident.created.toLocaleTimeString()}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );

  const SecurityMetrics = () => (
    <div className="bg-white rounded-lg shadow-md p-6">
      <h3 className="text-lg font-semibold mb-4 flex items-center">
        <Activity className="h-5 w-5 mr-2 text-blue-600" />
        Security Metrics
      </h3>
      <div className="space-y-4">
        <div>
          <div className="flex justify-between text-sm mb-1">
            <span>System Health</span>
            <span>{networkStats.systemHealth}%</span>
          </div>
          <div className="w-full bg-gray-200 rounded-full h-2">
            <div 
              className="bg-green-500 h-2 rounded-full transition-all duration-500"
              style={{ width: `${networkStats.systemHealth}%` }}
            />
          </div>
        </div>
        <div>
          <div className="flex justify-between text-sm mb-1">
            <span>Threat Level</span>
            <span>{networkStats.threatLevel}/5</span>
          </div>
          <div className="w-full bg-gray-200 rounded-full h-2">
            <div 
              className="bg-yellow-500 h-2 rounded-full transition-all duration-500"
              style={{ width: `${(networkStats.threatLevel / 5) * 100}%` }}
            />
          </div>
        </div>
        <div className="grid grid-cols-2 gap-4 mt-4">
          <div className="text-center p-3 bg-blue-50 rounded-lg">
            <div className="text-2xl font-bold text-blue-600">{networkStats.activeUsers}</div>
            <div className="text-sm text-gray-600">Active Users</div>
          </div>
          <div className="text-center p-3 bg-green-50 rounded-lg">
            <div className="text-2xl font-bold text-green-600">{networkStats.dataTransfer} GB</div>
            <div className="text-sm text-gray-600">Data Transfer</div>
          </div>
        </div>
      </div>
    </div>
  );

  return (
    <div className="min-h-screen bg-gray-100">
      {/* Header */}
      <header className="bg-gray-900 text-white p-4 shadow-lg">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <Shield className="h-8 w-8 text-blue-400" />
            <div>
              <h1 className="text-xl font-bold">CyberGuard SOC</h1>
              <p className="text-sm text-gray-400">Security Operations Center</p>
            </div>
          </div>
          <div className="flex items-center space-x-4">
            <div className="text-right">
              <div className="text-sm font-medium">{currentTime.toLocaleDateString()}</div>
              <div className="text-xs text-gray-400">{currentTime.toLocaleTimeString()}</div>
            </div>
            <div className="flex items-center space-x-2">
              <div className="w-3 h-3 bg-green-500 rounded-full animate-pulse" />
              <span className="text-sm">Systems Online</span>
            </div>
          </div>
        </div>
      </header>

      {/* Navigation */}
      <nav className="bg-white shadow-sm border-b">
        <div className="px-4">
          <div className="flex space-x-8">
            {[
              { id: 'overview', label: 'Overview', icon: Eye },
              { id: 'threats', label: 'Threats', icon: AlertTriangle },
              { id: 'incidents', label: 'Incidents', icon: Bell },
              { id: 'network', label: 'Network', icon: Wifi }
            ].map(({ id, label, icon: Icon }) => (
              <button
                key={id}
                onClick={() => setSelectedTab(id)}
                className={`flex items-center space-x-2 py-4 px-2 border-b-2 font-medium text-sm ${
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
        {selectedTab === 'overview' && (
          <div className="space-y-6">
            {/* Stats Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
              <StatCard
                title="Total Connections"
                value={networkStats.totalConnections?.toLocaleString() || '0'}
                icon={Server}
                trend={5}
                color="blue"
              />
              <StatCard
                title="Blocked Threats"
                value={networkStats.blockedAttempts?.toLocaleString() || '0'}
                icon={Shield}
                trend={Math.random() > 0.5 ? Math.floor(Math.random() * 10) - 5 : 0}
                color="red"
              />
              <StatCard
                title="Active Incidents"
                value={incidents.filter(i => i.status === 'Open').length}
                icon={AlertTriangle}
                trend={incidents.filter(i => i.status === 'Open').length > 5 ? -2 : incidents.filter(i => i.status === 'Open').length > 2 ? 1 : 0}
                color="orange"
              />
              <StatCard
                title="System Health"
                value={`${networkStats.systemHealth || 0}%`}
                icon={Activity}
                trend={networkStats.systemHealth > 85 ? 3 : networkStats.systemHealth < 70 ? -3 : 0}
                color="green"
              />
            </div>

            {/* Main Dashboard Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <ThreatMap />
              <ThreatIntelligence />
              <IncidentResponse />
              <SecurityMetrics />
            </div>
          </div>
        )}

        {selectedTab === 'threats' && (
          <div className="space-y-6">
            <ThreatIntelligence />
            <div className="bg-white rounded-lg shadow-md p-6">
              <h3 className="text-lg font-semibold mb-4">Threat Analysis</h3>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="p-4 bg-red-50 rounded-lg">
                  <div className="text-2xl font-bold text-red-600">{threats.filter(t => t.severity === 'Critical').length}</div>
                  <div className="text-sm text-gray-600">Critical Threats</div>
                </div>
                <div className="p-4 bg-yellow-50 rounded-lg">
                  <div className="text-2xl font-bold text-yellow-600">{threats.filter(t => t.blocked).length}</div>
                  <div className="text-sm text-gray-600">Blocked Threats</div>
                </div>
                <div className="p-4 bg-blue-50 rounded-lg">
                  <div className="text-2xl font-bold text-blue-600">{new Set(threats.map(t => t.ip)).size}</div>
                  <div className="text-sm text-gray-600">Unique IPs</div>
                </div>
              </div>
            </div>
          </div>
        )}

        {selectedTab === 'incidents' && (
          <div className="space-y-6">
            <IncidentResponse />
            <div className="bg-white rounded-lg shadow-md p-6">
              <h3 className="text-lg font-semibold mb-4">Incident Statistics</h3>
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                {['Open', 'In Progress', 'Resolved', 'Closed'].map(status => (
                  <div key={status} className="p-4 bg-gray-50 rounded-lg">
                    <div className="text-2xl font-bold text-gray-800">
                      {incidents.filter(i => i.status === status).length}
                    </div>
                    <div className="text-sm text-gray-600">{status}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {selectedTab === 'network' && (
          <div className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="bg-white rounded-lg shadow-md p-6">
                <h3 className="text-lg font-semibold mb-4 flex items-center">
                  <Terminal className="h-5 w-5 mr-2 text-blue-600" />
                  Network Activity
                </h3>
                <div className="space-y-4">
                  <div className="flex justify-between">
                    <span>Bandwidth Usage</span>
                    <span className="font-medium">{networkStats.dataTransfer} GB/s</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Active Connections</span>
                    <span className="font-medium">{networkStats.totalConnections}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Dropped Packets</span>
                    <span className="font-medium">0.02%</span>
                  </div>
                </div>
              </div>
              <SecurityMetrics />
            </div>
          </div>
        )}
      </main>
    </div>
  );
};

export default SOCDashboard;