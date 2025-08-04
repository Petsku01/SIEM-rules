import React, { useState, useEffect } from 'react';
import { Shield, AlertTriangle, CheckCircle, Search, Smartphone, Globe, Lock, AlertCircle } from 'lucide-react';

const SecurityMonitorApp = () => {
  const [email, setEmail] = useState('');
  const [phoneNumber, setPhoneNumber] = useState('');
  const [isChecking, setIsChecking] = useState(false);
  const [breachResults, setBreachResults] = useState(null);
  const [systemStatus, setSystemStatus] = useState(null);
  const [errors, setErrors] = useState({});

  // Email validation function
  const validateEmail = (email) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  };

  // Phone validation function
  const validatePhone = (phone) => {
    const phoneRegex = /^[\d\s\-\+\(\)]+$/;
    return phone.length >= 10 && phoneRegex.test(phone);
  };

  // Simulate breach check (in production, this would call actual APIs)
  const checkDataBreaches = async () => {
    try {
      // Validate inputs
      const newErrors = {};
      
      if (!email && !phoneNumber) {
        newErrors.general = 'Please enter at least an email or phone number to check';
        setErrors(newErrors);
        return;
      }

      if (email && !validateEmail(email)) {
        newErrors.email = 'Please enter a valid email address';
      }

      if (phoneNumber && !validatePhone(phoneNumber)) {
        newErrors.phone = 'Please enter a valid phone number';
      }

      if (Object.keys(newErrors).length > 0) {
        setErrors(newErrors);
        return;
      }

      setErrors({});
      setIsChecking(true);
      
      // Simulate API delay
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      // Simulated breach data (in production, use actual breach detection APIs)
      const mockBreachData = {
        email: email ? {
          breached: Math.random() > 0.7,
          breaches: Math.random() > 0.5 ? [
            {
              name: 'Example Service',
              date: '2023-05-15',
              dataTypes: ['Email addresses', 'Passwords', 'Names']
            },
            {
              name: 'Social Platform',
              date: '2022-11-20',
              dataTypes: ['Email addresses', 'Phone numbers']
            }
          ] : []
        } : null,
        phone: phoneNumber ? {
          breached: Math.random() > 0.8,
          exposures: Math.random() > 0.5 ? [
            {
              source: 'Data Broker Site',
              exposed: ['Phone number', 'Name', 'Address']
            }
          ] : []
        } : null
      };

      setBreachResults(mockBreachData);
    } catch (error) {
      console.error('Error checking breaches:', error);
      setErrors({ general: 'An error occurred while checking for breaches. Please try again.' });
    } finally {
      setIsChecking(false);
    }
  };

  // Check system security status
  const checkSystemSecurity = async () => {
    try {
      setIsChecking(true);
      
      // Simulate system checks
      await new Promise(resolve => setTimeout(resolve, 1500));
      
      // Browser/system security checks
      const securityChecks = {
        httpsConnection: window.location.protocol === 'https:',
        // Check for suspicious browser extensions (simplified)
        suspiciousActivity: false,
        // Check browser permissions
        locationEnabled: 'geolocation' in navigator,
        // Check for common security indicators
        doNotTrack: navigator.doNotTrack === '1',
        // Platform info
        platform: navigator.platform || 'Unknown',
        // Connection info
        connectionType: navigator.connection?.effectiveType || 'Unknown'
      };

      // Calculate security score
      let score = 100;
      if (!securityChecks.httpsConnection) score -= 30;
      if (securityChecks.locationEnabled) score -= 10;
      if (!securityChecks.doNotTrack) score -= 10;

      setSystemStatus({
        ...securityChecks,
        securityScore: score,
        recommendations: generateRecommendations(securityChecks, score)
      });
    } catch (error) {
      console.error('Error checking system security:', error);
      setErrors({ system: 'Unable to check system security status' });
    } finally {
      setIsChecking(false);
    }
  };

  // Generate security recommendations based on findings
  const generateRecommendations = (checks, score) => {
    const recommendations = [];
    
    if (!checks.httpsConnection) {
      recommendations.push({
        severity: 'high',
        message: 'You are not using a secure HTTPS connection',
        action: 'Ensure you are accessing websites via HTTPS'
      });
    }
    
    if (score < 70) {
      recommendations.push({
        severity: 'medium',
        message: 'Your security score is below optimal',
        action: 'Review and implement suggested security measures'
      });
    }
    
    if (!checks.doNotTrack) {
      recommendations.push({
        severity: 'low',
        message: 'Do Not Track is not enabled',
        action: 'Enable Do Not Track in your browser settings'
      });
    }

    return recommendations;
  };

  // Clear all results
  const clearResults = () => {
    setBreachResults(null);
    setSystemStatus(null);
    setErrors({});
    setEmail('');
    setPhoneNumber('');
  };

  return (
    <div className="min-h-screen bg-gray-100 p-4">
      <div className="max-w-4xl mx-auto">
        {/* Header */}
        <div className="bg-white rounded-lg shadow-md p-6 mb-6">
          <div className="flex items-center mb-4">
            <Shield className="w-8 h-8 text-blue-600 mr-3" />
            <h1 className="text-2xl font-bold text-gray-800">Personal Security Monitor</h1>
          </div>
          <p className="text-gray-600">Check if your data has been exposed in breaches and monitor your system security</p>
        </div>

        {/* Input Section */}
        <div className="bg-white rounded-lg shadow-md p-6 mb-6">
          <h2 className="text-xl font-semibold mb-4 flex items-center">
            <Search className="w-5 h-5 mr-2" />
            Check Data Breaches
          </h2>
          
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Email Address
              </label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="your.email@example.com"
                className={`w-full px-3 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent ${
                  errors.email ? 'border-red-500' : 'border-gray-300'
                }`}
                disabled={isChecking}
              />
              {errors.email && (
                <p className="text-red-500 text-sm mt-1">{errors.email}</p>
              )}
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Phone Number
              </label>
              <input
                type="tel"
                value={phoneNumber}
                onChange={(e) => setPhoneNumber(e.target.value)}
                placeholder="+1 (555) 123-4567"
                className={`w-full px-3 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent ${
                  errors.phone ? 'border-red-500' : 'border-gray-300'
                }`}
                disabled={isChecking}
              />
              {errors.phone && (
                <p className="text-red-500 text-sm mt-1">{errors.phone}</p>
              )}
            </div>

            {errors.general && (
              <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
                {errors.general}
              </div>
            )}

            <div className="flex gap-3">
              <button
                onClick={checkDataBreaches}
                disabled={isChecking}
                className="flex-1 bg-blue-600 text-white py-2 px-4 rounded-lg hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition duration-200"
              >
                {isChecking ? 'Checking...' : 'Check for Breaches'}
              </button>
              
              <button
                onClick={checkSystemSecurity}
                disabled={isChecking}
                className="flex-1 bg-green-600 text-white py-2 px-4 rounded-lg hover:bg-green-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition duration-200"
              >
                {isChecking ? 'Scanning...' : 'Scan System Security'}
              </button>
            </div>
          </div>
        </div>

        {/* Breach Results */}
        {breachResults && (
          <div className="bg-white rounded-lg shadow-md p-6 mb-6">
            <h2 className="text-xl font-semibold mb-4 flex items-center">
              <Globe className="w-5 h-5 mr-2" />
              Data Breach Results
            </h2>

            {breachResults.email && (
              <div className="mb-4">
                <h3 className="font-medium mb-2">Email: {email}</h3>
                {breachResults.email.breached ? (
                  <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-3">
                    <div className="flex items-center">
                      <AlertTriangle className="w-5 h-5 mr-2" />
                      <span className="font-semibold">Email found in data breaches!</span>
                    </div>
                  </div>
                ) : (
                  <div className="bg-green-100 border border-green-400 text-green-700 px-4 py-3 rounded mb-3">
                    <div className="flex items-center">
                      <CheckCircle className="w-5 h-5 mr-2" />
                      <span>No breaches found for this email</span>
                    </div>
                  </div>
                )}
                
                {breachResults.email.breaches && breachResults.email.breaches.length > 0 && (
                  <div className="space-y-3">
                    {breachResults.email.breaches.map((breach, index) => (
                      <div key={index} className="border border-gray-200 rounded p-3">
                        <h4 className="font-semibold">{breach.name}</h4>
                        <p className="text-sm text-gray-600">Date: {breach.date}</p>
                        <p className="text-sm text-gray-600">
                          Exposed data: {breach.dataTypes.join(', ')}
                        </p>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {breachResults.phone && (
              <div>
                <h3 className="font-medium mb-2">Phone: {phoneNumber}</h3>
                {breachResults.phone.breached ? (
                  <div className="bg-yellow-100 border border-yellow-400 text-yellow-700 px-4 py-3 rounded">
                    <div className="flex items-center">
                      <AlertCircle className="w-5 h-5 mr-2" />
                      <span>Phone number may be exposed online</span>
                    </div>
                  </div>
                ) : (
                  <div className="bg-green-100 border border-green-400 text-green-700 px-4 py-3 rounded">
                    <div className="flex items-center">
                      <CheckCircle className="w-5 h-5 mr-2" />
                      <span>Phone number appears secure</span>
                    </div>
                  </div>
                )}

                {breachResults.phone.exposures && breachResults.phone.exposures.length > 0 && (
                  <div className="mt-3 space-y-2">
                    {breachResults.phone.exposures.map((exposure, index) => (
                      <div key={index} className="border border-gray-200 rounded p-3">
                        <h4 className="font-semibold">{exposure.source}</h4>
                        <p className="text-sm text-gray-600">
                          Exposed: {exposure.exposed.join(', ')}
                        </p>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* System Security Status */}
        {systemStatus && (
          <div className="bg-white rounded-lg shadow-md p-6 mb-6">
            <h2 className="text-xl font-semibold mb-4 flex items-center">
              <Smartphone className="w-5 h-5 mr-2" />
              System Security Status
            </h2>

            <div className="mb-4">
              <div className="flex items-center justify-between mb-2">
                <span className="font-medium">Security Score</span>
                <span className={`text-2xl font-bold ${
                  systemStatus.securityScore >= 80 ? 'text-green-600' :
                  systemStatus.securityScore >= 60 ? 'text-yellow-600' : 'text-red-600'
                }`}>
                  {systemStatus.securityScore}%
                </span>
              </div>
              <div className="w-full bg-gray-200 rounded-full h-4">
                <div
                  className={`h-4 rounded-full transition-all duration-500 ${
                    systemStatus.securityScore >= 80 ? 'bg-green-600' :
                    systemStatus.securityScore >= 60 ? 'bg-yellow-600' : 'bg-red-600'
                  }`}
                  style={{ width: `${systemStatus.securityScore}%` }}
                />
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mb-4">
              <div className="flex items-center">
                <Lock className={`w-4 h-4 mr-2 ${systemStatus.httpsConnection ? 'text-green-600' : 'text-red-600'}`} />
                <span className="text-sm">
                  HTTPS: {systemStatus.httpsConnection ? 'Secured' : 'Not Secured'}
                </span>
              </div>
              <div className="flex items-center">
                <Shield className="w-4 h-4 mr-2 text-gray-600" />
                <span className="text-sm">Platform: {systemStatus.platform}</span>
              </div>
              <div className="flex items-center">
                <Globe className="w-4 h-4 mr-2 text-gray-600" />
                <span className="text-sm">Connection: {systemStatus.connectionType}</span>
              </div>
              <div className="flex items-center">
                <AlertCircle className={`w-4 h-4 mr-2 ${systemStatus.doNotTrack ? 'text-green-600' : 'text-yellow-600'}`} />
                <span className="text-sm">
                  Do Not Track: {systemStatus.doNotTrack ? 'Enabled' : 'Disabled'}
                </span>
              </div>
            </div>

            {systemStatus.recommendations && systemStatus.recommendations.length > 0 && (
              <div>
                <h3 className="font-semibold mb-2">Security Recommendations</h3>
                <div className="space-y-2">
                  {systemStatus.recommendations.map((rec, index) => (
                    <div
                      key={index}
                      className={`p-3 rounded border ${
                        rec.severity === 'high' ? 'bg-red-50 border-red-200' :
                        rec.severity === 'medium' ? 'bg-yellow-50 border-yellow-200' :
                        'bg-blue-50 border-blue-200'
                      }`}
                    >
                      <p className="font-medium text-sm">{rec.message}</p>
                      <p className="text-sm text-gray-600 mt-1">Action: {rec.action}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Clear Results Button */}
        {(breachResults || systemStatus) && (
          <div className="text-center">
            <button
              onClick={clearResults}
              className="bg-gray-600 text-white py-2 px-6 rounded-lg hover:bg-gray-700 transition duration-200"
            >
              Clear All Results
            </button>
          </div>
        )}

        {/* Error handling for system errors */}
        {errors.system && (
          <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mt-4">
            <div className="flex items-center">
              <AlertTriangle className="w-5 h-5 mr-2" />
              <span>{errors.system}</span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default SecurityMonitorApp;