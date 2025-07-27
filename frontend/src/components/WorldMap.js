import React, { useState, useEffect } from "react";
import { threatAPI } from "../services/api";

// Real-time update hook
const useRealTimeUpdates = (interval = 30000) => {
  const [lastUpdate, setLastUpdate] = useState(new Date());

  useEffect(() => {
    const timer = setInterval(() => {
      setLastUpdate(new Date());
    }, interval);

    return () => clearInterval(timer);
  }, [interval]);

  return lastUpdate;
};

// Country positions for threat markers (adjusted for 2D flat world map)
const countryPositions = {
  US: { x: 25, y: 45, name: "United States" },
  CA: { x: 23, y: 32, name: "Canada" },
  MX: { x: 22, y: 55, name: "Mexico" },
  BR: { x: 35, y: 68, name: "Brazil" },
  AR: { x: 35, y: 78, name: "Argentina" },
  GB: { x: 49, y: 38, name: "United Kingdom" },
  FR: { x: 51, y: 42, name: "France" },
  DE: { x: 53, y: 39, name: "Germany" },
  ES: { x: 48, y: 47, name: "Spain" },
  IT: { x: 53, y: 47, name: "Italy" },
  RU: { x: 70, y: 32, name: "Russia" },
  CN: { x: 75, y: 47, name: "China" },
  IN: { x: 69, y: 54, name: "India" },
  JP: { x: 82, y: 49, name: "Japan" },
  AU: { x: 79, y: 73, name: "Australia" },
  ZA: { x: 55, y: 75, name: "South Africa" },
  KR: { x: 80, y: 48, name: "South Korea" },
  TH: { x: 73, y: 58, name: "Thailand" },
  SG: { x: 74, y: 63, name: "Singapore" },
  MY: { x: 74, y: 62, name: "Malaysia" },
  NL: { x: 52, y: 40, name: "Netherlands" },
  SE: { x: 54, y: 28, name: "Sweden" },
  NO: { x: 52, y: 25, name: "Norway" },
  FI: { x: 56, y: 24, name: "Finland" },
  PL: { x: 55, y: 37, name: "Poland" },
  CZ: { x: 54, y: 39, name: "Czech Republic" },
  AT: { x: 54, y: 42, name: "Austria" },
  CH: { x: 51, y: 43, name: "Switzerland" }
};


const WorldMap = () => {
  // State declarations
  const [geospatialData, setGeospatialData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [hoveredCountry, setHoveredCountry] = useState(null);
  const [countryThreats, setCountryThreats] = useState({});
  const [mousePosition, setMousePosition] = useState({ x: 0, y: 0 });

  const lastUpdate = useRealTimeUpdates(30000);

  // Enhanced mock threat data that matches the user's structure
  const mockThreatData = [
    // United States - Multiple threats
    {
      id: 1001,
      country: "United States",
      country_code: "US",
      severity: "critical",
      title: "Ransomware Attack Targets Transportation Infrastructure",
      content:
        "LockBit ransomware group has compromised multiple logistics companies across the East Coast, affecting port operations and supply chain systems.",
      confidence: 0.95,
      source: "FBI Cyber Division",
      threat_type: "ransomware",
      attack_vector: "phishing_email",
      collected_at: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
      financial_impact: 50000000,
      affected_systems: [
        "port_management",
        "logistics_tracking",
        "financial_systems",
      ],
      iocs: ["192.168.1.100", "malware.exe", "suspicious-domain.com"],
      mitre_techniques: ["T1566.001", "T1486", "T1055"],
    },
    {
      id: 1002,
      country: "United States",
      country_code: "US",
      severity: "high",
      title: "Supply Chain Compromise in Automotive Sector",
      content:
        "Advanced persistent threat group targeting automotive suppliers with sophisticated spear-phishing campaign.",
      confidence: 0.88,
      source: "CISA Alert AA24-001A",
      threat_type: "supply_chain",
      attack_vector: "spear_phishing",
      collected_at: new Date(Date.now() - 6 * 60 * 60 * 1000).toISOString(),
      financial_impact: 15000000,
      affected_systems: ["manufacturing_control", "inventory_management"],
      iocs: ["evil-supplier.com", "203.0.113.45", "backdoor.dll"],
      mitre_techniques: ["T1566.002", "T1195.002", "T1071.001"],
    },
    {
      id: 1003,
      country: "United States",
      country_code: "US",
      severity: "medium",
      title: "Credential Harvesting Campaign Against Energy Sector",
      content:
        "Threat actors conducting credential harvesting against energy companies using fake Microsoft 365 login pages.",
      confidence: 0.82,
      source: "DHS CISA",
      threat_type: "credential_theft",
      attack_vector: "credential_harvesting",
      collected_at: new Date(Date.now() - 12 * 60 * 60 * 1000).toISOString(),
      financial_impact: 2000000,
      affected_systems: ["email_systems", "identity_management"],
      iocs: ["fake-microsoft365.com", "harvester.php"],
      mitre_techniques: ["T1566.002", "T1056.003", "T1539"],
    },

    // China - State-sponsored activity
    {
      id: 2001,
      country: "China",
      country_code: "CN",
      severity: "critical",
      title: "APT40 Targets Maritime Industry Intelligence",
      content:
        "Chinese state-sponsored group APT40 conducting espionage operations against maritime companies to steal shipping routes and cargo manifests.",
      confidence: 0.92,
      source: "Five Eyes Intelligence Report",
      threat_type: "espionage",
      attack_vector: "zero_day_exploit",
      collected_at: new Date(Date.now() - 1 * 60 * 60 * 1000).toISOString(),
      financial_impact: 75000000,
      affected_systems: [
        "shipping_manifests",
        "route_planning",
        "customer_databases",
      ],
      iocs: ["apt40-c2.example.com", "198.51.100.22", "maritime-stealer.exe"],
      mitre_techniques: ["T1190", "T1083", "T1041"],
      threat_actor: "APT40",
      campaign_name: "Maritime Shadow",
    },
    {
      id: 2002,
      country: "China",
      country_code: "CN",
      severity: "high",
      title: "Intellectual Property Theft in Manufacturing",
      content:
        "Sustained campaign targeting manufacturing blueprints and trade secrets from Western companies.",
      confidence: 0.85,
      source: "US-CERT",
      threat_type: "intellectual_property_theft",
      attack_vector: "watering_hole",
      collected_at: new Date(Date.now() - 8 * 60 * 60 * 1000).toISOString(),
      financial_impact: 30000000,
      affected_systems: [
        "cad_systems",
        "research_databases",
        "engineering_networks",
      ],
      iocs: ["industry-news-fake.com", "blueprint-exfil.dll"],
      mitre_techniques: ["T1189", "T1005", "T1048.003"],
    },

    // Russia - Sophisticated attacks
    {
      id: 3001,
      country: "Russia",
      country_code: "RU",
      severity: "critical",
      title: "Sandworm Targets Critical Infrastructure",
      content:
        "Russian military unit 74455 (Sandworm) launching destructive attacks against power grid and transportation systems.",
      confidence: 0.98,
      source: "NSA Cybersecurity Advisory",
      threat_type: "destructive_attack",
      attack_vector: "supply_chain_compromise",
      collected_at: new Date(Date.now() - 30 * 60 * 1000).toISOString(),
      financial_impact: 200000000,
      affected_systems: ["power_grid", "rail_systems", "industrial_control"],
      iocs: ["sandworm-implant.sys", "203.0.113.100", "energy-disruption.exe"],
      mitre_techniques: ["T1195.002", "T1562.001", "T1485"],
      threat_actor: "Sandworm Team",
      campaign_name: "Grid Blackout",
    },

    // United Kingdom - Financial sector
    {
      id: 4001,
      country: "United Kingdom",
      country_code: "GB",
      severity: "high",
      title: "Banking Trojan Targets UK Financial Institutions",
      content:
        "New variant of Emotet banking trojan specifically targeting UK banks and payment processors.",
      confidence: 0.87,
      source: "NCSC Threat Report",
      threat_type: "banking_trojan",
      attack_vector: "malicious_attachment",
      collected_at: new Date(Date.now() - 4 * 60 * 60 * 1000).toISOString(),
      financial_impact: 25000000,
      affected_systems: [
        "banking_systems",
        "payment_processing",
        "customer_accounts",
      ],
      iocs: ["emotet-uk-variant.exe", "banking-c2.onion", "192.0.2.50"],
      mitre_techniques: ["T1566.001", "T1055", "T1056.001"],
    },
    {
      id: 4002,
      country: "United Kingdom",
      country_code: "GB",
      severity: "medium",
      title: "Retail Point-of-Sale Malware Campaign",
      content:
        "POS malware targeting major UK retail chains during holiday shopping season.",
      confidence: 0.79,
      source: "UK Retail Security Consortium",
      threat_type: "pos_malware",
      attack_vector: "remote_access",
      collected_at: new Date(Date.now() - 18 * 60 * 60 * 1000).toISOString(),
      financial_impact: 8000000,
      affected_systems: ["pos_terminals", "payment_networks"],
      iocs: ["pos-scraper.dll", "retail-exfil.com"],
      mitre_techniques: ["T1210", "T1005", "T1041"],
    },

    // Germany - Industrial sector
    {
      id: 5001,
      country: "Germany",
      country_code: "DE",
      severity: "high",
      title: "Industrial Espionage in Automotive Sector",
      content:
        "Suspected state-sponsored actors targeting German automotive manufacturers to steal electric vehicle technology.",
      confidence: 0.91,
      source: "BSI Cyber Threat Report",
      threat_type: "industrial_espionage",
      attack_vector: "spear_phishing",
      collected_at: new Date(Date.now() - 3 * 60 * 60 * 1000).toISOString(),
      financial_impact: 45000000,
      affected_systems: [
        "engineering_workstations",
        "r_and_d_networks",
        "patent_databases",
      ],
      iocs: ["auto-research.de", "ev-tech-stealer.exe", "198.51.100.75"],
      mitre_techniques: ["T1566.002", "T1083", "T1020"],
    },

    // Japan - Critical infrastructure
    {
      id: 6001,
      country: "Japan",
      country_code: "JP",
      severity: "critical",
      title: "Attack on Tokyo Port Management Systems",
      content:
        "Sophisticated attack targeting Tokyo Port automated container management systems, potentially disrupting Pacific trade routes.",
      confidence: 0.94,
      source: "JPCERT/CC Alert",
      threat_type: "infrastructure_attack",
      attack_vector: "lateral_movement",
      collected_at: new Date(Date.now() - 90 * 60 * 1000).toISOString(),
      financial_impact: 60000000,
      affected_systems: [
        "container_management",
        "crane_control",
        "shipping_schedules",
      ],
      iocs: ["port-malware.bin", "192.0.2.200", "tokyo-disruption.dll"],
      mitre_techniques: ["T1190", "T1021.001", "T1572"],
    },
    {
      id: 6002,
      country: "Japan",
      country_code: "JP",
      severity: "medium",
      title: "Manufacturing IoT Device Compromise",
      content:
        "Large-scale compromise of IoT devices in Japanese manufacturing facilities for botnet recruitment.",
      confidence: 0.76,
      source: "NISC Advisory",
      threat_type: "iot_botnet",
      attack_vector: "default_credentials",
      collected_at: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
      financial_impact: 5000000,
      affected_systems: ["iot_sensors", "manufacturing_equipment"],
      iocs: ["iot-botnet.sh", "device-compromise.py"],
      mitre_techniques: ["T1078.001", "T1563.002", "T1095"],
    },

    // Australia - Mining and resources
    {
      id: 7001,
      country: "Australia",
      country_code: "AU",
      severity: "high",
      title: "Mining Company Data Exfiltration",
      content:
        "Foreign adversaries targeting Australian mining companies to steal geological survey data and operational intelligence.",
      confidence: 0.89,
      source: "ACSC Threat Bulletin",
      threat_type: "data_exfiltration",
      attack_vector: "business_email_compromise",
      collected_at: new Date(Date.now() - 5 * 60 * 60 * 1000).toISOString(),
      financial_impact: 35000000,
      affected_systems: [
        "geological_databases",
        "mining_operations",
        "commodity_trading",
      ],
      iocs: ["mining-data-stealer.exe", "survey-exfil.com", "203.0.113.150"],
      mitre_techniques: ["T1566.002", "T1114.002", "T1041"],
    },

    // Brazil - Financial crime
    {
      id: 8001,
      country: "Brazil",
      country_code: "BR",
      severity: "medium",
      title: "PIX Payment System Fraud Campaign",
      content:
        "Cybercriminals exploiting Brazil's instant payment system (PIX) through social engineering and mobile malware.",
      confidence: 0.83,
      source: "CERT.br Security Alert",
      threat_type: "financial_fraud",
      attack_vector: "mobile_malware",
      collected_at: new Date(Date.now() - 10 * 60 * 60 * 1000).toISOString(),
      financial_impact: 12000000,
      affected_systems: ["mobile_banking", "payment_processing"],
      iocs: ["pix-stealer.apk", "brazil-banking-fraud.com"],
      mitre_techniques: ["T1575.001", "T1417", "T1056.001"],
    },

    // India - Government sector
    {
      id: 9001,
      country: "India",
      country_code: "IN",
      severity: "high",
      title: "Government Portal Compromise",
      content:
        "Suspected Pakistan-linked threat actors compromising Indian government service portals to steal citizen data.",
      confidence: 0.86,
      source: "CERT-In Vulnerability Note",
      threat_type: "government_breach",
      attack_vector: "web_application_exploit",
      collected_at: new Date(Date.now() - 7 * 60 * 60 * 1000).toISOString(),
      financial_impact: 20000000,
      affected_systems: [
        "citizen_databases",
        "government_portals",
        "identity_systems",
      ],
      iocs: ["gov-portal-exploit.php", "citizen-data-exfil.py"],
      mitre_techniques: ["T1190", "T1133", "T1005"],
    },

    // France - Energy sector
    {
      id: 10001,
      country: "France",
      country_code: "FR",
      severity: "medium",
      title: "Nuclear Facility Reconnaissance Activity",
      content:
        "Suspicious network reconnaissance targeting French nuclear facilities, possibly probing for vulnerabilities.",
      confidence: 0.78,
      source: "ANSSI Cyber Threat Assessment",
      threat_type: "reconnaissance",
      attack_vector: "network_scanning",
      collected_at: new Date(Date.now() - 15 * 60 * 60 * 1000).toISOString(),
      financial_impact: 5000000,
      affected_systems: ["nuclear_safety_systems", "facility_networks"],
      iocs: ["nuclear-scanner.py", "facility-probe.sh"],
      mitre_techniques: ["T1595.001", "T1046", "T1018"],
    },
  ];

  // Process threats data by country
// Process threats data by country
// Process threats data by country  
useEffect(() => {
  if (!geospatialData?.country_data) {
    console.log('❌ No country data to process');
    return;
  }

  console.log('🔍 Processing country data from API...');
  
  const countryData = geospatialData.country_data;
  const threatLocations = geospatialData.threat_locations || [];
  
  const grouped = {};
  
  // Process each country from the API response
  Object.keys(countryData).forEach(countryCode => {
    const data = countryData[countryCode];
    
    // Get threats for this country
    const countryThreats = threatLocations.filter(threat => 
      threat.targeted_countries && threat.targeted_countries.includes(countryCode)
    );
    
    // Count severity levels
    const severityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
    countryThreats.forEach(threat => {
      const severity = threat.severity || 'medium';
      if (severityCounts[severity] !== undefined) {
        severityCounts[severity]++;
      }
    });
    
    grouped[countryCode] = {
  country: countryCode,
  threats: countryThreats,
  totalThreats: data.threat_count,
  critical: severityCounts.critical,
  high: severityCounts.high,
  medium: severityCounts.medium,
  low: severityCounts.low,
  avgConfidence: geospatialData.map_metadata?.avg_confidence || 80,
  totalFinancialImpact: countryThreats.reduce((sum, threat) => sum + (threat.financial_impact || 0), 0),
  riskScore: data.risk_score,
  riskLevel: data.risk_level,
  mapColor: data.map_color
};

  });
  
  setCountryThreats(grouped);
  console.log('✅ Countries processed:', Object.keys(grouped).length);
  console.log('🌍 Country breakdown:', Object.keys(grouped).map(code => ({
    code,
    threats: grouped[code].totalThreats,
    riskLevel: grouped[code].riskLevel
  })));
}, [geospatialData]);


// Add this useEffect right after the data loading useEffect for debugging
useEffect(() => {
  if (geospatialData?.threat_locations) {
    console.log('🔍 Raw API data sample:');
    console.log('Total threats:', geospatialData.threat_locations.length);
    console.log('First 3 threats:', geospatialData.threat_locations.slice(0, 3));
    console.log('Available country positions:', Object.keys(countryPositions));
  }
}, [geospatialData]);



  // Helper functions
  const getCountryThreatLevel = (countryCode) => {
    const countryData = countryThreats[countryCode];
    if (!countryData) return "none";

    if (countryData.critical > 0) return "critical";
    if (countryData.high > 0) return "high";
    if (countryData.medium > 0) return "medium";
    if (countryData.low > 0) return "low";
    return "none";
  };

  const getCountryColor = (countryCode) => {
    const threatLevel = getCountryThreatLevel(countryCode);
    const colors = {
      critical: "#dc2626", // Red
      high: "#ea580c", // Orange-red
      medium: "#d97706", // Orange
      low: "#65a30d", // Green
      none: "#475569", // Slate
    };
    return colors[threatLevel];
  };

  const formatCurrency = (amount) => {
    if (amount >= 1000000) {
      return `$${(amount / 1000000).toFixed(1)}M`;
    }
    return `$${(amount / 1000).toFixed(0)}K`;
  };

  const formatTimeAgo = (timestamp) => {
    const now = new Date();
    const date = new Date(timestamp);
    const diffMs = now - date;
    const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
    const diffMinutes = Math.floor(diffMs / (1000 * 60));

    if (diffHours > 0) {
      return `${diffHours}h ago`;
    }
    return `${diffMinutes}m ago`;
  };

  // Load data effect
  useEffect(() => {
    const loadMapData = async () => {
      try {
        console.log("🌍 Loading map data...");

        const response = await threatAPI.getAnalytics.geospatial(30, 0.5);

        if (response?.data?.threat_locations) {
          setGeospatialData(response.data);
          console.log(
            `✅ Loaded ${response.data.threat_locations.length} threats`,
          );
        } else {
          console.log(`response=${response.data}`);
          setGeospatialData({
            threat_locations: mockThreatData,
            map_metadata: { countries_affected: 10, avg_confidence: 0.85 },
          });
        }
      } catch (err) {
        console.error("❌ Map loading failed:", err);
        setError(err.message);
        setGeospatialData({
          threat_locations: mockThreatData,
          map_metadata: { countries_affected: 10, avg_confidence: 0.85 },
        });
      } finally {
        setLoading(false);
      }
    };

    loadMapData();
  }, [lastUpdate]);

  // Mouse tracking for tooltip positioning
  const handleMouseMove = (e) => {
    const rect = e.currentTarget.getBoundingClientRect();
    setMousePosition({
      x: e.clientX - rect.left,
      y: e.clientY - rect.top,
    });
  };

  // Loading state
  if (loading) {
    return (
      <div className="w-full h-96 bg-gradient-to-br from-slate-900 to-slate-800 border border-slate-700 rounded-2xl flex items-center justify-center">
        <div className="text-center">
          <div className="relative mb-6">
            <div className="w-16 h-16 border-4 border-slate-600 border-t-cyan-500 rounded-full animate-spin mx-auto"></div>
            <div className="absolute inset-0 flex items-center justify-center">
              <span className="text-2xl">🌍</span>
            </div>
          </div>
          <div className="text-slate-300 text-lg font-medium mb-2">
            Loading Global Threat Map
          </div>
          <div className="text-slate-500 text-sm">
            Gathering intelligence from around the world...
          </div>
        </div>
      </div>
    );
  }

  // Error state
  if (error) {
    return (
      <div className="w-full h-96 bg-gradient-to-br from-slate-900 to-slate-800 border border-slate-700 rounded-2xl flex items-center justify-center">
        <div className="text-center p-6">
          <div className="text-6xl mb-4">⚠️</div>
          <div className="text-red-400 text-lg font-medium mb-2">
            Map Loading Failed
          </div>
          <div className="text-slate-400 text-sm mb-4">{error}</div>
          <button
            onClick={() => window.location.reload()}
            className="px-4 py-2 bg-cyan-500 text-white rounded-lg hover:bg-cyan-400 transition-colors"
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  // Country Tooltip Component
  const CountryTooltip = ({ country, countryCode }) => {
  const countryData = countryThreats[countryCode];
  if (!countryData) return null;

  const threatLevel = getCountryThreatLevel(countryCode);
  const threatLevelDisplay =
    threatLevel.charAt(0).toUpperCase() + threatLevel.slice(1);

  const getSeverityIcon = (severity) => {
    const icons = {
      critical: "🚨",
      high: "⚠️",
      medium: "🟡",
      low: "🟢",
    };
    return icons[severity] || "❓";
  };

  return (
    <div
      className="fixed z-[9999] bg-slate-900/95 backdrop-blur-md border border-slate-600 rounded-xl shadow-2xl max-w-96 pointer-events-none"
      style={{
        left: Math.min(mousePosition.x + 15, window.innerWidth - 410),
        top: Math.min(mousePosition.y - 50, window.innerHeight - 350),
        maxHeight: '300px',
        overflow: 'visible'
      }}
    >
      <div className="p-4">
        {/* Header */}
        <div className="flex items-center gap-3 mb-4">
          <div
            className="w-4 h-4 rounded-full"
            style={{ backgroundColor: getCountryColor(countryCode) }}
          ></div>
          <div>
            <h3 className="text-white font-bold text-lg">{country}</h3>
            <div
              className={`text-sm font-medium uppercase tracking-wide`}
              style={{ color: getCountryColor(countryCode) }}
            >
              {threatLevelDisplay} Risk Level
            </div>
          </div>
        </div>

        {/* Summary Stats - Only Threats */}
        <div className="grid grid-cols-1 gap-4 mb-4">
          <div>
            <div className="text-slate-400 text-xs uppercase tracking-wider mb-1">
              Total Threats
            </div>
            <div className="text-white font-bold text-2xl">
              {countryData.totalThreats}
            </div>
          </div>
        </div>

        {/* Severity Breakdown */}
        <div className="mb-4">
          <div className="text-slate-400 text-xs uppercase tracking-wider mb-2">
            Threat Breakdown
          </div>
          <div className="space-y-2">
            {[
              {
                severity: "critical",
                count: countryData.critical,
                color: "#dc2626",
                icon: "🚨",
              },
              {
                severity: "high",
                count: countryData.high,
                color: "#ea580c",
                icon: "⚠️",
              },
              {
                severity: "medium",
                count: countryData.medium,
                color: "#d97706",
                icon: "🟡",
              },
              {
                severity: "low",
                count: countryData.low,
                color: "#65a30d",
                icon: "🟢",
              },
            ]
              .filter((item) => item.count > 0)
              .map((item) => (
                <div
                  key={item.severity}
                  className="flex items-center justify-between"
                >
                  <div className="flex items-center gap-2">
                    <span>{item.icon}</span>
                    <span className="text-white text-sm capitalize">
                      {item.severity}
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-white font-medium">
                      {item.count}
                    </span>
                    <div className="w-12 h-2 bg-slate-700 rounded-full overflow-hidden">
                      <div
                        className="h-full transition-all duration-500"
                        style={{
                          backgroundColor: item.color,
                          width: `${(item.count / countryData.totalThreats) * 100}%`,
                        }}
                      ></div>
                    </div>
                  </div>
                </div>
              ))}
          </div>
        </div>

        {/* Recent Threats */}
        <div>
          <div className="text-slate-400 text-xs uppercase tracking-wider mb-2">
            Recent Threats
          </div>
          <div className="space-y-2 max-h-24 overflow-y-auto">
            {countryData.threats.slice(0, 2).map((threat) => (
              <div key={threat.id} className="p-2 bg-slate-800/50 rounded-lg">
                <div className="flex items-start justify-between mb-1">
                  <div className="text-white text-sm font-medium truncate flex-1">
                    {getSeverityIcon(threat.severity)} {threat.title}
                  </div>
                  <div className="text-slate-400 text-xs ml-2">
                    {formatTimeAgo(threat.collected_at)}
                  </div>
                </div>
                <div className="text-slate-400 text-xs">
                  {threat.source} • {threat.threat_type}
                </div>
              </div>
            ))}
            {countryData.threats.length > 2 && (
              <div className="text-xs text-slate-500 italic text-center py-1">
                +{countryData.threats.length - 2} more threats...
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};


  // Main component return
  return (
    <div
      className="relative w-full h-[500px] bg-gradient-to-br from-slate-900 to-slate-800 border border-slate-700 rounded-2xl overflow-hidden"
      onMouseMove={handleMouseMove}
    >
      {/* Header - Moved to top left with smaller size */}
      <div className="absolute top-3 left-3 z-20">
        <div className="bg-slate-800/90 backdrop-blur-sm border border-slate-600 rounded-lg p-2 shadow-lg">
          <h2 className="text-white text-sm font-bold mb-1 flex items-center gap-2">
            <span className="text-base">🌍</span>
            Global Threat Map
          </h2>
          <p className="text-slate-400 text-xs">
            Real-time threat intelligence
          </p>
        </div>
      </div>

      {/* Map Statistics - Moved to top right with compact layout */}
      <div className="absolute top-3 right-3 z-20">
        <div className="bg-slate-800/90 backdrop-blur-sm border border-slate-600 rounded-lg p-2 shadow-lg">
          <div className="text-slate-300 text-xs space-y-1">
            <div className="flex justify-between gap-3">
  <span>Countries:</span>
  <span className="text-white font-medium">
    {geospatialData?.map_metadata?.countries_affected || Object.keys(countryThreats).length}
  </span>
</div>
<div className="flex justify-between gap-3">
  <span>Threats:</span>
  <span className="text-white font-medium">
    {geospatialData?.map_metadata?.total_mapped_threats || 0}
  </span>
</div>

          </div>
        </div>
      </div>

      {/* Legend - Moved to bottom left with compact design */}
      <div className="absolute bottom-3 left-3 z-20">
        <div className="bg-slate-800/90 backdrop-blur-sm border border-slate-600 rounded-lg p-3 shadow-lg">
          <h4 className="text-white font-bold text-sm mb-2 flex items-center gap-2">
            <span className="w-2 h-2 bg-gradient-to-r from-cyan-500 to-blue-500 rounded-full"></span>
            Threat Levels
          </h4>
          <div className="grid grid-cols-2 gap-2">
            {[
              {
                level: "critical",
                color: "#dc2626",
                label: "Critical",
                icon: "🚨",
              },
              { level: "high", color: "#ea580c", label: "High", icon: "⚠️" },
              {
                level: "medium",
                color: "#d97706",
                label: "Medium",
                icon: "🟡",
              },
              { level: "low", color: "#65a30d", label: "Low", icon: "🟢" },
            ].map((item) => (
              <div key={item.level} className="flex items-center gap-2 text-xs">
                <div
                  className="w-3 h-3 rounded border border-white/20"
                  style={{ backgroundColor: item.color }}
                ></div>
                <span className="text-slate-300">{item.label}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Activity Indicator */}
      <div className="absolute bottom-3 right-3 z-20">
        <div className="bg-slate-800/90 backdrop-blur-sm border border-slate-600 rounded-lg p-2 shadow-lg">
          <div className="flex items-center gap-2">
            <div className="relative">
              <div className="w-3 h-3 bg-red-500 rounded-full animate-pulse"></div>
              <div className="absolute inset-0 w-3 h-3 bg-red-500 rounded-full animate-ping opacity-75"></div>
            </div>
            <span className="text-white text-xs font-medium">
              {Object.values(countryThreats).reduce(
                (sum, country) => sum + country.critical,
                0,
              )}{" "}
              Critical Threats
            </span>
          </div>
        </div>
      </div>

      {/* Main Map Image with Pew Pew Attack Visualization */}
      <div
        className="absolute inset-0 flex items-center justify-center overflow-hidden"
          style={{ padding: "60px 20px" }}
        >
          <div className="relative w-full h-full max-w-6xl max-h-96 rounded-lg overflow-hidden">
          {/* 2D World Map Background Image */}
          <img
            src="https://media.istockphoto.com/id/1349135275/vector/world-map-each-country-on-a-separate-layer.jpg?s=612x612&w=0&k=20&c=EBCQSNKLCNOiTKR3lVZjuMCg_ugyCwLJSQF8BUqgk38="
            alt="2D World Map"
            className="w-full h-full object-cover"
            style={{
              filter: "brightness(0.5) contrast(1.4) saturate(0.8)",
              transform: "scale(0.95) translate(20px, 80px)"
            }}
          />

          {/* Dark overlay for better contrast with glowing edges */}
          <div className="absolute inset-0 bg-gradient-to-br from-slate-900/70 via-slate-800/50 to-slate-900/70"></div>
          <div className="absolute inset-0 bg-gradient-to-r from-cyan-900/20 via-transparent to-red-900/20"></div>

          {/* Clean Threat Markers - Country Spots Only */}
          <div className="absolute inset-0" style={{ zIndex: 2 }}>
            {Object.entries(countryThreats).map(
              ([countryCode, countryData]) => {
                const position = countryPositions[countryCode];
                if (!position) return null;

                const threatLevel = getCountryThreatLevel(countryCode);
                const isHovered = hoveredCountry === countryCode;

                return (
                  <div
                    key={countryCode}
                    className="absolute transform -translate-x-1/2 -translate-y-1/2 cursor-pointer"
                    style={{
                      left: `${position.x}%`,
                      top: `${position.y}%`,
                    }}
                    onMouseEnter={() => setHoveredCountry(countryCode)}
                    onMouseLeave={() => setHoveredCountry(null)}
                  >
                    {/* Clean threat marker spot */}
                    <div className="relative">
                      {/* Main country spot */}
                      <div
                        className={`w-4 h-4 rounded-full border-2 border-white transition-all duration-300 ${
                          isHovered ? "scale-150 shadow-lg" : "scale-100"
                        }`}
                        style={{
                          backgroundColor: getCountryColor(countryCode),
                          boxShadow: isHovered
                            ? `0 0 20px ${getCountryColor(countryCode)}80`
                            : `0 0 8px ${getCountryColor(countryCode)}40`,
                        }}
                      ></div>

                      {/* Critical threat pulsing effect */}
                      {threatLevel === "critical" && (
                        <>
                          <div
                            className="absolute inset-0 w-4 h-4 rounded-full animate-pulse"
                            style={{
                              backgroundColor: getCountryColor(countryCode),
                              opacity: 0.6,
                            }}
                          ></div>
                          <div
                            className="absolute inset-0 w-6 h-6 -top-1 -left-1 rounded-full animate-ping"
                            style={{
                              backgroundColor: getCountryColor(countryCode),
                              opacity: 0.3,
                              animationDuration: "2s",
                            }}
                          ></div>
                        </>
                      )}

                      {/* Threat count badge */}
                      {countryData.totalThreats > 1 && (
                        <div className="absolute -top-2 -right-2 w-5 h-5 bg-black/80 border border-white rounded-full flex items-center justify-center">
                          <span className="text-white text-xs font-bold">
                            {countryData.totalThreats}
                          </span>
                        </div>
                      )}

                      {/* Simple country label on hover */}
                      {isHovered && (
                        <div className="absolute top-6 left-1/2 transform -translate-x-1/2 bg-black/80 text-white px-2 py-1 rounded text-xs font-medium whitespace-nowrap border border-white/20">
                          {position.name}
                        </div>
                      )}
                    </div>
                  </div>
                );
              },
            )}
          </div>
        </div>
      </div>

      {/* Country Tooltip */}
      {hoveredCountry && countryThreats[hoveredCountry] && (
        <CountryTooltip
          country={countryPositions[hoveredCountry]?.name}
          countryCode={hoveredCountry}
        />
      )}
    </div>
  );
};

export default WorldMap;
