import React, { useState, useEffect } from "react";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  AreaChart,
  Area,
} from "recharts";
import {
  Shield,
  AlertTriangle,
  Activity,
  Globe,
  Search,
  Filter,
  RefreshCw,
  Download,
  Settings,
  Bell,
  TrendingUp,
  Users,
  Clock,
  MapPin,
  Zap,
  Database,
  Network,
  AlertCircle,
  Brain,
} from "lucide-react";
import { threatAPI } from "../services/api";
import WorldMap from "./WorldMap";
import ThreatAnalysisCard from './ThreatAnalysisCard';


const Dashboard = () => {
  // Enhanced Style System with Better Visual Hierarchy
  const containerStyle =
    "min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 text-gray-100 font-inter relative overflow-hidden";
  const headerStyle =
    "backdrop-blur-xl bg-slate-900/80 border-b border-slate-700/50 shadow-2xl relative z-10";
  const mainStyle = "max-w-7xl mx-auto px-6 py-8 space-y-8 relative z-10";
  const sectionCard =
    "group relative overflow-hidden rounded-3xl bg-gradient-to-br from-slate-900/90 to-slate-800/90 backdrop-blur-xl border border-slate-700/50 shadow-2xl hover:shadow-cyan-500/10 transition-all duration-500 hover:border-cyan-500/30";
  const titleStyle =
    "text-2xl font-bold text-white mb-6 flex items-center gap-3";
  const buttonPrimary =
    "relative overflow-hidden px-8 py-4 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-semibold rounded-2xl transition-all duration-300 shadow-lg shadow-cyan-500/20 hover:shadow-cyan-500/40 transform hover:scale-105 active:scale-95";
  const buttonSecondary =
    "relative overflow-hidden p-4 bg-gradient-to-br from-slate-800 to-slate-700 hover:from-slate-700 hover:to-slate-600 rounded-2xl transition-all duration-300 border border-slate-600/50 hover:border-slate-500 shadow-lg hover:shadow-xl transform hover:scale-105 active:scale-95";
  const inputStyle =
    "bg-slate-800/80 backdrop-blur-sm border border-slate-600/50 rounded-2xl px-6 py-3 text-sm text-white placeholder-slate-400 focus:outline-none focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/20 transition-all duration-300";
  const statCardStyle =
    "group relative overflow-hidden rounded-3xl bg-gradient-to-br from-slate-900/95 to-slate-800/95 backdrop-blur-xl p-8 border border-slate-700/50 shadow-2xl hover:shadow-xl transition-all duration-500 hover:border-cyan-500/30 hover:scale-105";
  const alertItemStyle =
    "group relative overflow-hidden rounded-2xl bg-gradient-to-br from-slate-800/90 to-slate-700/90 backdrop-blur-sm p-6 border border-slate-600/30 hover:border-slate-500/50 transition-all duration-300 hover:shadow-lg hover:shadow-slate-900/20";

  // State Variables (unchanged)
  const [threatData, setThreatData] = useState([]);
  const [dashboardOverview, setDashboardOverview] = useState(null);
  const [threatsList, setThreatsList] = useState([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState("overview");
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState(null);

  // Load real data from backend (unchanged logic)
  useEffect(() => {
    loadDashboardData();
  }, []);


// Replace the mockThreatData section in loadDashboardData function:
const loadDashboardData = async () => {
  try {
    setLoading(true);
    setError(null);

    const [overviewResponse, threatsResponse, trendsResponse] = await Promise.all([
      threatAPI.getDashboardOverview(24),
      threatAPI.getThreats(20, 0),
      threatAPI.getAnalytics.trends(7), // Add this line
    ]);

    setDashboardOverview(overviewResponse.data);
    setThreatsList(threatsResponse.data);

    // Process real trends data for charts
    if (trendsResponse.data && trendsResponse.data.hourly_distribution) {
      const realThreatData = trendsResponse.data.hourly_distribution.map(item => ({
        time: item.hour,
        total: item.threats,
        // Add some mock breakdown for now - you can enhance this in backend later
        malware: Math.floor(item.threats * 0.4),
        phishing: Math.floor(item.threats * 0.3),
        ddos: Math.floor(item.threats * 0.15),
        intrusion: Math.floor(item.threats * 0.15),
      }));
      setThreatData(realThreatData);
    } else {
      // Fallback to empty data if no trends available
      setThreatData([]);
    }

  } catch (err) {
    console.error("Failed to load dashboard data:", err);
    setError(
      "Failed to connect to backend. Make sure the server is running on http://localhost:8000",
    );
    
    // Set empty data on error
    setThreatData([]);
  } finally {
    setLoading(false);
  }
};


  const handleRefresh = async () => {
    setRefreshing(true);
    await loadDashboardData();
    setRefreshing(false);
  };

  const triggerDataCollection = async () => {
    try {
      setRefreshing(true);
      await threatAPI.triggerCollection("hybrid", 8);
      setTimeout(() => {
        loadDashboardData();
      }, 2000);
    } catch (err) {
      console.error("Collection failed:", err);
      setError("Failed to trigger data collection");
    } finally {
      setRefreshing(false);
    }
  };

  // Enhanced StatCard Component with better animations
  const StatCard = ({
    icon: Icon,
    title,
    value,
    change,
    color,
    trend,
    description,
  }) => (
    <div className={statCardStyle}>
      {/* Animated background gradient */}
      <div className="absolute inset-0 bg-gradient-to-br from-cyan-500/5 to-blue-500/5 opacity-0 group-hover:opacity-100 transition-opacity duration-500"></div>

      <div className="relative z-10">
        <div className="flex items-center justify-between mb-6">
          <div
            className={`p-4 rounded-2xl transition-all duration-300 group-hover:scale-110 ${
              color === "cyber-blue"
                ? "bg-gradient-to-br from-cyan-500/20 to-blue-500/20 text-cyan-400"
                : color === "cyber-red"
                  ? "bg-gradient-to-br from-red-500/20 to-rose-500/20 text-red-400"
                  : color === "cyber-green"
                    ? "bg-gradient-to-br from-green-500/20 to-emerald-500/20 text-green-400"
                    : "bg-gradient-to-br from-purple-500/20 to-violet-500/20 text-purple-400"
            }`}
          >
            <Icon className="h-8 w-8" />
          </div>
          <div
            className={`text-xs px-4 py-2 rounded-full font-bold tracking-wide ${
              trend === "up"
                ? "bg-gradient-to-r from-red-500/20 to-rose-500/20 text-red-400 border border-red-500/30"
                : trend === "down"
                  ? "bg-gradient-to-r from-green-500/20 to-emerald-500/20 text-green-400 border border-green-500/30"
                  : "bg-gradient-to-r from-slate-500/20 to-slate-400/20 text-slate-400 border border-slate-500/30"
            }`}
          >
            {change}
          </div>
        </div>
        <div>
          <p className="text-slate-400 text-sm mb-2 font-medium">{title}</p>
          <p className="text-3xl font-bold text-white mb-1 tracking-tight">
            {value}
          </p>
          {description && (
            <p className="text-slate-500 text-xs mt-3 leading-relaxed">
              {description}
            </p>
          )}
        </div>
      </div>
    </div>
  );

  // Enhanced AlertItem Component
  const AlertItem = ({ threat }) => (
    <div className={alertItemStyle}>
      <div className="flex items-start justify-between">
        <div className="flex items-start space-x-4 flex-1">
          <div
            className={`w-4 h-4 rounded-full mt-2 transition-all duration-300 ${
              threat.threat_severity === "critical"
                ? "bg-red-500 animate-pulse shadow-lg shadow-red-500/50"
                : threat.threat_severity === "high"
                  ? "bg-orange-500 shadow-lg shadow-orange-500/50"
                  : threat.threat_severity === "medium"
                    ? "bg-yellow-500 shadow-lg shadow-yellow-500/50"
                    : "bg-green-500 shadow-lg shadow-green-500/50"
            }`}
          ></div>
          <div className="flex-1">
            <h4 className="text-white font-semibold mb-2 text-lg leading-tight group-hover:text-cyan-300 transition-colors">
              {threat.title}
            </h4>
            <p className="text-slate-300 text-sm mb-4 leading-relaxed">
              {threat.content.length > 150
                ? threat.content.substring(0, 150) + "..."
                : threat.content}
            </p>
            <div className="flex items-center space-x-6 text-xs text-slate-400">
              <span className="flex items-center space-x-2 bg-slate-800/50 rounded-lg px-3 py-1">
                <Clock className="h-3 w-3" />
                <span>{new Date(threat.collected_at).toLocaleString()}</span>
              </span>
              <span className="flex items-center space-x-2 bg-slate-800/50 rounded-lg px-3 py-1">
                <Globe className="h-3 w-3" />
                <span>{threat.source}</span>
              </span>
              <span className="bg-slate-800/50 rounded-lg px-3 py-1">
                Relevance: {threat.logistics_relevance}/100
              </span>
            </div>
          </div>
        </div>
        <div className="flex flex-col items-end space-y-3">
          {threat.is_demo && (
            <span className="px-3 py-1 bg-gradient-to-r from-cyan-500/20 to-blue-500/20 text-cyan-400 text-xs rounded-full border border-cyan-500/30 font-medium">
              Demo
            </span>
          )}
          <span
            className={`px-4 py-2 rounded-full text-xs font-bold tracking-wide ${
              threat.threat_severity === "critical"
                ? "bg-gradient-to-r from-red-500/20 to-rose-500/20 text-red-400 border border-red-500/30"
                : threat.threat_severity === "high"
                  ? "bg-gradient-to-r from-orange-500/20 to-red-500/20 text-orange-400 border border-orange-500/30"
                  : threat.threat_severity === "medium"
                    ? "bg-gradient-to-r from-yellow-500/20 to-orange-500/20 text-yellow-400 border border-yellow-500/30"
                    : "bg-gradient-to-r from-green-500/20 to-emerald-500/20 text-green-400 border border-green-500/30"
            }`}
          >
            {(threat.threat_severity || "unknown").toUpperCase()}
          </span>
        </div>
      </div>
    </div>
  );

  const renderAIAnalysisContent = () => (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h2 className="text-2xl font-bold text-white">AI Threat Analysis</h2>
        <div className="text-sm text-slate-400">
          Multi-Agent Intelligence System
        </div>
      </div>
      
      <div className="grid gap-6">
        {threatsList.map(threat => (
          <ThreatAnalysisCard 
            key={threat.id} 
            threat={threat}
            onAnalysisUpdate={(threatId, analysisData) => {
              console.log('Analysis updated for threat:', threatId);
              // Handle analysis updates if needed
            }}
          />
        ))}
      </div>
      
      {threatsList.length === 0 && (
        <div className="text-center py-20">
          <div className="relative mb-8">
            <div className="absolute inset-0 bg-slate-600/20 rounded-full animate-pulse"></div>
            <Brain className="h-24 w-24 text-slate-600 mx-auto relative z-10" />
          </div>
          <h3 className="text-3xl font-bold text-slate-400 mb-4">
            No Threats Available for Analysis
          </h3>
          <p className="text-slate-500 mb-8 text-lg">
            Collect threat data to enable AI analysis
          </p>
          <button
            onClick={triggerDataCollection}
            className={buttonPrimary}
          >
            <Activity className="h-5 w-5 mr-2" />
            Collect Threat Data
          </button>
        </div>
      )}
    </div>
  );

  // Enhanced Error state
  if (error) {
    return (
      <div className={containerStyle}>
        {/* Animated background */}
        <div className="absolute inset-0 bg-gradient-to-br from-red-950/20 via-slate-950 to-slate-900"></div>
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_30%_40%,rgba(239,68,68,0.1),transparent_70%)]"></div>

        <div className="flex items-center justify-center min-h-screen relative z-10">
          <div className="text-center max-w-md mx-auto p-12 rounded-3xl bg-gradient-to-br from-slate-900/95 to-slate-800/95 backdrop-blur-xl border border-red-500/30 shadow-2xl shadow-red-500/10">
            <div className="relative mb-8">
              <div className="absolute inset-0 bg-red-500/20 rounded-full animate-ping"></div>
              <AlertTriangle className="h-20 w-20 text-red-500 mx-auto relative z-10" />
            </div>
            <h2 className="text-3xl font-bold text-white mb-4">
              Connection Error
            </h2>
            <p className="text-slate-400 mb-8 leading-relaxed">{error}</p>
            <button onClick={loadDashboardData} className={buttonPrimary}>
              <RefreshCw className="h-5 w-5 mr-2" />
              Retry Connection
            </button>
          </div>
        </div>
      </div>
    );
  }

  // Enhanced Loading state
  if (loading) {
    return (
      <div className={containerStyle}>
        {/* Animated background */}
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_50%,rgba(6,182,212,0.1),transparent_70%)]"></div>
        <div className="absolute inset-0 bg-[conic-gradient(from_0deg_at_50%_50%,transparent_0deg,rgba(6,182,212,0.05)_60deg,transparent_120deg)]"></div>

        <div className="flex items-center justify-center min-h-screen relative z-10">
          <div className="text-center">
            <div className="relative mb-12">
              <div className="animate-spin rounded-full h-32 w-32 border-4 border-transparent border-t-cyan-500 border-r-blue-500 mx-auto"></div>
              <div className="absolute inset-4 rounded-full bg-gradient-to-br from-cyan-500/20 to-blue-500/20 animate-pulse"></div>
              <Shield className="absolute inset-0 h-12 w-12 text-cyan-400 mx-auto my-auto" />
            </div>
            <h2 className="text-2xl font-bold text-white mb-4">
              Loading Threat Intelligence
            </h2>
            <p className="text-slate-400 text-lg">
              Connecting to secure API endpoints...
            </p>
            <div className="flex justify-center space-x-1 mt-8">
              <div className="w-2 h-2 bg-cyan-500 rounded-full animate-bounce"></div>
              <div
                className="w-2 h-2 bg-cyan-500 rounded-full animate-bounce"
                style={{ animationDelay: "0.1s" }}
              ></div>
              <div
                className="w-2 h-2 bg-cyan-500 rounded-full animate-bounce"
                style={{ animationDelay: "0.2s" }}
              ></div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // Chart data (unchanged)
  const threatTypes = [
    { name: "Malware", value: 145, color: "#ef4444" },
    { name: "Phishing", value: 112, color: "#f97316" },
    { name: "DDoS", value: 77, color: "#8b5cf6" },
    { name: "Intrusion", value: 93, color: "#06d6a0" },
  ];

  return (
    <div className={containerStyle}>
      {/* Enhanced animated background */}
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_20%_80%,rgba(6,182,212,0.1),transparent_50%)]"></div>
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_80%_20%,rgba(147,51,234,0.1),transparent_50%)]"></div>
      <div
        className="absolute inset-0 bg-[conic-gradient(from_0deg_at_50%_50%,transparent_0deg,rgba(6,182,212,0.03)_60deg,transparent_120deg)] animate-spin"
        style={{ animationDuration: "30s" }}
      ></div>

      {/* Enhanced Header */}
      <header className={headerStyle}>
        <div className="px-8 py-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-6">
              <div className="relative">
                <div className="absolute inset-0 bg-cyan-500/20 rounded-2xl animate-pulse"></div>
                <div className="relative p-4 bg-gradient-to-br from-cyan-500/20 to-blue-500/20 rounded-2xl border border-cyan-500/30">
                  <Shield className="h-10 w-10 text-cyan-400" />
                </div>
              </div>
              <div>
                <h1 className="text-4xl font-bold bg-gradient-to-r from-cyan-400 to-blue-400 bg-clip-text text-transparent">
                  Cyber Threat Intelligence Dashboard
                </h1>
                <div className="flex items-center space-x-6 text-sm mt-2">
                  <span className="text-slate-400 font-medium">
                    Real-time monitoring
                  </span>
                  <span className="text-slate-600">•</span>
                  <div className="flex items-center space-x-3">
                    <div
                      className={`w-3 h-3 rounded-full transition-all duration-300 ${
                        error
                          ? "bg-red-500 shadow-lg shadow-red-500/50"
                          : dashboardOverview?.system_status?.includes("🟢")
                            ? "bg-green-500 animate-pulse shadow-lg shadow-green-500/50"
                            : "bg-yellow-500 shadow-lg shadow-yellow-500/50"
                      }`}
                    ></div>
                    <span
                      className={`font-medium ${
                        error
                          ? "text-red-400"
                          : dashboardOverview?.system_status?.includes("🟢")
                            ? "text-green-400"
                            : "text-yellow-400"
                      }`}
                    >
                      {error
                        ? "Error"
                        : dashboardOverview?.system_status || "Loading..."}
                    </span>
                  </div>
                  <span className="text-slate-600">•</span>
                  <span className="text-slate-400 font-medium">
                    Updated: {new Date().toLocaleTimeString()}
                  </span>
                </div>
              </div>
            </div>

            {/* Enhanced action buttons */}
            <div className="flex items-center space-x-4">
              <button
                onClick={triggerDataCollection}
                disabled={refreshing}
                className={`${buttonPrimary} disabled:opacity-50 disabled:cursor-not-allowed`}
              >
                <div className="flex items-center space-x-3">
                  <Activity
                    className={`h-5 w-5 ${refreshing ? "animate-spin" : ""}`}
                  />
                  <span>Collect Data</span>
                </div>
              </button>

              <button
                onClick={handleRefresh}
                disabled={refreshing}
                className={`${buttonSecondary} disabled:opacity-50 disabled:cursor-not-allowed`}
              >
                <RefreshCw
                  className={`h-5 w-5 text-slate-400 ${refreshing ? "animate-spin" : ""}`}
                />
              </button>

              
            </div>
          </div>
        </div>
      </header>

      <main className={mainStyle}>
        {/* Enhanced Navigation Tabs */}
        <section className={`${sectionCard} p-8`}>
          <div className="flex flex-wrap gap-3">
            {[
              { id: "overview", label: "Overview", icon: Activity },
              { id: "threats", label: "Threats", icon: AlertTriangle },
              { id: "ai-analysis", label: "AI Analysis", icon: Brain },
              { id: "analytics", label: "Analytics", icon: TrendingUp },
              { id: "map", label: "World Map", icon: MapPin },
            ].map((tab) => {
              const IconComponent = tab.icon;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`flex items-center space-x-3 px-6 py-4 rounded-2xl text-sm font-semibold transition-all duration-300 transform hover:scale-105 ${
                    activeTab === tab.id
                      ? "bg-gradient-to-r from-cyan-500 to-blue-600 text-white shadow-lg shadow-cyan-500/30"
                      : "bg-gradient-to-br from-slate-700/50 to-slate-600/50 text-slate-400 hover:text-white hover:from-slate-600/50 hover:to-slate-500/50 border border-slate-600/30 hover:border-slate-500/50"
                  }`}
                >
                  <IconComponent className="h-5 w-5" />
                  <span>{tab.label}</span>
                </button>
              );
            })}
          </div>
        </section>

        {/* Rest of the content remains the same but with enhanced styling */}
        {activeTab === "overview" && (
          <>
            {/* Enhanced Threat Overview Stats */}
            <section className={`${sectionCard} p-8`}>
              <h2 className={titleStyle}>
                <AlertTriangle className="h-8 w-8 text-cyan-400" />
                Threat Overview
              </h2>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
                <StatCard
                  icon={AlertTriangle}
                  title="Active Threats (24h)"
                  value={dashboardOverview?.total_threats_24h || 0}
                  change={dashboardOverview?.threat_trend || "Loading..."}
                  color="cyber-red"
                  trend="up"
                  description={`${dashboardOverview?.critical_threats || 0} critical, ${dashboardOverview?.high_threats || 0} high`}
                />
                <StatCard
                  icon={Shield}
                  title="Critical Alerts"
                  value={dashboardOverview?.critical_threats || 0}
                  change="High Priority"
                  color="cyber-red"
                  trend="up"
                />
                <StatCard
                  icon={TrendingUp}
                  title="Avg Relevance"
                  value={`${dashboardOverview?.avg_logistics_relevance || 0}/100`}
                  change="Logistics Focus"
                  color="cyber-green"
                  trend="stable"
                />
                <StatCard
                  icon={Globe}
                  title="Data Sources"
                  value={dashboardOverview?.top_threat_sources?.length || 0}
                  change="Active"
                  color="cyber-blue"
                  trend="stable"
                />
              </div>
            </section>

            {/* Enhanced Main Charts Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
              {/* Enhanced Threat Activity Chart */}
<section className={`${sectionCard} lg:col-span-2 p-8`}>
  <h2 className={titleStyle}>
    <Activity className="h-8 w-8 text-cyan-400" />
    Threat Activity Timeline
  </h2>
  <div className="flex space-x-3 mb-6">
    <button className="px-4 py-2 text-xs bg-slate-700/50 text-slate-400 rounded-xl hover:bg-slate-600/50 transition-colors border border-slate-600/30">
      24H
    </button>
    <button className="px-4 py-2 text-xs bg-gradient-to-r from-cyan-500 to-blue-600 text-white rounded-xl shadow-lg shadow-cyan-500/20">
      7D
    </button>
    <button className="px-4 py-2 text-xs bg-slate-700/50 text-slate-400 rounded-xl hover:bg-slate-600/50 transition-colors border border-slate-600/30">
      30D
    </button>
  </div>
  <div className="relative overflow-hidden rounded-2xl bg-slate-900/50 p-4">
    {threatData.length > 0 ? (
      <ResponsiveContainer width="100%" height={350}>
        <AreaChart data={threatData}>
          <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
          <XAxis dataKey="time" stroke="#64748b" />
          <YAxis stroke="#64748b" />
          <Tooltip
            contentStyle={{
              backgroundColor: "rgba(15, 23, 42, 0.95)",
              border: "1px solid #334155",
              borderRadius: "12px",
              color: "#f8fafc",
              backdropFilter: "blur(12px)",
            }}
          />
          <Legend />
          <Area
            type="monotone"
            dataKey="malware"
            stackId="1"
            stroke="#ef4444"
            fill="#ef4444"
            fillOpacity={0.8}
          />
          <Area
            type="monotone"
            dataKey="phishing"
            stackId="1"
            stroke="#f97316"
            fill="#f97316"
            fillOpacity={0.8}
          />
          <Area
            type="monotone"
            dataKey="ddos"
            stackId="1"
            stroke="#8b5cf6"
            fill="#8b5cf6"
            fillOpacity={0.8}
          />
          <Area
            type="monotone"
            dataKey="intrusion"
            stackId="1"
            stroke="#06d6a0"
            fill="#06d6a0"
            fillOpacity={0.8}
          />
        </AreaChart>
      </ResponsiveContainer>
    ) : (
      <div className="h-[350px] flex items-center justify-center">
        <div className="text-center">
          <Activity className="h-16 w-16 text-slate-600 mx-auto mb-4" />
          <p className="text-slate-400 text-lg mb-2">No Trend Data Available</p>
          <p className="text-slate-500 text-sm mb-4">
            Collect threat data to see activity timeline
          </p>
          <button
            onClick={triggerDataCollection}
            className={buttonPrimary}
          >
            <Activity className="h-4 w-4 mr-2" />
            Collect Data
          </button>
        </div>
      </div>
    )}
  </div>
</section>


              {/* Enhanced Threat Distribution */}
              <section className={`${sectionCard} p-8`}>
                <h2 className={titleStyle}>
                  <Globe className="h-8 w-8 text-cyan-400" />
                  Threat Distribution
                </h2>
                <div className="relative overflow-hidden rounded-2xl bg-slate-900/50 p-4">
                  <ResponsiveContainer width="100%" height={350}>
                    <PieChart>
                      <Pie
                        data={threatTypes}
                        cx="50%"
                        cy="50%"
                        outerRadius={100}
                        dataKey="value"
                        label={({ name, percent }) =>
                          `${name} ${(percent * 100).toFixed(0)}%`
                        }
                        labelLine={false}
                      >
                        {threatTypes.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                      <Tooltip
                        contentStyle={{
                          backgroundColor: "rgba(15, 23, 42, 0.95)",
                          border: "1px solid #334155",
                          borderRadius: "12px",
                          color: "#f8fafc",
                          backdropFilter: "blur(12px)",
                        }}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              </section>
            </div>

            {/* Enhanced Top Threat Sources */}
            <section className={`${sectionCard} p-8`}>
              <h2 className={titleStyle}>
                <Database className="h-8 w-8 text-cyan-400" />
                Top Threat Sources
              </h2>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {(dashboardOverview?.top_threat_sources || []).map(
                  (source, index) => (
                    <div
                      key={index}
                      className={`${alertItemStyle} flex items-center justify-between`}
                    >
                      <div className="flex items-center space-x-4">
                        <div className="w-12 h-12 bg-gradient-to-br from-cyan-500/20 to-blue-500/20 rounded-2xl flex items-center justify-center border border-cyan-500/30">
                          <span className="text-cyan-400 font-bold">
                            #{index + 1}
                          </span>
                        </div>
                        <div>
                          <p className="text-white font-semibold">
                            {source.source}
                          </p>
                          <p className="text-slate-400 text-sm">
                            Active source
                          </p>
                        </div>
                      </div>
                      <div className="text-right">
                        <p className="text-xl font-bold text-white">
                          {source.count}
                        </p>
                        <p className="text-slate-400 text-sm">threats</p>
                      </div>
                    </div>
                  ),
                )}

                {(!dashboardOverview?.top_threat_sources ||
                  dashboardOverview.top_threat_sources.length === 0) && (
                  <div className="col-span-full text-center py-12">
                    <div className="relative mb-6">
                      <div className="absolute inset-0 bg-slate-600/20 rounded-full animate-pulse"></div>
                      <Globe className="h-16 w-16 text-slate-600 mx-auto relative z-10" />
                    </div>
                    <p className="text-slate-400 text-lg mb-2">
                      No threat sources available
                    </p>
                    <p className="text-slate-500 text-sm">
                      Trigger data collection to see sources
                    </p>
                  </div>
                )}
              </div>
            </section>

            {/* Enhanced Recent Security Alerts */}
            <section className={`${sectionCard} p-8`}>
              <div className="flex items-center justify-between mb-8">
                <h2 className={titleStyle}>
                  <AlertCircle className="h-8 w-8 text-cyan-400" />
                  Recent Security Alerts
                </h2>
                <div className="flex items-center space-x-4">
                  <div className="relative">
                    <input
                      type="text"
                      placeholder="Search alerts..."
                      className={`${inputStyle} pl-12`}
                    />
                    <Search className="absolute left-4 top-4 h-5 w-5 text-slate-400" />
                  </div>
                  <button className={buttonSecondary}>
                    <Filter className="h-5 w-5 text-slate-400" />
                  </button>
                </div>
              </div>

              <div className="space-y-6">
                {threatsList.length > 0 ? (
                  threatsList.map((threat) => (
                    <AlertItem key={threat.id} threat={threat} />
                  ))
                ) : (
                  <div className="text-center py-16">
                    <div className="relative mb-8">
                      <div className="absolute inset-0 bg-slate-600/20 rounded-full animate-pulse"></div>
                      <AlertTriangle className="h-20 w-20 text-slate-600 mx-auto relative z-10" />
                    </div>
                    <h4 className="text-2xl font-semibold text-slate-400 mb-4">
                      No Threats Available
                    </h4>
                    <p className="text-slate-500 mb-8 text-lg">
                      Try collecting new data from threat intelligence sources
                    </p>
                    <button
                      onClick={triggerDataCollection}
                      className={buttonPrimary}
                    >
                      <Activity className="h-5 w-5 mr-2" />
                      Collect Threat Data
                    </button>
                  </div>
                )}
              </div>

              {threatsList.length > 0 && (
                <div className="text-center mt-8">
                  <button
                    onClick={() => setActiveTab("threats")}
                    className={buttonPrimary}
                  >
                    View All Threats ({threatsList.length})
                  </button>
                </div>
              )}
            </section>
          </>
        )}

        {/* Continue with other tabs but with enhanced styling... */}
        {activeTab === "threats" && (
          <section className={`${sectionCard} p-8`}>
            <h2 className={titleStyle}>
              <AlertTriangle className="h-8 w-8 text-cyan-400" />
              All Threat Intelligence
            </h2>

            {/* Enhanced Threats List */}
            <div className="space-y-6">
              {threatsList.map((threat) => (
                <div key={threat.id} className={alertItemStyle}>
                  <div className="flex items-start justify-between">
                    <div className="flex items-start space-x-6 flex-1">
                      <div
                        className={`w-5 h-5 rounded-full mt-2 transition-all duration-300 ${
                          threat.threat_severity === "critical"
                            ? "bg-red-500 animate-pulse shadow-lg shadow-red-500/50"
                            : threat.threat_severity === "high"
                              ? "bg-orange-500 shadow-lg shadow-orange-500/50"
                              : threat.threat_severity === "medium"
                                ? "bg-yellow-500 shadow-lg shadow-yellow-500/50"
                                : "bg-green-500 shadow-lg shadow-green-500/50"
                        }`}
                      ></div>
                      <div className="flex-1">
                        <div className="flex items-center space-x-4 mb-3">
                          <h4 className="text-white font-bold text-xl group-hover:text-cyan-300 transition-colors">
                            {threat.title}
                          </h4>
                          {threat.is_demo && (
                            <span className="px-3 py-1 bg-gradient-to-r from-cyan-500/20 to-blue-500/20 text-cyan-400 text-xs rounded-full border border-cyan-500/30 font-medium">
                              Demo
                            </span>
                          )}
                        </div>
                        <p className="text-slate-300 text-base mb-4 leading-relaxed">
                          {threat.content}
                        </p>
                        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 text-sm text-slate-400">
                          <div className="flex items-center space-x-2 bg-slate-800/50 rounded-lg px-3 py-2">
                            <Clock className="h-4 w-4" />
                            <span>
                              {new Date(
                                threat.collected_at,
                              ).toLocaleDateString()}
                            </span>
                          </div>
                          <div className="flex items-center space-x-2 bg-slate-800/50 rounded-lg px-3 py-2">
                            <Globe className="h-4 w-4" />
                            <span>{threat.source}</span>
                          </div>
                          <div className="flex items-center space-x-2 bg-slate-800/50 rounded-lg px-3 py-2">
                            <TrendingUp className="h-4 w-4" />
                            <span>
                              Relevance: {threat.logistics_relevance}/100
                            </span>
                          </div>
                          {threat.url && (
                            <div className="flex items-center space-x-2 bg-slate-800/50 rounded-lg px-3 py-2">
                              <Globe className="h-4 w-4" />
                              <a
                                href={threat.url}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-cyan-400 hover:text-cyan-300 underline font-medium"
                              >
                                View Source
                              </a>
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                    <div className="flex flex-col items-end space-y-3">
                      <span
                        className={`px-4 py-2 rounded-full text-xs font-bold tracking-wide ${
                          threat.threat_severity === "critical"
                            ? "bg-gradient-to-r from-red-500/20 to-rose-500/20 text-red-400 border border-red-500/30"
                            : threat.threat_severity === "high"
                              ? "bg-gradient-to-r from-orange-500/20 to-red-500/20 text-orange-400 border border-orange-500/30"
                              : threat.threat_severity === "medium"
                                ? "bg-gradient-to-r from-yellow-500/20 to-orange-500/20 text-yellow-400 border border-yellow-500/30"
                                : "bg-gradient-to-r from-green-500/20 to-emerald-500/20 text-green-400 border border-green-500/30"
                        }`}
                      >
                        {(threat.threat_severity || "unknown").toUpperCase()}
                      </span>
                      <button className="text-cyan-400 hover:text-cyan-300 text-sm font-semibold transition-colors">
                        Details →
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>

            {threatsList.length === 0 && (
              <div className="text-center py-20">
                <div className="relative mb-8">
                  <div className="absolute inset-0 bg-slate-600/20 rounded-full animate-pulse"></div>
                  <AlertTriangle className="h-24 w-24 text-slate-600 mx-auto relative z-10" />
                </div>
                <h3 className="text-3xl font-bold text-slate-400 mb-4">
                  No Threats Found
                </h3>
                <p className="text-slate-500 mb-8 text-lg">
                  Start collecting threat intelligence data
                </p>
                <button
                  onClick={triggerDataCollection}
                  className={buttonPrimary}
                >
                  <Activity className="h-5 w-5 mr-2" />
                  Start Data Collection
                </button>
              </div>
            )}
          </section>
        )}

        {activeTab === "ai-analysis" && (
            <section className={`${sectionCard} p-8`}>
                {renderAIAnalysisContent()}
            </section>
        )}

        {/* Analytics Tab with enhanced styling */}
        {activeTab === "analytics" && (
          <>
            <section className={`${sectionCard} p-8`}>
              <h2 className={titleStyle}>
                <TrendingUp className="h-8 w-8 text-cyan-400" />
                Threat Analytics
              </h2>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
                <div className="text-center p-8 rounded-2xl bg-gradient-to-br from-cyan-500/10 to-blue-500/10 border border-cyan-500/20">
                  <div className="text-4xl font-bold bg-gradient-to-r from-cyan-400 to-blue-400 bg-clip-text text-transparent mb-3">
                    {dashboardOverview?.total_threats_24h || 0}
                  </div>
                  <div className="text-slate-400 text-base font-medium">
                    Total Threats (24h)
                  </div>
                </div>
                <div className="text-center p-8 rounded-2xl bg-gradient-to-br from-red-500/10 to-rose-500/10 border border-red-500/20">
                  <div className="text-4xl font-bold bg-gradient-to-r from-red-400 to-rose-400 bg-clip-text text-transparent mb-3">
                    {dashboardOverview?.critical_threats || 0}
                  </div>
                  <div className="text-slate-400 text-base font-medium">
                    Critical Threats
                  </div>
                </div>
                <div className="text-center p-8 rounded-2xl bg-gradient-to-br from-green-500/10 to-emerald-500/10 border border-green-500/20">
                  <div className="text-4xl font-bold bg-gradient-to-r from-green-400 to-emerald-400 bg-clip-text text-transparent mb-3">
                    {dashboardOverview?.avg_logistics_relevance || 0}/100
                  </div>
                  <div className="text-slate-400 text-base font-medium">
                    Avg Relevance Score
                  </div>
                </div>
              </div>
            </section>

            <section className={`${sectionCard} p-8`}>
              <h2 className={titleStyle}>
                <Activity className="h-8 w-8 text-cyan-400" />
                Threat Trends
              </h2>
              <div className="relative overflow-hidden rounded-2xl bg-slate-900/50 p-6">
                <ResponsiveContainer width="100%" height={400}>
                  <LineChart data={threatData}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                    <XAxis dataKey="time" stroke="#64748b" />
                    <YAxis stroke="#64748b" />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: "rgba(15, 23, 42, 0.95)",
                        border: "1px solid #334155",
                        borderRadius: "12px",
                        color: "#f8fafc",
                        backdropFilter: "blur(12px)",
                      }}
                    />
                    <Legend />
                    <Line
                      type="monotone"
                      dataKey="malware"
                      stroke="#ef4444"
                      strokeWidth={3}
                    />
                    <Line
                      type="monotone"
                      dataKey="phishing"
                      stroke="#f97316"
                      strokeWidth={3}
                    />
                    <Line
                      type="monotone"
                      dataKey="ddos"
                      stroke="#8b5cf6"
                      strokeWidth={3}
                    />
                    <Line
                      type="monotone"
                      dataKey="intrusion"
                      stroke="#06d6a0"
                      strokeWidth={3}
                    />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </section>
          </>
        )}

        {/* World Map Tab with enhanced styling */}
        {activeTab === "map" && (
          <section className={`${sectionCard} p-8`}>
            <h2 className={titleStyle}>
              <MapPin className="h-8 w-8 text-cyan-400" />
              Global Threat Map
            </h2>
            <div className="h-96 rounded-2xl border border-slate-600/30 overflow-hidden shadow-2xl">
              <WorldMap />
            </div>
            <div className="mt-6 text-center">
              <p className="text-slate-400 text-base">
                Interactive world map showing threat intelligence locations and
                severity
              </p>
            </div>
          </section>
        )}

        {/* Incidents Tab with enhanced styling */}
        {activeTab === "incidents" && (
          <section className={`${sectionCard} p-8`}>
            <h2 className={titleStyle}>
              <Shield className="h-8 w-8 text-cyan-400" />
              Security Incidents
            </h2>
            <div className="text-center py-20">
              <div className="relative mb-8">
                <div className="absolute inset-0 bg-slate-600/20 rounded-full animate-pulse"></div>
                <Shield className="h-24 w-24 text-slate-600 mx-auto relative z-10" />
              </div>
              <h3 className="text-3xl font-bold text-slate-400 mb-4">
                Incident Management
              </h3>
              <p className="text-slate-500 mb-8 text-lg max-w-md mx-auto">
                Advanced incident tracking and response workflows
              </p>
              <button className={buttonPrimary}>
                <Settings className="h-5 w-5 mr-2" />
                Configure Incident Response
              </button>
            </div>
          </section>
        )}

        {/* System Tab with enhanced styling */}
        {activeTab === "system" && (
          <section className={`${sectionCard} p-8`}>
            <h2 className={titleStyle}>
              <Settings className="h-8 w-8 text-cyan-400" />
              System Status
            </h2>
            <div className="space-y-8">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div className="p-6 rounded-2xl bg-gradient-to-br from-green-500/10 to-emerald-500/10 border border-green-500/20">
                  <div className="flex items-center space-x-4">
                    <div className="w-4 h-4 bg-green-500 rounded-full animate-pulse shadow-lg shadow-green-500/50"></div>
                    <div>
                      <p className="text-white font-semibold text-lg">
                        API Status
                      </p>
                      <p className="text-green-400 text-sm font-medium">
                        Operational
                      </p>
                    </div>
                  </div>
                </div>
                <div className="p-6 rounded-2xl bg-gradient-to-br from-cyan-500/10 to-blue-500/10 border border-cyan-500/20">
                  <div className="flex items-center space-x-4">
                    <div className="w-4 h-4 bg-cyan-500 rounded-full shadow-lg shadow-cyan-500/50"></div>
                    <div>
                      <p className="text-white font-semibold text-lg">
                        Data Sources
                      </p>
                      <p className="text-cyan-400 text-sm font-medium">
                        {dashboardOverview?.top_threat_sources?.length || 0}{" "}
                        Active
                      </p>
                    </div>
                  </div>
                </div>
                <div className="p-6 rounded-2xl bg-gradient-to-br from-purple-500/10 to-violet-500/10 border border-purple-500/20">
                  <div className="flex items-center space-x-4">
                    <div className="w-4 h-4 bg-purple-500 rounded-full shadow-lg shadow-purple-500/50"></div>
                    <div>
                      <p className="text-white font-semibold text-lg">
                        Last Scan
                      </p>
                      <p className="text-purple-400 text-sm font-medium">
                        {new Date().toLocaleString()}
                      </p>
                    </div>
                  </div>
                </div>
              </div>

              <div className="p-8 rounded-2xl bg-gradient-to-br from-slate-800/50 to-slate-700/50 border border-slate-600/30">
                <h3 className="text-white font-bold text-xl mb-6 flex items-center gap-3">
                  <Network className="h-6 w-6 text-cyan-400" />
                  System Information
                </h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6 text-base">
                  <div className="flex justify-between items-center p-4 rounded-xl bg-slate-800/50">
                    <span className="text-slate-400 font-medium">
                      Backend API:
                    </span>
                    <span className="text-white font-semibold">
                      http://localhost:8000
                    </span>
                  </div>
                  <div className="flex justify-between items-center p-4 rounded-xl bg-slate-800/50">
                    <span className="text-slate-400 font-medium">
                      Frontend:
                    </span>
                    <span className="text-white font-semibold">
                      React Dashboard
                    </span>
                  </div>
                  <div className="flex justify-between items-center p-4 rounded-xl bg-slate-800/50">
                    <span className="text-slate-400 font-medium">
                      Database:
                    </span>
                    <span className="text-white font-semibold">SQLite</span>
                  </div>
                  <div className="flex justify-between items-center p-4 rounded-xl bg-slate-800/50">
                    <span className="text-slate-400 font-medium">
                      AI Analysis:
                    </span>
                    <span className="text-white font-semibold">Enabled</span>
                  </div>
                </div>
              </div>
            </div>
          </section>
        )}

        {/* Enhanced System Status Footer */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className={`${sectionCard} p-6`}>
            <div className="flex items-center space-x-4">
              <div
                className={`w-4 h-4 rounded-full transition-all duration-300 ${
                  error
                    ? "bg-red-500 shadow-lg shadow-red-500/50"
                    : dashboardOverview?.system_status?.includes("🟢")
                      ? "bg-green-500 animate-pulse shadow-lg shadow-green-500/50"
                      : "bg-yellow-500 shadow-lg shadow-yellow-500/50"
                }`}
              ></div>
              <div>
                <p className="text-white text-base font-semibold">
                  System Status
                </p>
                <p
                  className={`text-sm font-medium ${
                    error
                      ? "text-red-400"
                      : dashboardOverview?.system_status?.includes("🟢")
                        ? "text-green-400"
                        : "text-yellow-400"
                  }`}
                >
                  {error
                    ? "Connection Error"
                    : dashboardOverview?.system_status || "Initializing..."}
                </p>
              </div>
            </div>
          </div>

          <div className={`${sectionCard} p-6`}>
            <div className="flex items-center space-x-4">
              <div className="w-4 h-4 bg-cyan-500 rounded-full shadow-lg shadow-cyan-500/50"></div>
              <div>
                <p className="text-white text-base font-semibold">
                  Data Sources
                </p>
                <p className="text-cyan-400 text-sm font-medium">
                  {dashboardOverview?.top_threat_sources?.length || 0} Active
                  Sources
                </p>
              </div>
            </div>
          </div>

          <div className={`${sectionCard} p-6`}>
            <div className="flex items-center space-x-4">
              <div className="w-4 h-4 bg-purple-500 rounded-full shadow-lg shadow-purple-500/50"></div>
              <div>
                <p className="text-white text-base font-semibold">
                  Last Update
                </p>
                <p className="text-purple-400 text-sm font-medium">
                  {new Date().toLocaleTimeString()}
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Enhanced Action Center */}
        <section className={`${sectionCard} p-8`}>
          <h2 className={titleStyle}>
            <Zap className="h-8 w-8 text-cyan-400" />
            Quick Actions
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            <button
              onClick={triggerDataCollection}
              disabled={refreshing}
              className={`${buttonPrimary} disabled:opacity-50 disabled:cursor-not-allowed`}
            >
              <Activity
                className={`h-5 w-5 mr-3 ${refreshing ? "animate-spin" : ""}`}
              />
              <span>Collect New Data</span>
            </button>

            <button
              onClick={handleRefresh}
              disabled={refreshing}
              className={`${buttonSecondary} text-slate-300 disabled:opacity-50 disabled:cursor-not-allowed`}
            >
              <RefreshCw
                className={`h-5 w-5 mr-3 ${refreshing ? "animate-spin" : ""}`}
              />
              <span>Refresh Dashboard</span>
            </button>

            
          </div>
        </section>

        {/* Enhanced API Status Indicator */}
        <section className={`${sectionCard} p-8`}>
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-8">
              <div className="flex items-center space-x-3">
                <div
                  className={`w-3 h-3 rounded-full transition-all duration-300 ${error ? "bg-red-500 shadow-lg shadow-red-500/50" : "bg-green-500 animate-pulse shadow-lg shadow-green-500/50"}`}
                ></div>
                <span className="text-base text-slate-400 font-medium">
                  Backend API
                </span>
              </div>
              <div className="flex items-center space-x-3">
                <div className="w-3 h-3 bg-cyan-500 rounded-full shadow-lg shadow-cyan-500/50"></div>
                <span className="text-base text-slate-400 font-medium">
                  Real-time Updates
                </span>
              </div>
              <div className="flex items-center space-x-3">
                <div className="w-3 h-3 bg-purple-500 rounded-full shadow-lg shadow-purple-500/50"></div>
                <span className="text-base text-slate-400 font-medium">
                  AI Analysis
                </span>
              </div>
            </div>

            <div className="text-right">
              <p className="text-sm text-slate-500 font-medium">
                Dashboard v1.0 • {threatsList.length} threats loaded
              </p>
              <p className="text-sm text-slate-500 font-medium">
                Last sync: {new Date().toLocaleString()}
              </p>
            </div>
          </div>
        </section>
      </main>

      {/* Enhanced Footer */}
      <footer className="text-center py-8 text-sm text-slate-500 border-t border-slate-700/50 bg-slate-950/50 backdrop-blur-xl">
        <div className="max-w-7xl mx-auto px-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-8">
              <span className="font-medium">
                &copy; 2025 Cyber Threat Intelligence Dashboard
              </span>
              <span>•</span>
              <span className="text-slate-400">
                Secure • Real-time • Enterprise-grade
              </span>
            </div>

            <div className="flex items-center space-x-4">
              <span className="text-xs text-slate-400">Powered by</span>
              <div className="flex items-center space-x-3">
                <div className="w-6 h-6 bg-gradient-to-br from-cyan-500/20 to-blue-500/20 rounded-lg flex items-center justify-center border border-cyan-500/30">
                  <span className="text-cyan-400 text-xs font-bold">API</span>
                </div>
                <span className="text-sm text-cyan-400 font-medium">
                  FastAPI + React
                </span>
              </div>
            </div>
          </div>

          <div className="mt-6 pt-6 border-t border-slate-700/30">
            <p className="text-xs text-slate-600">
              Professional threat intelligence dashboard for cybersecurity
              monitoring and analysis
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default Dashboard;