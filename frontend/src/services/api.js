import axios from 'axios';

const API_BASE_URL = 'http://localhost:8000';

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// API endpoints
export const threatAPI = {
  // Get dashboard overview
  getDashboardOverview: (hours = 24) => 
    api.get(`/api/dashboard?hours=${hours}`),

  // Get threats list
  getThreats: (limit = 20, offset = 0, filters = {}) => 
    api.get('/api/threats', { 
      params: { limit, offset, ...filters } 
    }),

  // Get specific threat details
  getThreatDetail: (threatId) => 
    api.get(`/api/threats/${threatId}`),

  // Trigger threat collection
  triggerCollection: (mode = 'hybrid', maxSources = 8) => 
    api.post('/api/collect', { mode, max_sources: maxSources }),

  // Get analytics data
  getAnalytics: {
    trends: (days = 7) => api.get(`/api/analytics/trends?days=${days}`),
    summary: (hours = 24) => api.get(`/api/analytics/summary?hours=${hours}`),
    geospatial: (days = 30, min_confidence = 0.5) => 
      api.get(`/api/analytics/geospatial?days=${days}&min_confidence=${min_confidence}`),
    industries: (days = 30) => api.get(`/api/analytics/industries?days=${days}`),
    threatActors: (days = 30) => api.get(`/api/analytics/threat-actors?days=${days}`),
  },

  // System health
  getSystemHealth: () => api.get('/api/system/collection-health'),
  getSystemInfo: () => api.get('/api/system/info'),

  // Health check
  healthCheck: () => api.get('/api/health'),

  orchestrator: {
    // Trigger multi-agent analysis
    triggerAnalysis: async (threatId, forceReanalysis = false) => {
      try {
        const response = await api.post('/api/orchestrator/analyze', {
          threat_id: threatId,
          force_reanalysis: forceReanalysis
        });
        return response.data;
      } catch (error) {
        console.error('Failed to trigger analysis:', error);
        throw error;
      }
    },

    // Get analysis results
    getAnalysisResults: async (threatId) => {
      try {
        const response = await api.get(`/api/orchestrator/analysis/${threatId}`);
        return response.data;
      } catch (error) {
        if (error.response?.status === 404) {
          return null; // No analysis found
        }
        console.error('Failed to get analysis results:', error);
        throw error;
      }
    },

    // Get workflow status
    getWorkflowStatus: async (workflowId) => {
      try {
        const response = await api.get(`/api/orchestrator/workflow/${workflowId}`);
        return response.data;
      } catch (error) {
        console.error('Failed to get workflow status:', error);
        throw error;
      }
    },

    // Check if threat has been analyzed
    hasAnalysis: async (threatId) => {
      try {
        const result = await threatAPI.orchestrator.getAnalysisResults(threatId);
        return result !== null;
      } catch (error) {
        return false;
      }
    },

    // Get analysis summary for multiple threats
    getAnalysisSummary: async (threatIds) => {
      try {
        const summaries = await Promise.all(
          threatIds.map(async (id) => {
            const analysis = await threatAPI.orchestrator.getAnalysisResults(id);
            return {
              threatId: id,
              hasAnalysis: analysis !== null,
              riskScore: analysis?.final_analysis?.overall_assessment?.final_risk_score || 0,
              riskLevel: analysis?.final_analysis?.overall_assessment?.risk_level || 'unknown',
              confidence: analysis?.confidence || 0,
              analysisTimestamp: analysis?.created_at || null
            };
          })
        );
        return summaries;
      } catch (error) {
        console.error('Failed to get analysis summary:', error);
        return [];
      }
    },

    // Get comprehensive analysis details
    getDetailedAnalysis: async (threatId) => {
      try {
        const analysis = await threatAPI.orchestrator.getAnalysisResults(threatId);
        if (!analysis) return null;

        // Extract key information for easy access
        const finalAnalysis = analysis.final_analysis;
        const overallAssessment = finalAnalysis?.overall_assessment || {};
        const agentConsensus = finalAnalysis?.multi_agent_consensus || {};
        
        return {
          threatId,
          timestamp: analysis.created_at,
          confidence: analysis.confidence,
          
          // Risk Assessment
          riskScore: overallAssessment.final_risk_score || 0,
          riskLevel: overallAssessment.risk_level || 'unknown',
          threatClassification: overallAssessment.threat_classification || 'unknown',
          sophisticationLevel: overallAssessment.sophistication_level || 'unknown',
          priorityClassification: overallAssessment.priority_classification || 'unknown',
          
          // Agent Consensus
          sourceCredibility: agentConsensus.source_credibility_consensus?.credibility_score || 0,
          threatCharacterization: agentConsensus.threat_characterization_consensus || {},
          businessImpact: agentConsensus.business_impact_consensus || {},
          
          // Key Intelligence
          primaryConcerns: finalAnalysis.key_intelligence_highlights?.primary_concerns || [],
          immediateActions: finalAnalysis.key_intelligence_highlights?.immediate_actions_required || [],
          systemsAtRisk: finalAnalysis.key_intelligence_highlights?.business_systems_at_risk || [],
          mitigationPriorities: finalAnalysis.key_intelligence_highlights?.mitigation_priorities || [],
          
          // Quality Metrics
          processingTime: finalAnalysis.analysis_quality_metrics?.processing_efficiency?.total_processing_time_seconds || 0,
          errorsEncountered: finalAnalysis.analysis_quality_metrics?.error_analysis?.errors_encountered || 0,
          
          // Full analysis for detailed view
          fullAnalysis: finalAnalysis
        };
      } catch (error) {
        console.error('Failed to get detailed analysis:', error);
        throw error;
      }
    }
  }
};

export default api;
