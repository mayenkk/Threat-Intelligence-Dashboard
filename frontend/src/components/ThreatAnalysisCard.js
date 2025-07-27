import React, { useState, useEffect } from 'react';
import { 
  Brain, 
  Zap, 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  Clock,
  TrendingUp,
  Activity,
  ExternalLink,
  Eye,
  ChevronDown, 
  ChevronUp, 
  BarChart3,
  FileText
} from 'lucide-react';
import { threatAPI } from '../services/api';
import RiskScoreGauge from './RiskScoreGauge';
import AgentProgressTracker from './AgentProgressTracker';


const ThreatAnalysisCard = ({ threat, onAnalysisUpdate }) => {
  const [analysisState, setAnalysisState] = useState({
    isAnalyzing: false,
    hasAnalysis: false,
    analysisData: null,
    detailedAnalysis: null,
    error: null,
    showDetails: false,           
    showAgentProgress: false,     
    startTime: null  
  });

  useEffect(() => {
    checkExistingAnalysis();
  }, [threat.id]);

  const checkExistingAnalysis = async () => {
  try {
    const analysisData = await threatAPI.orchestrator.getAnalysisResults(threat.id);
    
    // Extract detailed analysis from the main analysis data
    let detailedAnalysis = null;
    if (analysisData?.final_analysis) {
      const finalAnalysis = analysisData.final_analysis;
      const overallAssessment = finalAnalysis.overall_assessment || {};
      
      detailedAnalysis = {
        // Extract data from the analysis structure
        primaryConcerns: finalAnalysis.key_intelligence_highlights?.primary_concerns || [],
        immediateActions: finalAnalysis.key_intelligence_highlights?.immediate_actions_required || [],
        systemsAtRisk: finalAnalysis.key_intelligence_highlights?.business_systems_at_risk || [],
        mitigationPriorities: finalAnalysis.key_intelligence_highlights?.mitigation_priorities || [],
        
        // Business impact data
        businessImpact: finalAnalysis.multi_agent_consensus?.business_impact_consensus || {},
        riskLevel: overallAssessment.risk_level || 'unknown',
        threatClassification: overallAssessment.threat_classification || 'unknown',
        sophisticationLevel: overallAssessment.sophistication_level || 'unknown',
        
        // Quality metrics
        confidence: overallAssessment.overall_confidence || 0,
        processingTime: finalAnalysis.analysis_quality_metrics?.processing_efficiency?.total_processing_time_seconds || 0,
        errorsEncountered: finalAnalysis.analysis_quality_metrics?.error_analysis?.errors_encountered || 0,
        timestamp: analysisData.created_at || new Date().toISOString()
      };
    }
    
    setAnalysisState(prev => ({
      ...prev,
      hasAnalysis: analysisData !== null,
      analysisData: analysisData,
      detailedAnalysis: detailedAnalysis
    }));
  } catch (error) {
    console.error('Error checking analysis:', error);
  }
};



  const triggerAnalysis = async (forceReanalysis = false) => {
    setAnalysisState(prev => ({ ...prev, isAnalyzing: true, error: null, startTime: Date.now(), showAgentProgress: true}));
    
    try {
      await threatAPI.orchestrator.triggerAnalysis(threat.id, forceReanalysis);
      
      // Poll for results
      pollForResults();
      
    } catch (error) {
      setAnalysisState(prev => ({
        ...prev,
        isAnalyzing: false,
        error: 'Failed to start analysis'
      }));
    }
  };

  const pollForResults = async () => {
  const maxAttempts = 24; // 24 * 5 seconds = 120 seconds max wait
  let attempts = 0;

  const poll = async () => {
    try {
      const analysisData = await threatAPI.orchestrator.getAnalysisResults(threat.id);
      
      if (analysisData) {
        // Extract detailed analysis from the main analysis data
        const finalAnalysis = analysisData.final_analysis;
        let detailedAnalysis = null;
        
        if (finalAnalysis) {
          const overallAssessment = finalAnalysis.overall_assessment || {};
          
          detailedAnalysis = {
            // Extract data from the analysis structure
            primaryConcerns: finalAnalysis.key_intelligence_highlights?.primary_concerns || [],
            immediateActions: finalAnalysis.key_intelligence_highlights?.immediate_actions_required || [],
            systemsAtRisk: finalAnalysis.key_intelligence_highlights?.business_systems_at_risk || [],
            mitigationPriorities: finalAnalysis.key_intelligence_highlights?.mitigation_priorities || [],
            
            // Business impact data
            businessImpact: finalAnalysis.multi_agent_consensus?.business_impact_consensus || {},
            riskLevel: overallAssessment.risk_level || 'unknown',
            threatClassification: overallAssessment.threat_classification || 'unknown',
            sophisticationLevel: overallAssessment.sophistication_level || 'unknown',
            
            // Quality metrics
            confidence: overallAssessment.overall_confidence || 0,
            processingTime: analysisState.startTime ? (Date.now() - analysisState.startTime) / 1000 : 0,
            errorsEncountered: finalAnalysis.analysis_quality_metrics?.error_analysis?.errors_encountered || 0,
            timestamp: analysisData.created_at || new Date().toISOString()
          };
        }

        setAnalysisState(prev => ({
          ...prev,
          isAnalyzing: false,
          hasAnalysis: true,
          analysisData: analysisData,
          detailedAnalysis: detailedAnalysis,
          error: null,
          showAgentProgress: true
        }));
        
        if (onAnalysisUpdate) {
          onAnalysisUpdate(threat.id, analysisData);
        }
        return;
      }
      
      attempts++;
      if (attempts < maxAttempts) {
        setTimeout(poll, 5000); // Poll every 5 seconds
      } else {
        setAnalysisState(prev => ({
          ...prev,
          isAnalyzing: false,
          error: 'Analysis timed out'
        }));
      }
    } catch (error) {
      setAnalysisState(prev => ({
        ...prev,
        isAnalyzing: false,
        error: 'Failed to get results'
      }));
    }
  };

  poll();
};


  const getRiskColor = (riskLevel) => {
    switch (riskLevel?.toLowerCase()) {
      case 'critical': return 'text-red-500 bg-red-50';
      case 'high': return 'text-orange-500 bg-orange-50';
      case 'medium': return 'text-yellow-500 bg-yellow-50';
      case 'low': return 'text-green-500 bg-green-50';
      default: return 'text-gray-500 bg-gray-50';
    }
  };

  const analysisData = analysisState.analysisData?.final_analysis?.overall_assessment;

  return (
    <div className="bg-white rounded-lg border border-gray-200 p-6 hover:shadow-lg transition-shadow">
      {/* Original Threat Info */}
      <div className="flex justify-between items-start mb-4">
        <div className="flex-1">
          <h3 className="text-lg font-semibold text-gray-900 mb-2">
            {threat.title}
          </h3>
          <p className="text-gray-600 text-sm mb-3 line-clamp-3">
            {threat.content}
          </p>
          <div className="flex items-center gap-4 text-sm text-gray-500">
            <span>Source: {threat.source}</span>
            <span>•</span>
            <span>{new Date(threat.collected_at).toLocaleDateString()}</span>
          </div>
        </div>
      </div>

      {/* Analysis Section */}
      <div className="border-t pt-4">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <Brain className="h-5 w-5 text-blue-600" />
            <span className="font-medium text-gray-900">AI Analysis</span>
          </div>
          
          {/* Analysis Status */}
          {analysisState.isAnalyzing && (
            <div className="flex items-center gap-2 text-blue-600">
              <Activity className="h-4 w-4 animate-pulse" />
              <span className="text-sm">Analyzing...</span>
            </div>
          )}
          
          {analysisState.hasAnalysis && !analysisState.isAnalyzing && (
            <div className="flex items-center gap-2 text-green-600">
              <CheckCircle className="h-4 w-4" />
              <span className="text-sm">Complete</span>
            </div>
          )}
        </div>

        {/* Analysis Results */}
        {analysisState.hasAnalysis && analysisData && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-12">
            <div className="col-span-1 flex justify-center">
                <RiskScoreGauge 
                    score={analysisData.final_risk_score || 0}
                    level={analysisData.risk_level}
                    confidence={analysisData.overall_confidence || 0}
                    size="medium"
                    showDetails={true}
                />
            </div>
            
            <div className="text-center p-3 bg-gray-50 rounded-lg">
              <div className={`text-sm font-semibold px-2 py-1 rounded ${getRiskColor(analysisData.risk_level)}`}>
                {analysisData.risk_level?.toUpperCase() || 'UNKNOWN'}
              </div>
              <div className="text-xs text-gray-600 mt-1">Risk Level</div>
            </div>
            
            <div className="text-center p-3 bg-gray-50 rounded-lg">
              <div className="text-lg font-bold text-gray-900">
                {Math.round((analysisData.overall_confidence || 0) * 100)}%
              </div>
              <div className="text-xs text-gray-600">Confidence</div>
            </div>
            
            <div className="text-center p-3 bg-gray-50 rounded-lg">
              <div className="text-sm font-semibold text-gray-900">
                {analysisData.threat_classification?.toUpperCase() || 'UNKNOWN'}
              </div>
              <div className="text-xs text-gray-600">Type</div>
            </div>
          </div>
        )}

        {(analysisState.showAgentProgress || analysisState.isAnalyzing) && (
            <div className="mb-6">
                <AgentProgressTracker 
                isAnalyzing={analysisState.isAnalyzing}
                analysisData={analysisState.analysisData}
                processingTime={analysisState.processingTime}
                />
            </div>
        )}

        {/* Action Buttons */}
        <div className="flex gap-2 mb-4">
        {!analysisState.hasAnalysis && !analysisState.isAnalyzing && (
            <button
            onClick={() => triggerAnalysis(false)}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
            >
            <Zap className="h-4 w-4" />
            Analyze with AI
            </button>
        )}
        
        {analysisState.hasAnalysis && !analysisState.isAnalyzing && (
            <>
            <button
                onClick={() => triggerAnalysis(true)}
                className="flex items-center gap-2 px-3 py-2 bg-gray-600 text-white rounded-lg hover:bg-gray-700 transition-colors"
            >
                <TrendingUp className="h-4 w-4" />
                Re-analyze
            </button>
            
            <button
                onClick={() => setAnalysisState(prev => ({ ...prev, showDetails: !prev.showDetails }))}
                className="flex items-center gap-2 px-3 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors"
            >
                <Eye className="h-4 w-4" />
                {analysisState.showDetails ? 'Hide Details' : 'View Details'}
                {analysisState.showDetails ? 
                <ChevronUp className="h-4 w-4" /> : 
                <ChevronDown className="h-4 w-4" />
                }
            </button>

            <button
                onClick={() => setAnalysisState(prev => ({ ...prev, showAgentProgress: !prev.showAgentProgress }))}
                className="flex items-center gap-2 px-3 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 transition-colors"
            >
                <BarChart3 className="h-4 w-4" />
                {analysisState.showAgentProgress ? 'Hide Progress' : 'Show Progress'}
            </button>
            </>
        )}
        </div>
    </div>

{/* Detailed Analysis Results */}
{analysisState.showDetails && analysisState.hasAnalysis && analysisData && (
  <div className="border-t pt-6 mt-6 space-y-6">
    <h4 className="text-lg font-semibold text-gray-900 flex items-center gap-2">
      <FileText className="h-5 w-5 text-blue-600" />
      Detailed Analysis Results
    </h4>
    
    {analysisState.showDetails && analysisState.hasAnalysis && analysisData && (
  <div className="border-t pt-6 mt-6 space-y-6">
    <h4 className="text-lg font-semibold text-gray-900 flex items-center gap-2">
      <FileText className="h-5 w-5 text-blue-600" />
      Detailed Analysis Results
    </h4>
    
    {/* ADD THIS NEW SUMMARY SECTION */}
    {/* Original Threat Summary */}
    <div className="bg-slate-50 border border-slate-200 rounded-lg p-4">
      <h5 className="font-semibold text-slate-900 mb-3 flex items-center gap-2">
        <FileText className="h-4 w-4" />
        Original Threat Intelligence
      </h5>
      <div className="space-y-3">
        <div>
          <span className="text-sm font-medium text-slate-700 block mb-1">Source:</span>
          <div className="text-sm text-slate-600">{threat.source}</div>
        </div>
        <div>
          <span className="text-sm font-medium text-slate-700 block mb-1">Full Content:</span>
          <div className="text-sm text-slate-600 leading-relaxed whitespace-pre-wrap bg-white p-3 rounded border">
            {threat.content}
          </div>
        </div>
        {threat.url && (
          <div>
            <span className="text-sm font-medium text-slate-700 block mb-1">Source URL:</span>
            <a 
              href={threat.url} 
              target="_blank" 
              rel="noopener noreferrer"
              className="text-sm text-blue-600 hover:text-blue-800 flex items-center gap-1"
            >
              <ExternalLink className="h-3 w-3" />
              {threat.url}
            </a>
          </div>
        )}
        <div>
          <span className="text-sm font-medium text-slate-700 block mb-1">Collection Date:</span>
          <div className="text-sm text-slate-600">
            {new Date(threat.collected_at).toLocaleString()}
          </div>
        </div>
      </div>
    </div>

    {/* AI-Generated Executive Summary */}
    {analysisState.analysisData?.final_analysis?.executive_summary && (
      <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
        <h5 className="font-semibold text-blue-900 mb-3 flex items-center gap-2">
          <Brain className="h-4 w-4" />
          AI-Generated Executive Summary
        </h5>
        <div className="prose prose-sm text-blue-800 leading-relaxed">
          {analysisState.analysisData.final_analysis.executive_summary.summary_text || 
           analysisState.analysisData.final_analysis.executive_summary.executive_overview ||
           analysisState.analysisData.final_analysis.executive_summary ||
           "AI executive summary is being processed..."}
        </div>
      </div>
    )}

    {/* Executive Summary */}
    {analysisState.analysisData?.final_analysis?.executive_summary && (
      <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
        <h5 className="font-semibold text-blue-900 mb-3 flex items-center gap-2">
          <Brain className="h-4 w-4" />
          Executive Summary
        </h5>
        <div className="prose prose-sm text-blue-800">
          {analysisState.analysisData.final_analysis.executive_summary.summary_text || 
           analysisState.analysisData.final_analysis.executive_summary.executive_overview ||
           "Executive summary is being processed..."}
        </div>
      </div>
    )}

    {/* Key Intelligence Highlights */}
    {analysisState.detailedAnalysis && (
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Primary Concerns */}
        {analysisState.detailedAnalysis.primaryConcerns?.length > 0 && (
          <div className="bg-red-50 border border-red-200 rounded-lg p-4">
            <h5 className="font-semibold text-red-900 mb-3 flex items-center gap-2">
              <AlertTriangle className="h-4 w-4" />
              Primary Concerns
            </h5>
            <ul className="space-y-2">
              {analysisState.detailedAnalysis.primaryConcerns.map((concern, index) => (
                <li key={index} className="flex items-start gap-2 text-sm text-red-800">
                  <div className="w-1.5 h-1.5 bg-red-500 rounded-full mt-2 flex-shrink-0"></div>
                  {concern}
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Immediate Actions */}
        {analysisState.detailedAnalysis.immediateActions?.length > 0 && (
          <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
            <h5 className="font-semibold text-yellow-900 mb-3 flex items-center gap-2">
              <Zap className="h-4 w-4" />
              Immediate Actions Required
            </h5>
            <ul className="space-y-2">
              {analysisState.detailedAnalysis.immediateActions.map((action, index) => (
                <li key={index} className="flex items-start gap-2 text-sm text-yellow-800">
                  <div className="w-1.5 h-1.5 bg-yellow-500 rounded-full mt-2 flex-shrink-0"></div>
                  {action}
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Systems at Risk */}
        {analysisState.detailedAnalysis.systemsAtRisk?.length > 0 && (
          <div className="bg-orange-50 border border-orange-200 rounded-lg p-4">
            <h5 className="font-semibold text-orange-900 mb-3 flex items-center gap-2">
              <Shield className="h-4 w-4" />
              Systems at Risk
            </h5>
            <ul className="space-y-2">
              {analysisState.detailedAnalysis.systemsAtRisk.map((system, index) => (
                <li key={index} className="flex items-start gap-2 text-sm text-orange-800">
                  <div className="w-1.5 h-1.5 bg-orange-500 rounded-full mt-2 flex-shrink-0"></div>
                  {system}
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Mitigation Priorities */}
        {analysisState.detailedAnalysis.mitigationPriorities?.length > 0 && (
          <div className="bg-green-50 border border-green-200 rounded-lg p-4">
            <h5 className="font-semibold text-green-900 mb-3 flex items-center gap-2">
              <CheckCircle className="h-4 w-4" />
              Mitigation Priorities
            </h5>
            <ul className="space-y-2">
              {analysisState.detailedAnalysis.mitigationPriorities.map((priority, index) => (
                <li key={index} className="flex items-start gap-2 text-sm text-green-800">
                  <div className="w-1.5 h-1.5 bg-green-500 rounded-full mt-2 flex-shrink-0"></div>
                  {priority}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    )}

    {/* Business Impact Assessment */}
    {analysisState.detailedAnalysis?.businessImpact && (
      <div className="bg-gray-50 border border-gray-200 rounded-lg p-4">
        <h5 className="font-semibold text-gray-900 mb-3 flex items-center gap-2">
          <TrendingUp className="h-4 w-4" />
          Business Impact Assessment
        </h5>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
          <div className="bg-white p-3 rounded border">
            <span className="text-gray-600 block mb-1">Risk Level:</span>
            <div className={`font-semibold px-2 py-1 rounded text-center ${getRiskColor(analysisState.detailedAnalysis.riskLevel)}`}>
              {analysisState.detailedAnalysis.riskLevel?.toUpperCase() || 'UNKNOWN'}
            </div>
          </div>
          <div className="bg-white p-3 rounded border">
            <span className="text-gray-600 block mb-1">Threat Classification:</span>
            <div className="font-semibold text-gray-900">
              {analysisState.detailedAnalysis.threatClassification?.toUpperCase() || 'UNKNOWN'}
            </div>
          </div>
          <div className="bg-white p-3 rounded border">
            <span className="text-gray-600 block mb-1">Sophistication:</span>
            <div className="font-semibold text-gray-900">
              {analysisState.detailedAnalysis.sophisticationLevel?.toUpperCase() || 'UNKNOWN'}
            </div>
          </div>
        </div>
      </div>
    )}

    {/* Analysis Quality Metrics */}
    {analysisState.detailedAnalysis && (
      <div className="bg-gray-50 border border-gray-200 rounded-lg p-4">
        <h5 className="font-semibold text-gray-900 mb-3 flex items-center gap-2">
          <BarChart3 className="h-4 w-4" />
          Analysis Quality Metrics
        </h5>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
          <div className="text-center">
            <div className="text-lg font-bold text-blue-600">
              {Math.round((analysisState.detailedAnalysis.confidence || 0) * 100)}%
            </div>
            <div className="text-gray-600">Overall Confidence</div>
          </div>
          <div className="text-center">
            <div className="text-lg font-bold text-green-600">
              {Math.round(analysisState.detailedAnalysis.processingTime || 0)}s
            </div>
            <div className="text-gray-600">Processing Time</div>
          </div>
          <div className="text-center">
            <div className="text-lg font-bold text-purple-600">
              {analysisState.detailedAnalysis.errorsEncountered || 0}
            </div>
            <div className="text-gray-600">Errors</div>
          </div>
          <div className="text-center">
            <div className="text-lg font-bold text-gray-600">
              {new Date(analysisState.detailedAnalysis.timestamp || Date.now()).toLocaleDateString()}
            </div>
            <div className="text-gray-600">Analysis Date</div>
          </div>
        </div>
      </div>
    )}
  </div>
)}


        {/* Error Display */}
        {analysisState.error && (
          <div className="mt-3 p-3 bg-red-50 border border-red-200 rounded-lg">
            <div className="flex items-center gap-2 text-red-700">
              <AlertTriangle className="h-4 w-4" />
              <span className="text-sm">{analysisState.error}</span>
            </div>
          </div>
        )}
      </div>
)}</div>
  );
};

export default ThreatAnalysisCard;
