import React from 'react';
import { 
  Search, 
  Target, 
  TrendingUp, 
  FileText, 
  CheckCircle2, 
  Clock, 
  AlertCircle,
  Brain
} from 'lucide-react';

const AgentProgressTracker = ({ 
  isAnalyzing = false, 
  analysisData = null,
  processingTime = 0 
}) => {
  const agents = [
    {
      id: 'source_analysis',
      name: 'Source Analysis',
      description: 'Verifying source credibility',
      icon: Search,
      order: 1
    },
    {
      id: 'mitre_mapping',
      name: 'MITRE Mapping',
      description: 'Identifying attack techniques',
      icon: Target,
      order: 2
    },
    {
      id: 'impact_assessment',
      name: 'Impact Assessment',
      description: 'Analyzing business impact',
      icon: TrendingUp,
      order: 3
    },
    {
      id: 'executive_summary',
      name: 'Executive Summary',
      description: 'Generating final report',
      icon: FileText,
      order: 4
    }
  ];

  const getAgentStatus = (agentId) => {
    if (!analysisData?.final_analysis?.analysis_quality_metrics?.confidence_distribution) {
      return isAnalyzing ? 'processing' : 'pending';
    }

    const confidence = analysisData.final_analysis.analysis_quality_metrics.confidence_distribution[agentId];
    if (confidence > 0) return 'completed';
    return isAnalyzing ? 'processing' : 'pending';
  };

  const getAgentConfidence = (agentId) => {
    const confidence = analysisData?.final_analysis?.analysis_quality_metrics?.confidence_distribution?.[agentId];
    return confidence ? Math.round(confidence * 100) : 0;
  };

  const getStatusConfig = (status, confidence = 0) => {
    switch (status) {
      case 'completed':
        return {
          color: confidence >= 70 ? 'text-green-600' : 'text-yellow-600',
          bgColor: confidence >= 70 ? 'bg-green-100' : 'bg-yellow-100',
          borderColor: confidence >= 70 ? 'border-green-300' : 'border-yellow-300',
          icon: CheckCircle2,
          pulse: false
        };
      case 'processing':
        return {
          color: 'text-blue-600',
          bgColor: 'bg-blue-100',
          borderColor: 'border-blue-300',
          icon: Clock,
          pulse: true
        };
      default:
        return {
          color: 'text-gray-400',
          bgColor: 'bg-gray-50',
          borderColor: 'border-gray-200',
          icon: Clock,
          pulse: false
        };
    }
  };

  const completedAgents = agents.filter(agent => getAgentStatus(agent.id) === 'completed').length;
  const overallProgress = (completedAgents / agents.length) * 100;

  return (
    <div className="bg-white rounded-lg border border-gray-200 p-6">
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <Brain className="h-6 w-6 text-blue-600" />
          <h3 className="text-lg font-semibold text-gray-900">
            Multi-Agent Analysis Progress
          </h3>
        </div>
        
        {isAnalyzing && (
          <div className="flex items-center gap-2 text-blue-600">
            <div className="animate-spin rounded-full h-4 w-4 border-2 border-blue-600 border-t-transparent"></div>
            <span className="text-sm font-medium">Processing...</span>
          </div>
        )}
      </div>

      {/* Overall Progress Bar */}
      <div className="mb-6">
        <div className="flex justify-between items-center mb-2">
          <span className="text-sm font-medium text-gray-700">
            Overall Progress
          </span>
          <span className="text-sm text-gray-500">
            {completedAgents}/{agents.length} agents completed
          </span>
        </div>
        <div className="w-full bg-gray-200 rounded-full h-2">
          <div 
            className="bg-blue-600 h-2 rounded-full transition-all duration-500 ease-out"
            style={{ width: `${overallProgress}%` }}
          ></div>
        </div>
        {processingTime > 0 && (
          <div className="text-xs text-gray-500 mt-1">
            Processing time: {Math.round(processingTime)}s
          </div>
        )}
      </div>

      {/* Individual Agent Status */}
      <div className="space-y-4">
        {agents.map((agent, index) => {
          const status = getAgentStatus(agent.id);
          const confidence = getAgentConfidence(agent.id);
          const config = getStatusConfig(status, confidence);
          const StatusIcon = config.icon;

          return (
            <div key={agent.id} className="flex items-center gap-4">
              {/* Step indicator */}
              <div className="flex flex-col items-center">
                <div 
                  className={`
                    w-10 h-10 rounded-full border-2 flex items-center justify-center
                    ${config.borderColor} ${config.bgColor}
                    ${config.pulse ? 'animate-pulse' : ''}
                  `}
                >
                  <agent.icon className={`h-5 w-5 ${config.color}`} />
                </div>
                {index < agents.length - 1 && (
                  <div className={`w-0.5 h-8 mt-2 ${
                    status === 'completed' ? 'bg-green-300' : 'bg-gray-200'
                  }`}></div>
                )}
              </div>

              {/* Agent info */}
              <div className="flex-1">
                <div className="flex items-center justify-between">
                  <h4 className="font-medium text-gray-900">{agent.name}</h4>
                  <div className="flex items-center gap-2">
                    {status === 'completed' && (
                      <span className="text-sm text-gray-600">
                        {confidence}% confidence
                      </span>
                    )}
                    <StatusIcon className={`h-4 w-4 ${config.color}`} />
                  </div>
                </div>
                <p className="text-sm text-gray-600">{agent.description}</p>
                
                {/* Progress bar for individual agent */}
                {status === 'processing' && (
                  <div className="mt-2">
                    <div className="w-full bg-gray-200 rounded-full h-1">
                      <div className="bg-blue-600 h-1 rounded-full animate-pulse w-3/4"></div>
                    </div>
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* Summary */}
      {analysisData && !isAnalyzing && (
        <div className="mt-6 pt-4 border-t border-gray-200">
          <div className="flex items-center justify-between text-sm">
            <span className="text-gray-600">Analysis completed</span>
            <span className="font-medium text-green-600">
              ✓ {completedAgents} of {agents.length} agents successful
            </span>
          </div>
        </div>
      )}
    </div>
  );
};

export default AgentProgressTracker;