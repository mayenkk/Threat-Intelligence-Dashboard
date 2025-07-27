import React from 'react';
import { AlertTriangle, Shield, TrendingUp, Zap } from 'lucide-react';

const RiskScoreGauge = ({ 
  score = 0, 
  level = 'unknown', 
  confidence = 0, 
  size = 'medium',
  showDetails = true 
}) => {
  const sizes = {
    small: { container: 'w-16 h-16', text: 'text-xs', icon: 'h-4 w-4' },
    medium: { container: 'w-24 h-24', text: 'text-sm', icon: 'h-5 w-5' },
    large: { container: 'w-32 h-32', text: 'text-base', icon: 'h-6 w-6' }
  };

  const getRiskConfig = (level, score) => {
    switch (level?.toLowerCase()) {
      case 'critical':
        return {
          color: '#dc2626', // red-600
          bgColor: '#fef2f2', // red-50
          textColor: 'text-red-600',
          bgClass: 'bg-red-50',
          icon: AlertTriangle,
          label: 'CRITICAL'
        };
      case 'high':
        return {
          color: '#ea580c', // orange-600
          bgColor: '#fff7ed', // orange-50
          textColor: 'text-orange-600',
          bgClass: 'bg-orange-50',
          icon: TrendingUp,
          label: 'HIGH'
        };
      case 'medium':
        return {
          color: '#d97706', // amber-600
          bgColor: '#fffbeb', // amber-50
          textColor: 'text-amber-600',
          bgClass: 'bg-amber-50',
          icon: Zap,
          label: 'MEDIUM'
        };
      case 'low':
        return {
          color: '#16a34a', // green-600
          bgColor: '#f0fdf4', // green-50
          textColor: 'text-green-600',
          bgClass: 'bg-green-50',
          icon: Shield,
          label: 'LOW'
        };
      default:
        return {
          color: '#6b7280', // gray-500
          bgColor: '#f9fafb', // gray-50
          textColor: 'text-gray-500',
          bgClass: 'bg-gray-50',
          icon: Shield,
          label: 'UNKNOWN'
        };
    }
  };

  const config = getRiskConfig(level, score);
  const Icon = config.icon;
  const sizeConfig = sizes[size];
  
  // Calculate progress (score out of 100)
  const progress = Math.min(Math.max(score, 0), 100);
  const strokeDasharray = 2 * Math.PI * 45; // radius = 45
  const strokeDashoffset = strokeDasharray - (progress / 100) * strokeDasharray;

  return (
    <div className={`relative ${sizeConfig.container} mx-auto mb-4`}>
      {/* SVG Circular Progress */}
      <svg className="transform -rotate-90 w-full h-full" viewBox="0 0 100 100">
        {/* Background circle */}
        <circle
          cx="50"
          cy="50"
          r="45"
          stroke="#e5e7eb"
          strokeWidth="8"
          fill="transparent"
          className="opacity-20"
        />
        {/* Progress circle */}
        <circle
          cx="50"
          cy="50"
          r="45"
          stroke={config.color}
          strokeWidth="8"
          fill="transparent"
          strokeDasharray={strokeDasharray}
          strokeDashoffset={strokeDashoffset}
          strokeLinecap="round"
          className="transition-all duration-1000 ease-out"
          style={{
            filter: 'drop-shadow(0 0 4px rgba(0,0,0,0.1))'
          }}
        />
      </svg>

      {/* Center content */}
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <div className={`font-bold ${sizeConfig.text} ${config.textColor}`}>
          {Math.round(score)}
        </div>
        {size !== 'small' && (
          <Icon className={`${sizeConfig.icon} ${config.textColor} mt-1`} />
        )}
      </div>

      {/* Details below gauge */}
      {showDetails && size !== 'small' && (
        <div className="mt-3 text-center">
          <div className={`inline-block px-2 py-1 rounded text-xs font-semibold ${config.textColor} ${config.bgClass}`}>
            {config.label}
          </div>
          <div className="text-xs text-gray-500 mt-1">
            {Math.round(confidence * 100)}% confidence
          </div>
        </div>
      )}
    </div>
  );
};

export default RiskScoreGauge;
