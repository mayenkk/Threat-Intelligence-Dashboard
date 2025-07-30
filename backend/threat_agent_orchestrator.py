#!/usr/bin/env python3
"""
Multi-Agent Threat Intelligence Orchestrator using LangGraph
Implements specialized agents for comprehensive threat analysis
"""

import asyncio
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, TypedDict, Annotated
from dataclasses import dataclass
from datetime import timedelta
import pandas as pd
import os
import requests


# LangGraph imports
from langgraph.graph import StateGraph, END
from langchain_core.messages import HumanMessage, AIMessage

# Local imports
from ai_analyzer import ThreatAIAnalyzer
import sqlite3

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# State definition for the agent workflow
class ThreatProcessingState(TypedDict):
    """State passed between agents in the workflow"""
    raw_threat: Dict
    source_analysis: Optional[Dict]
    mitre_mapping: Optional[Dict]
    impact_assessment: Optional[Dict]
    executive_summary: Optional[Dict]
    final_analysis: Optional[Dict]
    current_agent: str
    error_log: List[str]
    processing_metadata: Dict

@dataclass
class AgentResponse:
    """Standardized response from each agent"""
    success: bool
    data: Dict
    confidence: float
    processing_time: float
    errors: List[str] = None

class ThreatAgentOrchestrator:
    """
    Multi-agent orchestrator for threat intelligence processing
    """
    
    def __init__(self, project_id: str = "itd-ai-interns", region: str = "us-central1"):
        self.groq_api_key = os.getenv("GROQ_API_KEY")
        self.groq_model = "llama-3.3-70b-versatile" 
        
        # Initialize existing AI analyzer
        self.ai_analyzer = ThreatAIAnalyzer()
        
        # Database connection
        self.conn = sqlite3.connect("../data/threats.db")
        self._create_agent_tables()
        
        # Build the agent workflow graph
        self.workflow = self._build_workflow()
        
        logger.info("🤖 Multi-Agent Threat Orchestrator initialized")
    
    def _create_agent_tables(self):
        """Create database tables for agent results"""
        cursor = self.conn.cursor()
        
        # Agent analysis results table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS agent_analysis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                raw_threat_id INTEGER,
                agent_type TEXT,
                analysis_result TEXT,
                confidence_score REAL,
                processing_time REAL,
                created_at TEXT,
                FOREIGN KEY (raw_threat_id) REFERENCES raw_threats (id)
            )
        """)
        
        # Multi-agent workflow results
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS multi_agent_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                raw_threat_id INTEGER,
                workflow_status TEXT,
                overall_confidence REAL,
                final_analysis TEXT,
                processing_metadata TEXT,
                created_at TEXT,
                FOREIGN KEY (raw_threat_id) REFERENCES raw_threats (id)
            )
        """)
        
        self.conn.commit()
        logger.info("✅ Agent database tables created/verified")
    
    def _build_workflow(self) -> StateGraph:
        """Build the LangGraph workflow for agent orchestration"""
        
        workflow = StateGraph(ThreatProcessingState)
        
        # Add agent nodes 
        workflow.add_node("source_analyzer", self._source_analysis_agent)
        workflow.add_node("mitre_mapper", self._mitre_mapping_agent)
        workflow.add_node("impact_assessor", self._impact_assessment_agent)
        workflow.add_node("summarizer", self._executive_summary_agent)
        workflow.add_node("finalizer", self._finalization_agent)
        
        # Define workflow edges (agent sequence)
        workflow.add_edge("source_analyzer", "mitre_mapper")
        workflow.add_edge("mitre_mapper", "impact_assessor")
        workflow.add_edge("impact_assessor", "summarizer")
        workflow.add_edge("summarizer", "finalizer")
        workflow.add_edge("finalizer", END)
        
        # Set entry point
        workflow.set_entry_point("source_analyzer")
        
        return workflow.compile()
    
    async def _query_llm_async(self, prompt: str) -> str:
        def query_groq(prompt: str) -> str:
            url = "https://api.groq.com/v1/chat/completions"
            headers = {
                "Authorization": f"Bearer {self.groq_api_key}",
                "Content-Type": "application/json"
            }
            data = {
                "model": self.groq_model,
                "messages": [{"role": "user", "content": prompt}],
            }
            response = requests.post(url, headers=headers, json=data, timeout=60)
            response.raise_for_status()
            return response.json()["choices"][0]["message"]["content"]
        return await asyncio.to_thread(query_groq, prompt)
    
    def _parse_json_response(self, response: str) -> Dict:
        """Parse JSON response from LLM"""
        try:
            # Clean the response (remove markdown formatting if present)
            cleaned = response.strip()
            if cleaned.startswith(""):
                cleaned = cleaned[7:]
            if cleaned.endswith(""):
                cleaned = cleaned[:-3]
            
            return json.loads(cleaned.strip())
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON response: {e}")
            return {"error": "Invalid JSON response", "raw_response": response[:500]}
    
    # Placeholder methods for agents (we'll implement these in subsequent parts)
    async def _source_analysis_agent(self, state: ThreatProcessingState) -> ThreatProcessingState:
        """
        Agent 1: Source Analysis & Reputation Verification
        Analyzes source credibility, frequency of false positives, and reliability
        """
        logger.info("🔍 Source Analysis Agent processing...")
        start_time = datetime.now()
        
        try:
            raw_threat = state["raw_threat"]
            source = raw_threat.get("source", "unknown")
            url = raw_threat.get("url", "")
            title = raw_threat.get("title", "")
            
            # Enhanced source analysis prompt
            prompt = f"""
            You are a cybersecurity source analysis expert with extensive knowledge of threat intelligence sources.
            
            Analyze this threat intelligence source for credibility and reliability:
            
            SOURCE: {source}
            URL: {url}
            THREAT TITLE: {title}
            
            Consider these factors in your analysis:
            1. Domain authority and reputation in cybersecurity community
            2. Source type (government, vendor, research institution, blog, etc.)
            3. Historical accuracy and false positive rates
            4. Editorial standards and verification processes
            5. Technical depth and analysis quality
            
            Provide your analysis in this EXACT JSON format:
            {{
                "source_reputation": "excellent|high|medium|low|poor",
                "credibility_score": 85,
                "false_positive_risk": "very_low|low|medium|high|very_high",
                "source_type": "government|security_vendor|research_institution|cybersec_news|tech_blog|forum|social_media|unknown",
                "domain_authority": "verified|established|moderate|questionable|unknown",
                "editorial_standards": "rigorous|professional|basic|minimal|none",
                "technical_depth": "expert|advanced|intermediate|basic|superficial",
                "verification_processes": "multi_source|peer_reviewed|internal_review|minimal|none",
                "historical_accuracy": "excellent|high|medium|low|unknown",
                "bias_assessment": "minimal|slight|moderate|significant|extreme",
                "update_frequency": "real_time|daily|weekly|irregular|sporadic",
                "industry_recognition": "widely_respected|recognized|known|limited|unknown",
                "content_quality_indicators": [
                    "technical_detail_level",
                    "citation_quality", 
                    "analysis_depth"
                ],
                "risk_factors": [
                    "potential_risk_factor_1",
                    "potential_risk_factor_2"
                ],
                "trust_recommendation": "fully_trusted|trusted|cautious|skeptical|not_recommended",
                "confidence_in_analysis": 0.85,
                "source_classification_notes": "Brief explanation of classification reasoning"
            }}
            
            Base your assessment on known cybersecurity industry standards and reputation.
            Be conservative in your scoring - err on the side of caution.
            
            Respond with ONLY the JSON object, no additional text.
            """
            
            # Query LLM for source analysis
            response = await self._query_llm_async(prompt)
            source_analysis = self._parse_json_response(response)
            
            # Validate and enhance the analysis
            source_analysis = self._validate_source_analysis(source_analysis, source, url)
            
            # Calculate processing time
            processing_time = (datetime.now() - start_time).total_seconds()
            
            # Store individual agent result
            await self._store_individual_agent_result(
                raw_threat.get('id'), 
                'source_analysis', 
                source_analysis, 
                processing_time
            )
            
            # Update state
            state["source_analysis"] = source_analysis
            state["current_agent"] = "source_analyzer"
            state["processing_metadata"]["source_analysis_time"] = processing_time
            
            # Log results
            reputation = source_analysis.get('source_reputation', 'unknown')
            credibility = source_analysis.get('credibility_score', 0)
            trust = source_analysis.get('trust_recommendation', 'unknown')
            
            logger.info(f"✅ Source analysis completed - Reputation: {reputation}, Score: {credibility}/100, Trust: {trust}")
            
        except Exception as e:
            error_msg = f"Source analysis failed: {str(e)}"
            logger.error(f"❌ {error_msg}")
            state["error_log"].append(error_msg)
            
            # Provide fallback analysis
            state["source_analysis"] = self._fallback_source_analysis(raw_threat.get("source", "unknown"))
            state["current_agent"] = "source_analyzer"
            state["processing_metadata"]["source_analysis_time"] = (datetime.now() - start_time).total_seconds()
        
        return state

    def _validate_source_analysis(self, analysis: Dict, source: str, url: str) -> Dict:
        """Validate and enhance source analysis with rule-based checks"""
        
        # Known high-reputation sources
        high_reputation_domains = [
            'cisa.gov', 'nist.gov', 'us-cert.gov', 'cert.org',
            'microsoft.com', 'google.com', 'cisco.com', 'crowdstrike.com',
            'fireeye.com', 'mandiant.com', 'symantec.com', 'kaspersky.com',
            'trendmicro.com', 'paloaltonetworks.com', 'fortinet.com',
            'mitre.org', 'sans.org', 'securelist.com', 'krebsonsecurity.com'
        ]
        
        # Government and official sources
        government_domains = [
            '.gov', '.mil', 'cert.', 'cisa.', 'fbi.', 'dhs.',
            'europol.', 'interpol.', 'ncsc.'
        ]
        
        # Extract domain from source or URL
        domain = source.lower()
        if url:
            try:
                from urllib.parse import urlparse
                domain = urlparse(url).netloc.lower()
            except:
                pass
        
        # Apply rule-based validation
        if any(high_domain in domain for high_domain in high_reputation_domains):
            if analysis.get('credibility_score', 0) < 80:
                analysis['credibility_score'] = max(analysis.get('credibility_score', 0), 85)
                analysis['source_reputation'] = 'high'
                analysis['trust_recommendation'] = 'trusted'
                analysis['validation_applied'] = 'high_reputation_domain_boost'
        
        if any(gov_indicator in domain for gov_indicator in government_domains):
            analysis['source_type'] = 'government'
            analysis['credibility_score'] = max(analysis.get('credibility_score', 0), 90)
            analysis['source_reputation'] = 'excellent'
            analysis['trust_recommendation'] = 'fully_trusted'
            analysis['validation_applied'] = 'government_source_boost'
        
        # Ensure required fields exist
        required_fields = {
            'credibility_score': 50,
            'confidence_in_analysis': 0.5,
            'source_reputation': 'medium',
            'trust_recommendation': 'cautious'
        }
        
        for field, default in required_fields.items():
            if field not in analysis or analysis[field] is None:
                analysis[field] = default
        
        # Add validation metadata
        analysis['validation_timestamp'] = datetime.now().isoformat()
        analysis['validation_version'] = '1.0'
        
        return analysis

    def _fallback_source_analysis(self, source: str) -> Dict:
        """Provide basic fallback analysis when LLM fails"""
        return {
            "source_reputation": "medium",
            "credibility_score": 50,
            "false_positive_risk": "medium",
            "source_type": "unknown",
            "domain_authority": "unknown",
            "trust_recommendation": "cautious",
            "confidence_in_analysis": 0.3,
            "error": "LLM analysis failed, using fallback assessment",
            "fallback_mode": True,
            "source_analyzed": source,
            "analysis_timestamp": datetime.now().isoformat()
        }

    async def _store_individual_agent_result(self, threat_id: int, agent_type: str, analysis: Dict, processing_time: float):
        """Store individual agent result in database"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT INTO agent_analysis 
                (raw_threat_id, agent_type, analysis_result, confidence_score, processing_time, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                threat_id,
                agent_type,
                json.dumps(analysis),
                analysis.get('confidence_in_analysis', analysis.get('confidence', 0.5)),
                processing_time,
                datetime.now().isoformat()
            ))
            self.conn.commit()
            logger.debug(f"💾 Stored {agent_type} result for threat {threat_id}")
        except Exception as e:
            logger.error(f"Failed to store {agent_type} result: {e}")
    
    async def _mitre_mapping_agent(self, state: ThreatProcessingState) -> ThreatProcessingState:
        """
        Agent 2: MITRE ATT&CK Framework Mapping
        Maps threat to MITRE ATT&CK tactics, techniques, and procedures
        """
        logger.info("🎯 MITRE Mapping Agent processing...")
        start_time = datetime.now()
        
        try:
            raw_threat = state["raw_threat"]
            source_analysis = state.get("source_analysis", {})
            
            # Get threat content
            title = raw_threat.get('title', '')
            content = raw_threat.get('content', '')
            
            # Enhanced MITRE mapping prompt with real techniques
            prompt = f"""
            You are a MITRE ATT&CK framework expert with deep knowledge of all tactics, techniques, and sub-techniques.
            
            Analyze this threat and map it to the MITRE ATT&CK framework:
            
            THREAT TITLE: {title}
            THREAT CONTENT: {content[:2500]}
            SOURCE CREDIBILITY: {source_analysis.get('credibility_score', 50)}/100
            
            Map this threat to MITRE ATT&CK framework using REAL technique IDs and names.
            
            Provide your analysis in this EXACT JSON format:
            {{
                "tactics": [
                    {{
                        "id": "TA0001",
                        "name": "Initial Access",
                        "description": "Brief description of how this tactic applies",
                        "confidence": 0.9,
                        "evidence": "Specific evidence from threat description"
                    }}
                ],
                "techniques": [
                    {{
                        "id": "T1566",
                        "name": "Phishing",
                        "sub_technique_id": "T1566.001",
                        "sub_technique_name": "Spearphishing Attachment",
                        "tactic": "Initial Access",
                        "confidence": 0.85,
                        "evidence": "Evidence from threat content",
                        "platforms": ["Windows", "macOS", "Linux"],
                        "data_sources": ["Email Gateway", "File Monitoring"]
                    }}
                ],
                "mitigations": [
                    {{
                        "id": "M1049",
                        "name": "Antivirus/Antimalware",
                        "description": "How this mitigation applies",
                        "effectiveness": "high|medium|low",
                        "implementation_priority": "immediate|high|medium|low"
                    }}
                ],
                "attack_pattern_analysis": {{
                    "sophistication_level": "basic|intermediate|advanced|expert",
                    "attack_complexity": "low|medium|high",
                    "stealth_level": "overt|moderate|stealthy",
                    "persistence_methods": ["technique1", "technique2"],
                    "evasion_techniques": ["technique1", "technique2"]
                }},
                "kill_chain_mapping": {{
                    "cyber_kill_chain": ["reconnaissance", "weaponization", "delivery", "exploitation", "installation", "command_control", "actions_objectives"],
                    "phases_identified": ["delivery", "exploitation"],
                    "primary_phase": "delivery"
                }},
                "threat_categorization": {{
                    "threat_type": "malware|ransomware|apt|insider|ddos|phishing|vulnerability_exploit|supply_chain",
                    "actor_sophistication": "script_kiddie|cybercriminal|apt|nation_state",
                    "campaign_indicators": "isolated|coordinated|sustained|advanced_persistent"
                }},
                "mitre_confidence_overall": 0.75,
                "analysis_notes": "Key observations about the threat mapping",
                "gaps_in_information": ["What information would improve mapping accuracy"],
                "recommended_detections": [
                    {{
                        "technique_id": "T1566.001",
                        "detection_method": "Email attachment analysis",
                        "data_source": "Email Gateway Logs",
                        "detection_confidence": "high"
                    }}
                ]
            }}
            
            Important guidelines:
            1. Only include techniques you can confidently identify from the threat description
            2. Use actual MITRE ATT&CK technique IDs (T1XXX format)
            3. Use actual MITRE tactic IDs (TA00XX format) 
            4. Provide specific evidence for each mapping
            5. Be conservative with confidence scores
            6. Focus on logistics/supply chain relevant techniques when applicable
            
            Respond with ONLY the JSON object, no additional text.
            """
            
            # Query LLM for MITRE mapping
            response = await self._query_llm_async(prompt)
            mitre_mapping = self._parse_json_response(response)
            
            # Validate and enhance the MITRE analysis
            mitre_mapping = self._validate_mitre_mapping(mitre_mapping, content)
            
            # Calculate processing time
            processing_time = (datetime.now() - start_time).total_seconds()
            
            # Store individual agent result
            await self._store_individual_agent_result(
                raw_threat.get('id'), 
                'mitre_mapping', 
                mitre_mapping, 
                processing_time
            )
            
            # Update state
            state["mitre_mapping"] = mitre_mapping
            state["current_agent"] = "mitre_mapper"
            state["processing_metadata"]["mitre_mapping_time"] = processing_time
            
            # Log results
            tactics_count = len(mitre_mapping.get("tactics", []))
            techniques_count = len(mitre_mapping.get("techniques", []))
            overall_confidence = mitre_mapping.get("mitre_confidence_overall", 0)
            threat_type = mitre_mapping.get("threat_categorization", {}).get("threat_type", "unknown")
            
            logger.info(f"✅ MITRE mapping completed - {tactics_count} tactics, {techniques_count} techniques, Type: {threat_type}, Confidence: {overall_confidence}")
            
        except Exception as e:
            error_msg = f"MITRE mapping failed: {str(e)}"
            logger.error(f"❌ {error_msg}")
            state["error_log"].append(error_msg)
            
            # Provide fallback MITRE analysis
            state["mitre_mapping"] = self._fallback_mitre_mapping(raw_threat.get("title", ""))
            state["current_agent"] = "mitre_mapper"
            state["processing_metadata"]["mitre_mapping_time"] = (datetime.now() - start_time).total_seconds()
        
        return state

    
    async def _impact_assessment_agent(self, state: ThreatProcessingState) -> ThreatProcessingState:
        """
        Agent 3: Impact Assessment Agent
        Analyzes potential business impact, affected systems, and risk scoring
        """
        logger.info("⚡ Impact Assessment Agent processing...")
        start_time = datetime.now()
        
        try:
            raw_threat = state["raw_threat"]
            source_analysis = state.get("source_analysis", {})
            mitre_mapping = state.get("mitre_mapping", {})
            
            # Get threat content
            title = raw_threat.get('title', '')
            content = raw_threat.get('content', '')
            
            # Extract relevant context for impact assessment
            threat_type = mitre_mapping.get("threat_categorization", {}).get("threat_type", "unknown")
            sophistication = mitre_mapping.get("attack_pattern_analysis", {}).get("sophistication_level", "unknown")
            techniques = mitre_mapping.get("techniques", [])
            technique_list = [f"{t.get('id', 'unknown')}: {t.get('name', 'Unknown')}" for t in techniques]
            
            # Enhanced impact assessment prompt
            prompt = f"""
            You are a cybersecurity risk analyst specializing in logistics and supply chain operations.
            
            Analyze this threat for potential business impact on a global logistics company:
            
            THREAT TITLE: {title}
            THREAT CONTENT: {content[:2500]}
            THREAT TYPE: {threat_type}
            SOPHISTICATION LEVEL: {sophistication}
            MITRE TECHNIQUES: {', '.join(technique_list[:5])}
            SOURCE CREDIBILITY: {source_analysis.get('credibility_score', 50)}/100
            
            Provide a comprehensive impact assessment in this EXACT JSON format:
            {{
                "business_impact_assessment": {{
                    "overall_risk_score": 75,
                    "risk_level": "high|critical|medium|low",
                    "potential_financial_impact": {{
                        "min_estimate_usd": 100000,
                        "max_estimate_usd": 5000000,
                        "impact_categories": ["operational_disruption", "data_breach_costs", "regulatory_fines", "reputation_damage"]
                    }},
                    "operational_impact": {{
                        "severity": "critical|high|medium|low",
                        "affected_operations": ["shipping", "tracking", "inventory", "billing", "customer_service"],
                        "downtime_estimate_hours": 24,
                        "recovery_time_estimate_hours": 72,
                        "customer_impact_level": "severe|moderate|minimal|none"
                    }}
                }},
                "affected_systems_analysis": {{
                    "primary_targets": [
                        {{
                            "system_type": "inventory_management",
                            "criticality": "critical|high|medium|low",
                            "impact_description": "Description of impact",
                            "affected_processes": ["process1", "process2"]
                        }}
                    ],
                    "secondary_targets": ["email_systems", "network_infrastructure", "backup_systems"],
                    "data_at_risk": {{
                        "customer_data": true,
                        "financial_records": true,
                        "operational_data": true,
                        "intellectual_property": false,
                        "supplier_information": true
                    }},
                    "geographic_scope": {{
                        "global_impact": true,
                        "regional_focus": ["North America", "Europe", "Asia-Pacific"],
                        "critical_facilities": ["distribution_centers", "ports", "airports", "headquarters"]
                    }}
                }},
                "vulnerability_assessment": {{
                    "attack_vectors": [
                        {{
                            "vector": "email_phishing",
                            "likelihood": "high|medium|low",
                            "ease_of_exploitation": "easy|moderate|difficult",
                            "mitigation_status": "unprotected|partially_protected|well_protected"
                        }}
                    ],
                    "system_vulnerabilities": {{
                        "outdated_software": "high|medium|low|unknown",
                        "unpatched_systems": "high|medium|low|unknown",
                        "weak_authentication": "high|medium|low|unknown",
                        "network_segmentation": "poor|fair|good|excellent",
                        "employee_training": "insufficient|basic|adequate|comprehensive"
                    }},
                    "threat_actor_capabilities": {{
                        "technical_sophistication": "basic|intermediate|advanced|expert",
                        "resources_available": "limited|moderate|substantial|extensive",
                        "persistence_level": "opportunistic|targeted|persistent|advanced_persistent"
                    }}
                }},
                "compliance_and_regulatory_impact": {{
                    "affected_regulations": ["GDPR", "CCPA", "SOX", "HIPAA", "PCI_DSS"],
                    "potential_violations": [
                        {{
                            "regulation": "GDPR",
                            "violation_type": "data_breach_notification",
                            "potential_fine_range": "€20M or 4% annual revenue",
                            "likelihood": "high|medium|low"
                        }}
                    ],
                    "reporting_requirements": {{
                        "immediate_notification_required": true,
                        "regulatory_bodies": ["data_protection_authority", "sec", "industry_regulators"],
                        "notification_timeframe_hours": 72
                    }}
                }},
                "supply_chain_impact": {{
                    "supplier_risk": {{
                        "tier_1_suppliers": "high|medium|low",
                        "tier_2_suppliers": "high|medium|low",
                        "critical_suppliers": ["supplier_category1", "supplier_category2"]
                    }},
                    "customer_impact": {{
                        "delivery_delays": "severe|moderate|minimal|none",
                        "service_disruption": "complete|partial|minimal|none",
                        "customer_data_exposure": "high|medium|low|none"
                    }},
                    "logistics_disruption": {{
                        "transportation_networks": "severely_impacted|moderately_impacted|minimally_impacted|not_impacted",
                        "warehouse_operations": "severely_impacted|moderately_impacted|minimally_impacted|not_impacted",
                        "tracking_systems": "severely_impacted|moderately_impacted|minimally_impacted|not_impacted"
                    }}
                }},
                "recommended_response": {{
                    "immediate_actions": [
                        "action1: description",
                        "action2: description"
                    ],
                    "short_term_measures": [
                        "measure1: description"
                    ],
                    "long_term_improvements": [
                        "improvement1: description"
                    ],
                    "priority_level": "p0_critical|p1_high|p2_medium|p3_low",
                    "estimated_response_cost_usd": 250000,
                    "resource_requirements": {{
                        "security_team_hours": 120,
                        "it_team_hours": 80,
                        "external_consultants": true,
                        "business_disruption_hours": 48
                    }}
                }},
                "confidence_assessment": {{
                    "impact_confidence": 0.8,
                    "data_quality": "excellent|good|fair|poor",
                    "assessment_limitations": ["limitation1", "limitation2"],
                    "recommendation_confidence": 0.75
                }}
            }}
            
            Important guidelines for logistics company context:
            1. Consider 24/7 operations and global time zones
            2. Factor in seasonal peaks (holidays, weather)
            3. Assess impact on just-in-time delivery models
            4. Consider customer SLA commitments
            5. Evaluate supply chain dependencies
            6. Factor in regulatory compliance for international shipping
            
            Respond with ONLY the JSON object, no additional text.
            """
            
            # Query LLM for impact assessment
            response = await self._query_llm_async(prompt)
            impact_assessment = self._parse_json_response(response)
            
            # Validate and enhance the impact assessment
            impact_assessment = self._validate_impact_assessment(impact_assessment, threat_type, techniques)
            
            # Calculate processing time
            processing_time = (datetime.now() - start_time).total_seconds()
            
            # Store individual agent result
            await self._store_individual_agent_result(
                raw_threat.get('id'), 
                'impact_assessment', 
                impact_assessment, 
                processing_time
            )
            
            # Update state
            state["impact_assessment"] = impact_assessment
            state["current_agent"] = "impact_assessor"
            state["processing_metadata"]["impact_assessment_time"] = processing_time
            
            # Log results
            risk_score = impact_assessment.get("business_impact_assessment", {}).get("overall_risk_score", 0)
            risk_level = impact_assessment.get("business_impact_assessment", {}).get("risk_level", "unknown")
            financial_impact = impact_assessment.get("business_impact_assessment", {}).get("potential_financial_impact", {})
            max_impact = financial_impact.get("max_estimate_usd", 0)
            
            logger.info(f"✅ Impact assessment completed - Risk: {risk_level} ({risk_score}/100), Max Financial Impact: ${max_impact:,}")
            
        except Exception as e:
            error_msg = f"Impact assessment failed: {str(e)}"
            logger.error(f"❌ {error_msg}")
            state["error_log"].append(error_msg)
            
            # Provide fallback impact assessment
            state["impact_assessment"] = self._fallback_impact_assessment(threat_type, raw_threat.get("title", ""))
            state["current_agent"] = "impact_assessor"
            state["processing_metadata"]["impact_assessment_time"] = (datetime.now() - start_time).total_seconds()
        
        return state

    
    async def _geospatial_intelligence_agent(self, state: ThreatProcessingState) -> ThreatProcessingState:
        """
        Agent 4: Geospatial Intelligence Agent
        Analyzes geographic threat patterns, IP locations, and regional risk assessments
        """
        logger.info("🌍 Geospatial Intelligence Agent processing...")
        start_time = datetime.now()
        
        try:
            raw_threat = state["raw_threat"]
            source_analysis = state.get("source_analysis", {})
            mitre_mapping = state.get("mitre_mapping", {})
            impact_assessment = state.get("impact_assessment", {})
            
            # Get threat content
            title = raw_threat.get('title', '')
            content = raw_threat.get('content', '')
            
            # Extract geographic context
            threat_type = mitre_mapping.get("threat_categorization", {}).get("threat_type", "unknown")
            sophistication = mitre_mapping.get("attack_pattern_analysis", {}).get("sophistication_level", "unknown")
            risk_score = impact_assessment.get("business_impact_assessment", {}).get("overall_risk_score", 50)
            
            # Enhanced geospatial analysis prompt
            prompt = f"""
            You are a cybersecurity geospatial intelligence analyst specializing in global threat mapping.
            
            Analyze this threat for geographic patterns and location-based intelligence:
            
            THREAT TITLE: {title}
            THREAT CONTENT: {content[:2500]}
            THREAT TYPE: {threat_type}
            SOPHISTICATION LEVEL: {sophistication}
            RISK SCORE: {risk_score}/100
            SOURCE: {raw_threat.get('source', 'unknown')}
            
            Provide comprehensive geospatial intelligence in this EXACT JSON format:
            {{
                "geographic_origin_analysis": {{
                    "likely_origin_countries": [
                        {{
                            "country": "Country Name",
                            "country_code": "US",
                            "confidence": 0.85,
                            "evidence": ["indicator1", "indicator2"],
                            "threat_actor_presence": "high|medium|low|unknown"
                        }}
                    ],
                    "origin_assessment_confidence": 0.75,
                    "attribution_indicators": ["language_patterns", "timezone_activity", "infrastructure_overlap"],
                    "geographic_scope": "global|regional|national|local"
                }},
                "target_geography_analysis": {{
                    "primary_target_regions": [
                        {{
                            "region": "North America",
                            "countries": ["US", "CA", "MX"],
                            "targeting_confidence": 0.8,
                            "targeting_reasons": ["economic_value", "infrastructure_density", "geopolitical_factors"]
                        }}
                    ],
                    "industry_geographic_focus": {{
                        "logistics_hubs": ["Singapore", "Netherlands", "Germany", "United States"],
                        "port_cities": ["Shanghai", "Los Angeles", "Rotterdam", "Hamburg"],
                        "shipping_lanes": ["Trans-Pacific", "Trans-Atlantic", "Asia-Europe"],
                        "supply_chain_corridors": ["US-Mexico", "EU-Asia", "ASEAN"]
                    }},
                    "regional_vulnerability_assessment": {{
                        "high_risk_regions": ["region1", "region2"],
                        "medium_risk_regions": ["region3", "region4"],
                        "emerging_risk_areas": ["area1", "area2"]
                    }}
                }},
                "ip_and_infrastructure_analysis": {{
                    "malicious_ip_indicators": [
                        {{
                            "ip_address": "192.0.2.1",
                            "country": "Country",
                            "city": "City",
                            "latitude": 40.7128,
                            "longitude": -74.0060,
                            "isp": "ISP Name",
                            "confidence": 0.9,
                            "threat_type": "c2|malware_hosting|phishing|scanning"
                        }}
                    ],
                    "c2_infrastructure": {{
                        "identified_servers": 5,
                        "geographic_distribution": ["US", "DE", "SG"],
                        "hosting_patterns": ["bulletproof_hosting", "compromised_legitimate", "cloud_services"],
                        "infrastructure_sophistication": "basic|intermediate|advanced|professional"
                    }},
                    "domain_analysis": {{
                        "malicious_domains": ["example.com", "malicious-site.net"],
                        "domain_registration_countries": ["US", "PA", "RU"],
                        "registrar_patterns": ["privacy_protected", "fake_information", "legitimate_registrar"],
                        "domain_age_analysis": "new|established|aged"
                    }}
                }},
                "regional_threat_patterns": {{
                    "attack_timing_analysis": {{
                        "primary_timezone": "UTC-5|UTC+0|UTC+8",
                        "peak_activity_hours": [9, 10, 11, 14, 15],
                        "weekend_activity": "high|medium|low|none",
                        "holiday_patterns": "increased|decreased|normal|unknown"
                    }},
                    "regional_attack_methods": {{
                        "preferred_techniques": ["phishing", "malware", "social_engineering"],
                        "cultural_adaptation": "high|medium|low|none",
                        "language_localization": ["English", "Chinese", "Russian"],
                        "regional_compliance_evasion": ["GDPR_evasion", "local_law_evasion"]
                    }},
                    "geopolitical_context": {{
                        "state_sponsored_indicators": "strong|moderate|weak|none",
                        "economic_motivation": "high|medium|low|unknown",
                        "diplomatic_tensions": "relevant|somewhat_relevant|not_relevant",
                        "sanctions_evasion": "likely|possible|unlikely|not_applicable"
                    }}
                }},
                "logistics_geographic_impact": {{
                    "critical_logistics_regions": [
                        {{
                            "region": "Asia-Pacific",
                            "impact_level": "critical|high|medium|low",
                            "key_ports": ["Shanghai", "Singapore", "Hong Kong"],
                            "shipping_volume_at_risk": "percentage_estimate",
                            "alternative_routes": ["route1", "route2"]
                        }}
                    ],
                    "supply_chain_chokepoints": {{
                        "identified_vulnerabilities": ["Suez_Canal", "Panama_Canal", "Strait_of_Malacca"],
                        "backup_route_analysis": "adequate|limited|inadequate|unknown",
                        "seasonal_risk_factors": ["monsoon", "hurricane", "ice"],
                        "geopolitical_stability": "stable|unstable|volatile|unknown"
                    }},
                    "port_and_airport_risks": {{
                        "high_risk_facilities": ["facility1", "facility2"],
                        "cyber_infrastructure_exposure": "high|medium|low|unknown",
                        "physical_security_concerns": "significant|moderate|minimal|none",
                        "operational_continuity_risk": "critical|high|medium|low"
                    }}
                }},
                "threat_migration_patterns": {{
                    "historical_movement": {{
                        "origin_to_target_progression": ["country1", "country2", "country3"],
                        "infrastructure_hopping": "frequent|occasional|rare|none",
                        "seasonal_migration": "evident|limited|none|unknown"
                    }},
                    "predicted_expansion": {{
                        "likely_next_targets": ["country1", "country2"],
                        "expansion_timeline": "immediate|short_term|medium_term|long_term",
                        "expansion_confidence": 0.65
                    }},
                    "containment_opportunities": {{
                        "geographic_barriers": ["regulatory", "technical", "economic"],
                        "international_cooperation": "high|medium|low|none",
                        "containment_feasibility": "high|medium|low|unlikely"
                    }}
                }},
                "coordinates_and_mapping": {{
                    "threat_origin_coordinates": {{
                        "latitude": 40.7128,
                        "longitude": -74.0060,
                        "accuracy_radius_km": 50,
                        "confidence": 0.7
                    }},
                    "target_region_centers": [
                        {{
                            "region": "North America",
                            "latitude": 39.8283,
                            "longitude": -98.5795,
                            "threat_density": "high|medium|low"
                        }}
                    ],
                    "visualization_recommendations": {{
                        "map_zoom_level": 4,
                        "heat_map_appropriate": true,
                        "time_animation_valuable": true,
                        "connection_lines_useful": true
                    }}
                }},
                "confidence_and_limitations": {{
                    "overall_geographic_confidence": 0.75,
                    "data_quality_assessment": "excellent|good|fair|poor",
                    "analysis_limitations": ["limitation1", "limitation2"],
                    "recommendation_reliability": "high|medium|low"
                }}
            }}
            
            Analysis Guidelines:
            1. Focus on logistics-relevant geographic intelligence
            2. Consider global shipping routes and supply chains
            3. Assess regional cybersecurity maturity levels
            4. Factor in geopolitical tensions affecting logistics
            5. Analyze timezone patterns for attribution
            6. Consider economic motivations and targets
            7. Evaluate infrastructure dependencies
            
            Respond with ONLY the JSON object, no additional text.
            """
            
            # Query LLM for geospatial analysis
            response = await self._query_llm_async(prompt)
            geospatial_analysis = self._parse_json_response(response)
            
            # Validate and enhance the geospatial analysis
            geospatial_analysis = self._validate_geospatial_analysis(geospatial_analysis, threat_type, content)
            
            # Calculate processing time
            processing_time = (datetime.now() - start_time).total_seconds()
            
            # Store individual agent result
            await self._store_individual_agent_result(
                raw_threat.get('id'), 
                'geospatial_intelligence', 
                geospatial_analysis, 
                processing_time
            )
            
            # Update state
            state["geospatial_intelligence"] = geospatial_analysis
            state["current_agent"] = "geospatial_analyst"
            state["processing_metadata"]["geospatial_analysis_time"] = processing_time
            
            # Log results
            origin_countries = geospatial_analysis.get("geographic_origin_analysis", {}).get("likely_origin_countries", [])
            target_regions = geospatial_analysis.get("target_geography_analysis", {}).get("primary_target_regions", [])
            confidence = geospatial_analysis.get("confidence_and_limitations", {}).get("overall_geographic_confidence", 0)
            
            origin_summary = ", ".join([c.get("country", "Unknown") for c in origin_countries[:3]])
            target_summary = ", ".join([r.get("region", "Unknown") for r in target_regions[:3]])
            
            logger.info(f"✅ Geospatial analysis completed - Origins: {origin_summary}, Targets: {target_summary}, Confidence: {confidence:.2f}")
        
        except Exception as e:
            error_msg = f"Geospatial analysis failed: {str(e)}"
            logger.error(f"❌ {error_msg}")
            state["error_log"].append(error_msg)
            
            # Provide fallback geospatial analysis
            state["geospatial_intelligence"] = self._fallback_geospatial_analysis(threat_type, raw_threat.get("title", ""))
            state["current_agent"] = "geospatial_analyst"
            state["processing_metadata"]["geospatial_analysis_time"] = (datetime.now() - start_time).total_seconds()
        
        return state

    async def _executive_summary_agent(self, state: ThreatProcessingState) -> ThreatProcessingState:
        """
        Agent 4: Executive Summary Agent
        Creates business-focused summaries and actionable intelligence for executives
        """
        logger.info("📊 Executive Summary Agent processing...")
        start_time = datetime.now()
        
        try:
            raw_threat = state["raw_threat"]
            source_analysis = state.get("source_analysis", {})
            mitre_mapping = state.get("mitre_mapping", {})
            impact_assessment = state.get("impact_assessment", {})
            
            # Extract key information for executive summary
            title = raw_threat.get('title', '')
            content = raw_threat.get('content', '')[:1500]  # Limit content
            
            # Key metrics from previous analyses
            credibility_score = source_analysis.get('credibility_score', 50)
            threat_type = mitre_mapping.get("threat_categorization", {}).get("threat_type", "unknown")
            risk_score = impact_assessment.get("business_impact_assessment", {}).get("overall_risk_score", 50)
            risk_level = impact_assessment.get("business_impact_assessment", {}).get("risk_level", "medium")
            max_financial_impact = impact_assessment.get("business_impact_assessment", {}).get("potential_financial_impact", {}).get("max_estimate_usd", 0)
            
            # Enhanced executive summary prompt
            prompt = f"""
            You are an executive cybersecurity advisor creating a C-level briefing for a global logistics company.
            
            Synthesize this threat intelligence into an executive summary:
            
            THREAT: {title}
            THREAT TYPE: {threat_type}
            SOURCE CREDIBILITY: {credibility_score}/100
            RISK LEVEL: {risk_level.upper()}
            RISK SCORE: {risk_score}/100
            MAX FINANCIAL IMPACT: ${max_financial_impact:,}
            
            THREAT DETAILS: {content}
            
            Create an executive summary in this EXACT JSON format:
            {{
                "executive_overview": {{
                    "threat_name": "Clear, business-focused threat name",
                    "severity_rating": "CRITICAL|HIGH|MEDIUM|LOW",
                    "business_impact": "One sentence describing business impact",
                    "recommended_action": "Immediate action required",
                    "timeline_for_action": "immediate|24_hours|this_week|this_month",
                    "executive_attention_required": true
                }},
                "key_findings": {{
                    "primary_threat": "Main threat in business terms",
                    "attack_method": "How the attack works (non-technical)",
                    "business_systems_at_risk": ["system1", "system2", "system3"],
                    "geographic_scope": "global|regional|local",
                    "threat_actor_sophistication": "nation_state|organized_crime|opportunistic|unknown"
                }},
                "business_impact_summary": {{
                    "operations_affected": ["shipping", "warehousing", "customer_service"],
                    "customer_impact": "severe|moderate|minimal|none",
                    "financial_exposure": {{
                        "immediate_costs": "Range in millions",
                        "potential_losses": "Range in millions", 
                        "business_continuity_risk": "critical|high|medium|low"
                    }},
                    "reputation_risk": "high|medium|low",
                    "regulatory_compliance_risk": "high|medium|low|none"
                }},
                "strategic_recommendations": {{
                    "immediate_actions": [
                        "Action 1 for immediate implementation",
                        "Action 2 for immediate implementation"
                    ],
                    "short_term_priorities": [
                        "Priority 1 (next 30 days)",
                        "Priority 2 (next 30 days)"
                    ],
                    "long_term_strategic_initiatives": [
                        "Strategic initiative 1",
                        "Strategic initiative 2"
                    ],
                    "resource_requirements": {{
                        "budget_estimate": "dollar_range",
                        "staffing_needs": "description",
                        "external_expertise": "needed|recommended|not_required"
                    }}
                }},
                "risk_context": {{
                    "industry_trend": "increasing|stable|decreasing",
                    "threat_evolution": "new_threat|evolving_threat|known_threat",
                    "competitive_impact": "all_industry|logistics_focused|company_specific",
                    "seasonal_factors": "relevant|not_relevant",
                    "supply_chain_implications": "severe|moderate|minimal|none"
                }},
                "communication_guidance": {{
                    "board_briefing_points": [
                        "Key point 1 for board",
                        "Key point 2 for board"
                    ],
                    "customer_communication": "required|recommended|not_needed",
                    "public_relations_considerations": "high|medium|low|none",
                    "regulatory_notification": "required|recommended|not_required",
                    "internal_communication_urgency": "all_hands|leadership|it_security|normal"
                }},
                "competitive_intelligence": {{
                    "industry_peers_affected": "widespread|some|few|unknown",
                    "competitive_advantage_opportunity": "high|medium|low|none",
                    "market_positioning_impact": "positive|neutral|negative",
                    "customer_confidence_factors": ["factor1", "factor2"]
                }},
                "success_metrics": {{
                    "incident_response_kpis": [
                        "Response time target",
                        "Recovery time target"
                    ],
                    "business_continuity_measures": [
                        "Measure 1",
                        "Measure 2"
                    ],
                    "stakeholder_confidence_indicators": [
                        "Customer retention rate",
                        "Partner confidence level"
                    ]
                }},
                "executive_decision_points": {{
                    "budget_approval_needed": "immediate|planned|not_required",
                    "policy_changes_required": "major|minor|none",
                    "vendor_relationships": "new_partnerships|existing_expansion|no_change",
                    "strategic_planning_impact": "significant|moderate|minimal"
                }},
                "confidence_and_limitations": {{
                    "assessment_confidence": 0.85,
                    "data_quality": "excellent|good|fair|limited",
                    "intelligence_gaps": ["gap1", "gap2"],
                    "recommendation_reliability": "high|medium|low"
                }}
            }}
            
            Guidelines:
            1. Use business language, not technical jargon
            2. Focus on operational and financial impacts
            3. Provide clear, actionable recommendations
            4. Consider global logistics context (24/7 operations, supply chains)
            5. Address stakeholder communication needs
            6. Emphasize competitive and market implications
            
            Respond with ONLY the JSON object, no additional text.
            """
            
            # Query LLM for executive summary
            response = await self._query_llm_async(prompt)
            executive_summary = self._parse_json_response(response)
            
            # Validate and enhance the executive summary
            executive_summary = self._validate_executive_summary(executive_summary, risk_level, threat_type, max_financial_impact)
            
            # Calculate processing time
            processing_time = (datetime.now() - start_time).total_seconds()
            
            # Store individual agent result
            await self._store_individual_agent_result(
                raw_threat.get('id'), 
                'executive_summary', 
                executive_summary, 
                processing_time
            )
            
            # Update state
            state["executive_summary"] = executive_summary
            state["current_agent"] = "summarizer"
            state["processing_metadata"]["executive_summary_time"] = processing_time
            
            # Log results
            overview = executive_summary.get("executive_overview", {})
            severity = overview.get("severity_rating", "unknown")
            timeline = overview.get("timeline_for_action", "unknown")
            confidence = executive_summary.get("confidence_and_limitations", {}).get("assessment_confidence", 0)
            
            logger.info(f"✅ Executive summary completed - Severity: {severity}, Action Timeline: {timeline}, Confidence: {confidence:.2f}")
            
        except Exception as e:
            error_msg = f"Executive summary failed: {str(e)}"
            logger.error(f"❌ {error_msg}")
            state["error_log"].append(error_msg)
            
            # Provide fallback executive summary
            state["executive_summary"] = self._fallback_executive_summary(threat_type, risk_level, raw_threat.get("title", ""))
            state["current_agent"] = "summarizer"
            state["processing_metadata"]["executive_summary_time"] = (datetime.now() - start_time).total_seconds()
        
        return state

    async def _finalization_agent(self, state: ThreatProcessingState) -> ThreatProcessingState:
        """
        Agent 5: Finalization Agent
        Synthesizes all agent analyses into final comprehensive threat assessment
        """
        logger.info("🎯 Finalization Agent processing...")
        start_time = datetime.now()
        
        try:
            raw_threat = state["raw_threat"]
            source_analysis = state.get("source_analysis", {})
            mitre_mapping = state.get("mitre_mapping", {})
            impact_assessment = state.get("impact_assessment", {})
            executive_summary = state.get("executive_summary", {})
            
            # Extract key metrics from all agents
            credibility_score = source_analysis.get('credibility_score', 50)
            source_confidence = source_analysis.get('confidence_in_analysis', 0.5)
            mitre_confidence = mitre_mapping.get('mitre_confidence_overall', 0.5)
            impact_confidence = impact_assessment.get("confidence_assessment", {}).get("impact_confidence", 0.5)
            exec_confidence = executive_summary.get("confidence_and_limitations", {}).get("assessment_confidence", 0.5)
            
            # Calculate overall confidence score
            confidence_weights = {
                'source': 0.2,
                'mitre': 0.25,
                'impact': 0.3,
                'executive': 0.25
            }
            
            overall_confidence = (
                source_confidence * confidence_weights['source'] +
                mitre_confidence * confidence_weights['mitre'] +
                impact_confidence * confidence_weights['impact'] +
                exec_confidence * confidence_weights['executive']
            )
            
            # Extract risk metrics
            risk_score = impact_assessment.get("business_impact_assessment", {}).get("overall_risk_score", 50)
            risk_level = impact_assessment.get("business_impact_assessment", {}).get("risk_level", "medium")
            severity_rating = executive_summary.get("executive_overview", {}).get("severity_rating", "MEDIUM")
            
            # Threat categorization
            threat_type = mitre_mapping.get("threat_categorization", {}).get("threat_type", "unknown")
            sophistication = mitre_mapping.get("attack_pattern_analysis", {}).get("sophistication_level", "unknown")
            
            # Financial impact
            financial_impact = impact_assessment.get("business_impact_assessment", {}).get("potential_financial_impact", {})
            max_financial_impact = financial_impact.get("max_estimate_usd", 0)
            
            # Processing metadata
            processing_metadata = state.get("processing_metadata", {})
            total_processing_time = sum([
                processing_metadata.get("source_analysis_time", 0),
                processing_metadata.get("mitre_mapping_time", 0),
                processing_metadata.get("impact_assessment_time", 0),
                processing_metadata.get("executive_summary_time", 0)
            ])
            
            # Create comprehensive final analysis
            final_analysis = {
                "threat_intelligence_summary": {
                    "threat_id": raw_threat.get('id'),
                    "threat_title": raw_threat.get('title', ''),
                    "source": raw_threat.get('source', ''),
                    "analysis_timestamp": datetime.now().isoformat(),
                    "workflow_id": processing_metadata.get("workflow_id"),
                    "processing_version": "1.0"
                },
                "overall_assessment": {
                    "final_risk_score": risk_score,
                    "risk_level": risk_level,
                    "severity_rating": severity_rating,
                    "threat_classification": threat_type,
                    "sophistication_level": sophistication,
                    "overall_confidence": round(overall_confidence, 3),
                    "assessment_quality": self._determine_assessment_quality(overall_confidence),
                    "priority_classification": self._determine_priority(risk_score, severity_rating, threat_type)
                },
                "multi_agent_consensus": {
                    "source_credibility_consensus": {
                        "credibility_score": credibility_score,
                        "trust_level": source_analysis.get('trust_recommendation', 'cautious'),
                        "confidence": source_confidence
                    },
                    "threat_characterization_consensus": {
                        "mitre_techniques_identified": len(mitre_mapping.get("techniques", [])),
                        "attack_complexity": mitre_mapping.get("attack_pattern_analysis", {}).get("attack_complexity", "unknown"),
                        "confidence": mitre_confidence
                    },
                    "business_impact_consensus": {
                        "financial_exposure_range": f"${financial_impact.get('min_estimate_usd', 0):,} - ${max_financial_impact:,}",
                        "operational_severity": impact_assessment.get("business_impact_assessment", {}).get("operational_impact", {}).get("severity", "unknown"),
                        "confidence": impact_confidence
                    },
                    "executive_readiness": {
                        "executive_attention_required": executive_summary.get("executive_overview", {}).get("executive_attention_required", False),
                        "action_timeline": executive_summary.get("executive_overview", {}).get("timeline_for_action", "unknown"),
                        "confidence": exec_confidence
                    }
                }
            }
            
            # Continue building the final analysis...
            final_analysis.update(self._build_intelligence_highlights(mitre_mapping, impact_assessment, executive_summary))
            final_analysis.update(self._build_quality_metrics(state, total_processing_time, overall_confidence))
            final_analysis.update(self._build_actionable_intelligence(risk_score, threat_type, sophistication, max_financial_impact, executive_summary))
            
            # Calculate processing time
            processing_time = (datetime.now() - start_time).total_seconds()
            
            # Store individual agent result
            await self._store_individual_agent_result(
                raw_threat.get('id'), 
                'finalization', 
                final_analysis, 
                processing_time
            )
            
            # Update state
            state["final_analysis"] = final_analysis
            state["current_agent"] = "finalizer"
            state["processing_metadata"]["finalization_time"] = processing_time
            state["processing_metadata"]["total_workflow_time"] = total_processing_time + processing_time
            
            # Log final results
            logger.info(f"✅ Finalization completed - Final Risk: {risk_level.upper()} ({risk_score}/100), "
                       f"Confidence: {overall_confidence:.2f}, Total Time: {total_processing_time + processing_time:.1f}s")
            
        except Exception as e:
            error_msg = f"Finalization failed: {str(e)}"
            logger.error(f"❌ {error_msg}")
            state["error_log"].append(error_msg)
            
            # Provide minimal final analysis
            state["final_analysis"] = self._fallback_final_analysis(raw_threat, state)
            state["current_agent"] = "finalizer"
            state["processing_metadata"]["finalization_time"] = (datetime.now() - start_time).total_seconds()
        
        return state


    def _validate_executive_summary(self, summary: Dict, risk_level: str, threat_type: str, financial_impact: int) -> Dict:
        """Validate and enhance executive summary with business logic"""
        
        # Ensure severity aligns with risk level
        severity_mapping = {
            "critical": "CRITICAL",
            "high": "HIGH", 
            "medium": "MEDIUM",
            "low": "LOW"
        }
        
        overview = summary.get("executive_overview", {})
        expected_severity = severity_mapping.get(risk_level, "MEDIUM")
        
        if overview.get("severity_rating") != expected_severity:
            overview["severity_rating"] = expected_severity
            overview["validation_adjustment"] = f"Severity aligned with risk level: {risk_level}"
        
        # Adjust timeline based on severity
        if expected_severity == "CRITICAL" and overview.get("timeline_for_action") not in ["immediate", "24_hours"]:
            overview["timeline_for_action"] = "immediate"
            overview["timeline_adjustment"] = "Accelerated for critical severity"
        
        # Ensure executive attention for high-impact threats
        if financial_impact > 5000000 or expected_severity in ["CRITICAL", "HIGH"]:
            overview["executive_attention_required"] = True
        
        # Validate financial exposure consistency
        business_impact = summary.get("business_impact_summary", {})
        financial_exposure = business_impact.get("financial_exposure", {})
        
        if financial_impact > 10000000:
            financial_exposure["immediate_costs"] = "10-50 million range"
            financial_exposure["potential_losses"] = "50+ million range"
        elif financial_impact > 1000000:
            financial_exposure["immediate_costs"] = "1-10 million range"
            financial_exposure["potential_losses"] = "10-50 million range"
        
        # Threat-specific adjustments
        if threat_type == "ransomware":
            business_impact["business_continuity_risk"] = "critical"
            business_impact["reputation_risk"] = "high"
        elif threat_type == "supply_chain":
            business_impact["business_continuity_risk"] = "critical"
            summary.get("risk_context", {})["supply_chain_implications"] = "severe"
        
        # Ensure required fields exist
        required_sections = {
            "executive_overview": {},
            "key_findings": {},
            "business_impact_summary": {},
            "strategic_recommendations": {},
            "confidence_and_limitations": {"assessment_confidence": 0.5}
        }
        
        for section, defaults in required_sections.items():
            if section not in summary:
                summary[section] = defaults
            else:
                for key, default_value in defaults.items():
                    if key not in summary[section]:
                        summary[section][key] = default_value
        
        # Add validation metadata
        summary["validation_applied"] = True
        summary["validation_timestamp"] = datetime.now().isoformat()
        summary["business_logic_validation"] = {
            "severity_alignment_checked": True,
            "financial_consistency_verified": True,
            "threat_type_adjustments_applied": True
        }
        
        return summary

    def _fallback_executive_summary(self, threat_type: str, risk_level: str, title: str) -> Dict:
        """Provide basic fallback executive summary when LLM fails"""
        
        severity_mapping = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW"}
        severity = severity_mapping.get(risk_level, "MEDIUM")
        
        threat_descriptions = {
            "ransomware": "Ransomware attack threatening operations and data",
            "supply_chain": "Supply chain compromise affecting business partners",
            "phishing": "Targeted phishing campaign against employees",
            "malware": "Malware infection threatening systems",
            "ddos": "Service disruption from network attacks"
        }
        
        description = threat_descriptions.get(threat_type, "Cybersecurity threat requiring attention")
        
        return {
            "executive_overview": {
                "threat_name": title[:100] if title else "Cybersecurity Threat",
                "severity_rating": severity,
                "business_impact": description,
                "recommended_action": "Activate incident response team",
                "timeline_for_action": "immediate" if severity == "CRITICAL" else "24_hours",
                "executive_attention_required": severity in ["CRITICAL", "HIGH"]
            },
            "key_findings": {
                "primary_threat": f"{threat_type.replace('_', ' ').title()} attack",
                "attack_method": "Cyber attack targeting business operations",
                "business_systems_at_risk": ["email", "network", "databases"],
                "geographic_scope": "unknown",
                "threat_actor_sophistication": "unknown"
            },
            "business_impact_summary": {
                "operations_affected": ["shipping", "it_systems"],
                "customer_impact": "moderate",
                "financial_exposure": {
                    "immediate_costs": "TBD based on assessment",
                    "potential_losses": "TBD based on assessment",
                    "business_continuity_risk": "medium"
                },
                "reputation_risk": "medium",
                "regulatory_compliance_risk": "medium"
            },
            "strategic_recommendations": {
                "immediate_actions": [
                    "Activate incident response procedures",
                    "Assess system integrity and user access"
                ],
                "short_term_priorities": [
                    "Complete threat assessment",
                    "Implement additional monitoring"
                ],
                "resource_requirements": {
                    "budget_estimate": "TBD",
                    "staffing_needs": "IT security team engagement",
                    "external_expertise": "recommended"
                }
            },
            "confidence_and_limitations": {
                "assessment_confidence": 0.3,
                "data_quality": "limited",
                "intelligence_gaps": ["LLM analysis failed", "Limited threat intelligence"],
                "recommendation_reliability": "low"
            },
            "fallback_mode": True,
            "threat_type_analyzed": threat_type,
            "risk_level_analyzed": risk_level,
            "analysis_timestamp": datetime.now().isoformat()
        }


    async def process_threat(self, threat_data: Dict) -> Dict:
        """
        Main entry point for processing a threat through the multi-agent workflow
        """
        logger.info(f"🚀 Starting multi-agent analysis for threat: {threat_data.get('title', 'Unknown')[:50]}...")
        
        # Initialize state
        initial_state = ThreatProcessingState(
            raw_threat=threat_data,
            source_analysis=None,
            mitre_mapping=None,
            impact_assessment=None,
            executive_summary=None,
            final_analysis=None,
            current_agent="initializing",
            error_log=[],
            processing_metadata={
                "start_time": datetime.now().isoformat(),
                "workflow_id": f"workflow_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                "threat_id": threat_data.get('id', 'unknown')
            }
        )
        
        try:
            # Run the workflow
            final_state = await self.workflow.ainvoke(initial_state)
            
            # Store results in database
            await self._store_agent_results(final_state)
            
            logger.info("🎯 Multi-agent analysis completed successfully")
            return final_state
            
        except Exception as e:
            logger.error(f"❌ Multi-agent workflow failed: {e}")
            return {
                "error": str(e),
                "partial_results": initial_state,
                "status": "failed"
            }
    
    async def _store_agent_results(self, final_state: ThreatProcessingState):
        """Store agent analysis results in database"""
        try:
            threat_id = final_state["raw_threat"].get('id')
            cursor = self.conn.cursor()
            
            # Store individual agent results
            for agent_type in ['source_analysis', 'mitre_mapping', 'impact_assessment', 'executive_summary']:
                if final_state.get(agent_type):
                    cursor.execute("""
                        INSERT INTO agent_analysis 
                        (raw_threat_id, agent_type, analysis_result, confidence_score, processing_time, created_at)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (
                        threat_id,
                        agent_type,
                        json.dumps(final_state[agent_type]),
                        final_state[agent_type].get('confidence', 0.5),
                        final_state["processing_metadata"].get(f"{agent_type}_time", 0),
                        datetime.now().isoformat()
                    ))
            
            # Store overall workflow result
            cursor.execute("""
                INSERT INTO multi_agent_results 
                (raw_threat_id, workflow_status, overall_confidence, final_analysis, processing_metadata, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                threat_id,
                "completed",
                final_state.get("final_analysis", {}).get("overall_confidence", 0.5),
                json.dumps(final_state.get("final_analysis", {})),
                json.dumps(final_state["processing_metadata"]),
                datetime.now().isoformat()
            ))
            
            self.conn.commit()
            logger.info("💾 Agent results stored in database")
            
        except Exception as e:
            logger.error(f"Failed to store agent results: {e}")

    def get_source_analysis_for_threat(self, threat_id: int) -> Optional[Dict]:
        """Retrieve source analysis for a specific threat"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT analysis_result, created_at 
                FROM agent_analysis 
                WHERE raw_threat_id = ? AND agent_type = 'source_analysis'
                ORDER BY created_at DESC 
                LIMIT 1
            """, (threat_id,))
            
            result = cursor.fetchone()
            if result:
                analysis = json.loads(result[0])
                analysis['retrieved_at'] = result[1]
                return analysis
            return None
        except Exception as e:
            logger.error(f"Failed to retrieve source analysis: {e}")
            return None

    def get_source_reliability_summary(self) -> Dict:
        """Get summary of source reliability across all analyzed threats"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT 
                    json_extract(analysis_result, '$.source_type') as source_type,
                    AVG(json_extract(analysis_result, '$.credibility_score')) as avg_credibility,
                    COUNT(*) as analysis_count,
                    json_extract(analysis_result, '$.trust_recommendation') as trust_level
                FROM agent_analysis 
                WHERE agent_type = 'source_analysis'
                GROUP BY source_type, trust_level
                ORDER BY avg_credibility DESC
            """)
            
            results = cursor.fetchall()
            
            summary = {
                "source_types": {},
                "trust_distribution": {},
                "overall_avg_credibility": 0,
                "total_analyses": 0
            }
            
            total_credibility = 0
            total_count = 0
            
            for row in results:
                source_type = row[0] or 'unknown'
                avg_cred = row[1] or 0
                count = row[2]
                trust = row[3] or 'unknown'
                
                if source_type not in summary["source_types"]:
                    summary["source_types"][source_type] = {
                        "avg_credibility": avg_cred,
                        "count": count,
                        "trust_levels": {}
                    }
                
                summary["source_types"][source_type]["trust_levels"][trust] = count
                summary["trust_distribution"][trust] = summary["trust_distribution"].get(trust, 0) + count
                
                total_credibility += avg_cred * count
                total_count += count
            
            if total_count > 0:
                summary["overall_avg_credibility"] = round(total_credibility / total_count, 1)
            summary["total_analyses"] = total_count
            
            return summary
            
        except Exception as e:
            logger.error(f"Failed to get source reliability summary: {e}")
            return {"error": str(e)}
        
    def _validate_mitre_mapping(self, mapping: Dict, content: str) -> Dict:
        """Validate and enhance MITRE mapping with rule-based checks"""
        
        # Common technique patterns for quick validation
        technique_patterns = {
            "T1566": ["phishing", "spear phishing", "email", "malicious attachment"],
            "T1059": ["command line", "powershell", "cmd", "script", "shell"],
            "T1105": ["download", "remote file", "payload", "dropper"],
            "T1083": ["file discovery", "enumerate", "list files", "directory"],
            "T1082": ["system information", "systeminfo", "environment", "os version"],
            "T1047": ["wmi", "windows management", "remote execution"],
            "T1055": ["process injection", "dll injection", "code injection"],
            "T1027": ["obfuscation", "encoded", "encrypted", "packed"],
            "T1486": ["ransomware", "encryption", "file encryption", "ransom"],
            "T1567": ["exfiltration", "data theft", "upload", "cloud storage"]
        }
        
        # Validate techniques against content
        content_lower = content.lower()
        validated_techniques = []
        
        # Check if mapped techniques have supporting evidence
        for technique in mapping.get("techniques", []):
            technique_id = technique.get("id", "")
            if technique_id in technique_patterns:
                patterns = technique_patterns[technique_id]
                if any(pattern in content_lower for pattern in patterns):
                    technique["validation_status"] = "confirmed"
                    technique["validation_evidence"] = f"Content contains relevant keywords for {technique_id}"
                else:
                    technique["validation_status"] = "weak_evidence"
                    technique["confidence"] = max(0.3, technique.get("confidence", 0.5) * 0.7)
            else:
                technique["validation_status"] = "unknown_technique"
            
            validated_techniques.append(technique)
        
        mapping["techniques"] = validated_techniques
        
        # Add rule-based technique suggestions for high-confidence patterns
        suggested_techniques = []
        for tech_id, patterns in technique_patterns.items():
            if any(pattern in content_lower for pattern in patterns):
                # Check if not already mapped
                existing_ids = [t.get("id") for t in mapping.get("techniques", [])]
                if tech_id not in existing_ids:
                    suggested_techniques.append({
                        "id": tech_id,
                        "name": self._get_technique_name(tech_id),
                        "confidence": 0.7,
                        "evidence": f"Automated detection based on content patterns",
                        "suggested_by": "rule_based_validation",
                        "validation_status": "auto_suggested"
                    })
        
        if suggested_techniques:
            mapping["auto_suggested_techniques"] = suggested_techniques
        
        # Ensure required fields
        if "mitre_confidence_overall" not in mapping:
            avg_confidence = 0.5
            if mapping.get("techniques"):
                confidences = [t.get("confidence", 0.5) for t in mapping["techniques"]]
                avg_confidence = sum(confidences) / len(confidences)
            mapping["mitre_confidence_overall"] = avg_confidence
        
        # Add validation metadata
        mapping["validation_applied"] = True
        mapping["validation_timestamp"] = datetime.now().isoformat()
        mapping["content_analysis_performed"] = True
        
        return mapping
    
    def _validate_mitre_mapping(self, mapping: Dict, content: str) -> Dict:
        """Validate and enhance MITRE mapping with rule-based checks"""
        
        # Common technique patterns for quick validation
        technique_patterns = {
            "T1566": ["phishing", "spear phishing", "email", "malicious attachment"],
            "T1059": ["command line", "powershell", "cmd", "script", "shell"],
            "T1105": ["download", "remote file", "payload", "dropper"],
            "T1083": ["file discovery", "enumerate", "list files", "directory"],
            "T1082": ["system information", "systeminfo", "environment", "os version"],
            "T1047": ["wmi", "windows management", "remote execution"],
            "T1055": ["process injection", "dll injection", "code injection"],
            "T1027": ["obfuscation", "encoded", "encrypted", "packed"],
            "T1486": ["ransomware", "encryption", "file encryption", "ransom"],
            "T1567": ["exfiltration", "data theft", "upload", "cloud storage"]
        }
        
        # Validate techniques against content
        content_lower = content.lower()
        validated_techniques = []
        
        # Check if mapped techniques have supporting evidence
        for technique in mapping.get("techniques", []):
            technique_id = technique.get("id", "")
            if technique_id in technique_patterns:
                patterns = technique_patterns[technique_id]
                if any(pattern in content_lower for pattern in patterns):
                    technique["validation_status"] = "confirmed"
                    technique["validation_evidence"] = f"Content contains relevant keywords for {technique_id}"
                else:
                    technique["validation_status"] = "weak_evidence"
                    technique["confidence"] = max(0.3, technique.get("confidence", 0.5) * 0.7)
            else:
                technique["validation_status"] = "unknown_technique"
            
            validated_techniques.append(technique)
        
        mapping["techniques"] = validated_techniques
        
        # Add rule-based technique suggestions for high-confidence patterns
        suggested_techniques = []
        for tech_id, patterns in technique_patterns.items():
            if any(pattern in content_lower for pattern in patterns):
                # Check if not already mapped
                existing_ids = [t.get("id") for t in mapping.get("techniques", [])]
                if tech_id not in existing_ids:
                    suggested_techniques.append({
                        "id": tech_id,
                        "name": self._get_technique_name(tech_id),
                        "confidence": 0.7,
                        "evidence": f"Automated detection based on content patterns",
                        "suggested_by": "rule_based_validation",
                        "validation_status": "auto_suggested"
                    })
        
        if suggested_techniques:
            mapping["auto_suggested_techniques"] = suggested_techniques
        
        # Ensure required fields
        if "mitre_confidence_overall" not in mapping:
            avg_confidence = 0.5
            if mapping.get("techniques"):
                confidences = [t.get("confidence", 0.5) for t in mapping["techniques"]]
                avg_confidence = sum(confidences) / len(confidences)
            mapping["mitre_confidence_overall"] = avg_confidence
        
        # Add validation metadata
        mapping["validation_applied"] = True
        mapping["validation_timestamp"] = datetime.now().isoformat()
        mapping["content_analysis_performed"] = True
        
        return mapping
    
    def get_mitre_analysis_for_threat(self, threat_id: int) -> Optional[Dict]:
        """Retrieve MITRE analysis for a specific threat"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT analysis_result, created_at 
                FROM agent_analysis 
                WHERE raw_threat_id = ? AND agent_type = 'mitre_mapping'
                ORDER BY created_at DESC 
                LIMIT 1
            """, (threat_id,))
            
            result = cursor.fetchone()
            if result:
                analysis = json.loads(result[0])
                analysis['retrieved_at'] = result[1]
                return analysis
            return None
        except Exception as e:
            logger.error(f"Failed to retrieve MITRE analysis: {e}")
            return None

    def get_mitre_technique_frequency(self) -> Dict:
        """Get frequency analysis of MITRE techniques across all threats"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT analysis_result
                FROM agent_analysis 
                WHERE agent_type = 'mitre_mapping'
            """)
            
            results = cursor.fetchall()
            technique_freq = {}
            tactic_freq = {}
            threat_types = {}
            
            for row in results:
                try:
                    analysis = json.loads(row[0])
                    
                    # Count techniques
                    for technique in analysis.get("techniques", []):
                        tech_id = technique.get("id", "unknown")
                        tech_name = technique.get("name", "Unknown")
                        confidence = technique.get("confidence", 0)
                        
                        if tech_id not in technique_freq:
                            technique_freq[tech_id] = {
                                "name": tech_name,
                                "count": 0,
                                "avg_confidence": 0,
                                "total_confidence": 0
                            }
                        
                        technique_freq[tech_id]["count"] += 1
                        technique_freq[tech_id]["total_confidence"] += confidence
                        technique_freq[tech_id]["avg_confidence"] = round(
                            technique_freq[tech_id]["total_confidence"] / 
                            technique_freq[tech_id]["count"], 2
                        )
                    
                    # Count tactics
                    for tactic in analysis.get("tactics", []):
                        tactic_id = tactic.get("id", "unknown")
                        tactic_name = tactic.get("name", "Unknown")
                        
                        if tactic_id not in tactic_freq:
                            tactic_freq[tactic_id] = {
                                "name": tactic_name,
                                "count": 0
                            }
                        tactic_freq[tactic_id]["count"] += 1
                    
                    # Count threat types
                    threat_cat = analysis.get("threat_categorization", {})
                    threat_type = threat_cat.get("threat_type", "unknown")
                    
                    if threat_type not in threat_types:
                        threat_types[threat_type] = 0
                    threat_types[threat_type] += 1
                    
                except json.JSONDecodeError:
                    continue
            
            # Sort by frequency
            sorted_techniques = dict(sorted(
                technique_freq.items(), 
                key=lambda x: x[1]["count"], 
                reverse=True
            ))
            
            sorted_tactics = dict(sorted(
                tactic_freq.items(), 
                key=lambda x: x[1]["count"], 
                reverse=True
            ))
            
            return {
                "top_techniques": sorted_techniques,
                "top_tactics": sorted_tactics,
                "threat_type_distribution": threat_types,
                "total_analyses": len(results),
                "generated_at": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to get MITRE frequency analysis: {e}")
            return {"error": str(e)}
        
    def get_mitre_attack_patterns(self, days: int = 30) -> Dict:
        """Get advanced MITRE attack pattern analysis"""
        try:
            cursor = self.conn.cursor()
            time_threshold = (datetime.now() - timedelta(days=days)).isoformat()
            
            cursor.execute("""
                SELECT a.analysis_result, r.collected_at, r.source
                FROM agent_analysis a
                JOIN raw_threats r ON a.raw_threat_id = r.id
                WHERE a.agent_type = 'mitre_mapping'
                AND r.collected_at > ?
                ORDER BY r.collected_at DESC
            """, (time_threshold,))
            
            results = cursor.fetchall()
            
            # Analysis containers
            kill_chain_analysis = {}
            sophistication_levels = {}
            attack_complexity = {}
            source_technique_mapping = {}
            temporal_patterns = {}
            
            for row in results:
                try:
                    analysis = json.loads(row[0])
                    collected_date = row[1][:10]  # YYYY-MM-DD
                    source = row[2]
                    
                    # Kill chain analysis
                    kill_chain = analysis.get("kill_chain_mapping", {})
                    phases = kill_chain.get("phases_identified", [])
                    for phase in phases:
                        kill_chain_analysis[phase] = kill_chain_analysis.get(phase, 0) + 1
                    
                    # Sophistication tracking
                    attack_pattern = analysis.get("attack_pattern_analysis", {})
                    sophistication = attack_pattern.get("sophistication_level", "unknown")
                    sophistication_levels[sophistication] = sophistication_levels.get(sophistication, 0) + 1
                    
                    complexity = attack_pattern.get("attack_complexity", "unknown")
                    attack_complexity[complexity] = attack_complexity.get(complexity, 0) + 1
                    
                    # Source-technique mapping
                    if source not in source_technique_mapping:
                        source_technique_mapping[source] = {}
                    
                    for technique in analysis.get("techniques", []):
                        tech_id = technique.get("id", "unknown")
                        if tech_id not in source_technique_mapping[source]:
                            source_technique_mapping[source][tech_id] = 0
                        source_technique_mapping[source][tech_id] += 1
                    
                    # Temporal patterns
                    if collected_date not in temporal_patterns:
                        temporal_patterns[collected_date] = {
                            "total_threats": 0,
                            "unique_techniques": set(),
                            "avg_sophistication": []
                        }
                    
                    temporal_patterns[collected_date]["total_threats"] += 1
                    temporal_patterns[collected_date]["unique_techniques"].update(
                        [t.get("id") for t in analysis.get("techniques", [])]
                    )
                    if sophistication != "unknown":
                        soph_score = {"basic": 1, "intermediate": 2, "advanced": 3, "expert": 4}.get(sophistication, 2)
                        temporal_patterns[collected_date]["avg_sophistication"].append(soph_score)
                    
                except (json.JSONDecodeError, KeyError):
                    continue
            
            # Process temporal patterns
            processed_temporal = {}
            for date, data in temporal_patterns.items():
                avg_soph = sum(data["avg_sophistication"]) / len(data["avg_sophistication"]) if data["avg_sophistication"] else 2
                processed_temporal[date] = {
                    "total_threats": data["total_threats"],
                    "unique_techniques": len(data["unique_techniques"]),
                    "avg_sophistication_score": round(avg_soph, 2)
                }
            
            return {
                "analysis_period_days": days,
                "kill_chain_distribution": kill_chain_analysis,
                "sophistication_distribution": sophistication_levels,
                "complexity_distribution": attack_complexity,
                "source_technique_patterns": {
                    source: dict(sorted(techniques.items(), key=lambda x: x[1], reverse=True)[:5])
                    for source, techniques in source_technique_mapping.items()
                },
                "temporal_attack_patterns": processed_temporal,
                "summary": {
                    "total_threats_analyzed": len(results),
                    "most_common_kill_chain_phase": max(kill_chain_analysis.items(), key=lambda x: x[1])[0] if kill_chain_analysis else "unknown",
                    "dominant_sophistication": max(sophistication_levels.items(), key=lambda x: x[1])[0] if sophistication_levels else "unknown",
                    "average_complexity": max(attack_complexity.items(), key=lambda x: x[1])[0] if attack_complexity else "unknown"
                },
                "generated_at": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to get MITRE attack patterns: {e}")
            return {"error": str(e)}
        
    def _get_technique_name(self, technique_id: str) -> str:
        """Get technique name for common MITRE ATT&CK techniques"""
        technique_names = {
            "T1566": "Phishing",
            "T1059": "Command and Scripting Interpreter", 
            "T1105": "Ingress Tool Transfer",
            "T1083": "File and Directory Discovery",
            "T1082": "System Information Discovery",
            "T1047": "Windows Management Instrumentation",
            "T1055": "Process Injection",
            "T1027": "Obfuscated Files or Information",
            "T1486": "Data Encrypted for Impact",
            "T1567": "Exfiltration Over Web Service",
            "T1195": "Supply Chain Compromise",
            "T1078": "Valid Accounts",
            "T1190": "Exploit Public-Facing Application",
            "T1021": "Remote Services",
            "T1053": "Scheduled Task/Job",
            "T1003": "OS Credential Dumping",
            "T1071": "Application Layer Protocol",
            "T1095": "Non-Application Layer Protocol",
            "T1041": "Exfiltration Over C2 Channel",
            "T1005": "Data from Local System"
        }
        return technique_names.get(technique_id, f"Technique {technique_id}")
    
    def _validate_impact_assessment(self, assessment: Dict, threat_type: str, techniques: List[Dict]) -> Dict:
        """Validate and enhance impact assessment with rule-based logic"""
        
        # Risk score adjustments based on threat type
        risk_adjustments = {
            "ransomware": +25,  # Very high impact
            "supply_chain": +20,  # High logistics impact
            "ddos": +15,  # Service disruption
            "phishing": +10,  # Data breach risk
            "malware": +10,  # System compromise
            "apt": +30,  # Advanced persistent threat
            "insider": +20,  # Privileged access
            "vulnerability_exploit": +15
        }
        
        # Get current risk score
        business_impact = assessment.get("business_impact_assessment", {})
        current_risk = business_impact.get("overall_risk_score", 50)
        
        # Apply threat type adjustment
        if threat_type in risk_adjustments:
            adjusted_risk = min(100, current_risk + risk_adjustments[threat_type])
            business_impact["overall_risk_score"] = adjusted_risk
            business_impact["risk_adjustment_applied"] = f"+{risk_adjustments[threat_type]} for {threat_type}"
        
        # High-impact MITRE techniques
        high_impact_techniques = {
            "T1486": 25,  # Data Encrypted for Impact (Ransomware)
            "T1567": 20,  # Exfiltration Over Web Service
            "T1078": 15,  # Valid Accounts
            "T1566": 15,  # Phishing
            "T1195": 30,  # Supply Chain Compromise
            "T1190": 20,  # Exploit Public-Facing Application
            "T1021": 15,  # Remote Services
            "T1055": 18   # Process Injection
        }
        
        # Apply technique-based risk adjustments
        technique_boost = 0
        for technique in techniques:
            tech_id = technique.get("id", "")
            if tech_id in high_impact_techniques:
                confidence = technique.get("confidence", 0.5)
                technique_boost += high_impact_techniques[tech_id] * confidence
        
        if technique_boost > 0:
            final_risk = min(100, business_impact.get("overall_risk_score", 50) + int(technique_boost))
            business_impact["overall_risk_score"] = final_risk
            business_impact["technique_risk_boost"] = int(technique_boost)
        
        # Update risk level based on final score
        final_score = business_impact.get("overall_risk_score", 50)
        if final_score >= 85:
            business_impact["risk_level"] = "critical"
        elif final_score >= 70:
            business_impact["risk_level"] = "high"
        elif final_score >= 50:
            business_impact["risk_level"] = "medium"
        else:
            business_impact["risk_level"] = "low"
        
        assessment["business_impact_assessment"] = business_impact
        
        # Validate operational impact consistency
        operational = assessment.get("operational_impact", {})
        if final_score >= 80 and operational.get("severity") not in ["critical", "high"]:
            operational["severity"] = "critical" if final_score >= 90 else "high"
            operational["validation_adjustment"] = "Severity upgraded based on risk score"
        
        # Ensure financial impact aligns with risk level
        financial = business_impact.get("potential_financial_impact", {})
        risk_level = business_impact.get("risk_level", "medium")
        
        if risk_level == "critical" and financial.get("max_estimate_usd", 0) < 1000000:
            financial["max_estimate_usd"] = max(financial.get("max_estimate_usd", 0), 5000000)
            financial["validation_adjustment"] = "Financial impact increased for critical risk"
        elif risk_level == "high" and financial.get("max_estimate_usd", 0) < 500000:
            financial["max_estimate_usd"] = max(financial.get("max_estimate_usd", 0), 2000000)
            financial["validation_adjustment"] = "Financial impact increased for high risk"
        
        # Add validation metadata
        assessment["validation_applied"] = True
        assessment["validation_timestamp"] = datetime.now().isoformat()
        assessment["validation_rules"] = {
            "threat_type_adjustment": threat_type in risk_adjustments,
            "technique_risk_boost": technique_boost > 0,
            "consistency_checks": True
        }
        
        return assessment

    def _fallback_impact_assessment(self, threat_type: str, title: str) -> Dict:
        """Provide basic fallback impact assessment when LLM fails"""
        
        # Basic impact scoring based on threat type
        threat_impacts = {
            "ransomware": {
                "risk_score": 85,
                "risk_level": "critical",
                "financial_min": 500000,
                "financial_max": 10000000,
                "operational_severity": "critical",
                "downtime_hours": 72
            },
            "supply_chain": {
                "risk_score": 80,
                "risk_level": "high", 
                "financial_min": 1000000,
                "financial_max": 25000000,
                "operational_severity": "critical",
                "downtime_hours": 48
            },
            "phishing": {
                "risk_score": 65,
                "risk_level": "high",
                "financial_min": 100000,
                "financial_max": 5000000,
                "operational_severity": "medium",
                "downtime_hours": 12
            },
            "malware": {
                "risk_score": 70,
                "risk_level": "high",
                "financial_min": 250000,
                "financial_max": 3000000,
                "operational_severity": "high",
                "downtime_hours": 24
            },
            "ddos": {
                "risk_score": 60,
                "risk_level": "medium",
                "financial_min": 50000,
                "financial_max": 1000000,
                "operational_severity": "high",
                "downtime_hours": 8
            }
        }
        
        # Get impact data or use defaults
        impact_data = threat_impacts.get(threat_type, {
            "risk_score": 50,
            "risk_level": "medium",
            "financial_min": 100000,
            "financial_max": 1000000,
            "operational_severity": "medium",
            "downtime_hours": 12
        })
        
        # Check title for severity indicators
        title_lower = title.lower()
        severity_boost = 0
        
        if any(word in title_lower for word in ["critical", "severe", "major", "widespread"]):
            severity_boost = 15
        elif any(word in title_lower for word in ["advanced", "sophisticated", "targeted"]):
            severity_boost = 10
        elif any(word in title_lower for word in ["new", "zero-day", "unknown"]):
            severity_boost = 20
        
        final_risk_score = min(100, impact_data["risk_score"] + severity_boost)
        
        # Adjust risk level based on final score
        if final_risk_score >= 85:
            risk_level = "critical"
        elif final_risk_score >= 70:
            risk_level = "high"
        elif final_risk_score >= 50:
            risk_level = "medium"
        else:
            risk_level = "low"
        
        return {
            "business_impact_assessment": {
                "overall_risk_score": final_risk_score,
                "risk_level": risk_level,
                "potential_financial_impact": {
                    "min_estimate_usd": impact_data["financial_min"],
                    "max_estimate_usd": impact_data["financial_max"],
                    "impact_categories": ["operational_disruption", "data_breach_costs", "reputation_damage"]
                },
                "operational_impact": {
                    "severity": impact_data["operational_severity"],
                    "affected_operations": ["shipping", "tracking", "inventory"],
                    "downtime_estimate_hours": impact_data["downtime_hours"],
                    "recovery_time_estimate_hours": impact_data["downtime_hours"] * 2,
                    "customer_impact_level": "moderate"
                }
            },
            "affected_systems_analysis": {
                "primary_targets": [
                    {
                        "system_type": "logistics_management",
                        "criticality": "high",
                        "impact_description": f"Generic {threat_type} impact on logistics systems",
                        "affected_processes": ["shipping", "tracking"]
                    }
                ],
                "secondary_targets": ["email_systems", "network_infrastructure"],
                "data_at_risk": {
                    "customer_data": True,
                    "operational_data": True,
                    "financial_records": False,
                    "supplier_information": True
                }
            },
            "recommended_response": {
                "immediate_actions": [
                    "Activate incident response team",
                    "Assess system integrity",
                    "Notify stakeholders"
                ],
                "priority_level": "p1_high" if risk_level in ["critical", "high"] else "p2_medium",
                "estimated_response_cost_usd": impact_data["financial_min"] // 10
            },
            "confidence_assessment": {
                "impact_confidence": 0.4,
                "data_quality": "poor",
                "assessment_limitations": ["LLM analysis failed", "Using fallback assessment"],
                "recommendation_confidence": 0.3
            },
            "fallback_mode": True,
            "threat_type_analyzed": threat_type,
            "severity_boost_applied": severity_boost,
            "analysis_timestamp": datetime.now().isoformat()
        }

    def _fallback_impact_assessment(self, threat_type: str, title: str) -> Dict:
        """Provide basic fallback impact assessment when LLM fails"""
        
        # Basic impact scoring based on threat type
        threat_impacts = {
            "ransomware": {
                "risk_score": 85,
                "risk_level": "critical",
                "financial_min": 500000,
                "financial_max": 10000000,
                "operational_severity": "critical",
                "downtime_hours": 72
            },
            "supply_chain": {
                "risk_score": 80,
                "risk_level": "high", 
                "financial_min": 1000000,
                "financial_max": 25000000,
                "operational_severity": "critical",
                "downtime_hours": 48
            },
            "phishing": {
                "risk_score": 65,
                "risk_level": "high",
                "financial_min": 100000,
                "financial_max": 5000000,
                "operational_severity": "medium",
                "downtime_hours": 12
            },
            "malware": {
                "risk_score": 70,
                "risk_level": "high",
                "financial_min": 250000,
                "financial_max": 3000000,
                "operational_severity": "high",
                "downtime_hours": 24
            },
            "ddos": {
                "risk_score": 60,
                "risk_level": "medium",
                "financial_min": 50000,
                "financial_max": 1000000,
                "operational_severity": "high",
                "downtime_hours": 8
            }
        }
        
        # Get impact data or use defaults
        impact_data = threat_impacts.get(threat_type, {
            "risk_score": 50,
            "risk_level": "medium",
            "financial_min": 100000,
            "financial_max": 1000000,
            "operational_severity": "medium",
            "downtime_hours": 12
        })
        
        # Check title for severity indicators
        title_lower = title.lower()
        severity_boost = 0
        
        if any(word in title_lower for word in ["critical", "severe", "major", "widespread"]):
            severity_boost = 15
        elif any(word in title_lower for word in ["advanced", "sophisticated", "targeted"]):
            severity_boost = 10
        elif any(word in title_lower for word in ["new", "zero-day", "unknown"]):
            severity_boost = 20
        
        final_risk_score = min(100, impact_data["risk_score"] + severity_boost)
        
        # Adjust risk level based on final score
        if final_risk_score >= 85:
            risk_level = "critical"
        elif final_risk_score >= 70:
            risk_level = "high"
        elif final_risk_score >= 50:
            risk_level = "medium"
        else:
            risk_level = "low"
        
        return {
            "business_impact_assessment": {
                "overall_risk_score": final_risk_score,
                "risk_level": risk_level,
                "potential_financial_impact": {
                    "min_estimate_usd": impact_data["financial_min"],
                    "max_estimate_usd": impact_data["financial_max"],
                    "impact_categories": ["operational_disruption", "data_breach_costs", "reputation_damage"]
                },
                "operational_impact": {
                    "severity": impact_data["operational_severity"],
                    "affected_operations": ["shipping", "tracking", "inventory"],
                    "downtime_estimate_hours": impact_data["downtime_hours"],
                    "recovery_time_estimate_hours": impact_data["downtime_hours"] * 2,
                    "customer_impact_level": "moderate"
                }
            },
            "affected_systems_analysis": {
                "primary_targets": [
                    {
                        "system_type": "logistics_management",
                        "criticality": "high",
                        "impact_description": f"Generic {threat_type} impact on logistics systems",
                        "affected_processes": ["shipping", "tracking"]
                    }
                ],
                "secondary_targets": ["email_systems", "network_infrastructure"],
                "data_at_risk": {
                    "customer_data": True,
                    "operational_data": True,
                    "financial_records": False,
                    "supplier_information": True
                }
            },
            "recommended_response": {
                "immediate_actions": [
                    "Activate incident response team",
                    "Assess system integrity",
                    "Notify stakeholders"
                ],
                "priority_level": "p1_high" if risk_level in ["critical", "high"] else "p2_medium",
                "estimated_response_cost_usd": impact_data["financial_min"] // 10
            },
            "confidence_assessment": {
                "impact_confidence": 0.4,
                "data_quality": "poor",
                "assessment_limitations": ["LLM analysis failed", "Using fallback assessment"],
                "recommendation_confidence": 0.3
            },
            "fallback_mode": True,
            "threat_type_analyzed": threat_type,
            "severity_boost_applied": severity_boost,
            "analysis_timestamp": datetime.now().isoformat()
        }
    
    def get_impact_risk_summary(self, days: int = 30) -> Dict:
        """Get risk summary across all analyzed threats"""
        try:
            cursor = self.conn.cursor()
            time_threshold = (datetime.now() - timedelta(days=days)).isoformat()
            
            cursor.execute("""
                SELECT a.analysis_result, r.collected_at, r.source
                FROM agent_analysis a
                JOIN raw_threats r ON a.raw_threat_id = r.id
                WHERE a.agent_type = 'impact_assessment'
                AND r.collected_at > ?
                ORDER BY r.collected_at DESC
            """, (time_threshold,))
            
            results = cursor.fetchall()
            
            # Risk analysis containers
            risk_levels = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            financial_impacts = []
            operational_impacts = []
            affected_systems = {}
            compliance_risks = {}
            
            total_threats = len(results)
            
            for row in results:
                try:
                    analysis = json.loads(row[0])
                    
                    # Risk level distribution
                    business_impact = analysis.get("business_impact_assessment", {})
                    risk_level = business_impact.get("risk_level", "unknown")
                    if risk_level in risk_levels:
                        risk_levels[risk_level] += 1
                    
                    # Financial impact tracking
                    financial = business_impact.get("potential_financial_impact", {})
                    max_impact = financial.get("max_estimate_usd", 0)
                    if max_impact > 0:
                        financial_impacts.append(max_impact)
                    
                    # Operational impact severity
                    operational = business_impact.get("operational_impact", {})
                    severity = operational.get("severity", "unknown")
                    operational_impacts.append(severity)
                    
                    # Affected systems analysis
                    systems_analysis = analysis.get("affected_systems_analysis", {})
                    primary_targets = systems_analysis.get("primary_targets", [])
                    for target in primary_targets:
                        system_type = target.get("system_type", "unknown")
                        affected_systems[system_type] = affected_systems.get(system_type, 0) + 1
                    
                    # Compliance risk tracking
                    compliance = analysis.get("compliance_and_regulatory_impact", {})
                    affected_regs = compliance.get("affected_regulations", [])
                    for reg in affected_regs:
                        compliance_risks[reg] = compliance_risks.get(reg, 0) + 1
                    
                except (json.JSONDecodeError, KeyError):
                    continue
            
            # Calculate statistics
            avg_financial_impact = sum(financial_impacts) / len(financial_impacts) if financial_impacts else 0
            max_financial_impact = max(financial_impacts) if financial_impacts else 0
            
            # Risk distribution percentages
            risk_percentages = {
                level: round((count / max(total_threats, 1)) * 100, 1)
                for level, count in risk_levels.items()
            }
            
            # Most affected systems
            top_affected_systems = dict(sorted(
                affected_systems.items(), 
                key=lambda x: x[1], 
                reverse=True
            )[:10])
            
            # Compliance risk ranking
            top_compliance_risks = dict(sorted(
                compliance_risks.items(),
                key=lambda x: x[1],
                reverse=True
            )[:5])
            
            # Operational impact severity distribution (without pandas)
            severity_distribution = {}
            for severity in operational_impacts:
                severity_distribution[severity] = severity_distribution.get(severity, 0) + 1
            
            return {
                "analysis_period_days": days,
                "total_threats_analyzed": total_threats,
                "risk_distribution": {
                    "counts": risk_levels,
                    "percentages": risk_percentages,
                    "dominant_risk_level": max(risk_levels.items(), key=lambda x: x[1])[0] if risk_levels else "unknown"
                },
                "financial_impact_analysis": {
                    "average_max_impact_usd": int(avg_financial_impact),
                    "highest_impact_usd": int(max_financial_impact),
                    "total_potential_exposure_usd": int(sum(financial_impacts)),
                    "threats_with_financial_data": len(financial_impacts)
                },
                "operational_impact_summary": {
                    "severity_distribution": severity_distribution,
                    "high_severity_percentage": round(
                        (operational_impacts.count("critical") + operational_impacts.count("high")) / 
                        max(len(operational_impacts), 1) * 100, 1
                    )
                },
                "systems_at_risk": {
                    "most_targeted_systems": top_affected_systems,
                    "unique_system_types": len(affected_systems),
                    "total_system_impact_events": sum(affected_systems.values())
                },
                "compliance_risk_overview": {
                    "regulations_at_risk": top_compliance_risks,
                    "unique_regulations": len(compliance_risks),
                    "total_compliance_events": sum(compliance_risks.values())
                },
                "risk_trends": {
                    "critical_high_percentage": risk_percentages.get("critical", 0) + risk_percentages.get("high", 0),
                    "overall_risk_posture": (
                        "🔴 High Risk Environment" if risk_percentages.get("critical", 0) + risk_percentages.get("high", 0) > 50 else
                        "🟡 Moderate Risk Environment" if risk_percentages.get("medium", 0) > 40 else
                        "🟢 Lower Risk Environment"
                    )
                },
                "generated_at": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to get impact risk summary: {e}")
            return {"error": str(e)}

    def _validate_geospatial_analysis(self, analysis: Dict, threat_type: str, content: str) -> Dict:
        """Validate and enhance geospatial analysis with rule-based intelligence"""
        
        # Extract common country and region indicators from content
        content_lower = content.lower()
        
        # Common country indicators in threat intelligence
        country_indicators = {
            "china": ["CN", "China", "Beijing", "Shanghai"],
            "russia": ["RU", "Russia", "Moscow", "St. Petersburg"],
            "north korea": ["KP", "North Korea", "DPRK", "Pyongyang"],
            "iran": ["IR", "Iran", "Tehran"],
            "united states": ["US", "United States", "America"],
            "ukraine": ["UA", "Ukraine", "Kiev", "Kyiv"],
            "germany": ["DE", "Germany", "Berlin"],
            "netherlands": ["NL", "Netherlands", "Amsterdam"],
            "singapore": ["SG", "Singapore"],
            "japan": ["JP", "Japan", "Tokyo"]
        }
        
        # Detect country mentions in content
        detected_countries = []
        for country, indicators in country_indicators.items():
            for indicator in indicators:
                if indicator.lower() in content_lower:
                    detected_countries.append({
                        "country": country.title(),
                        "country_code": indicators[0],
                        "confidence": 0.6,
                        "evidence": [f"mentioned_in_content: {indicator}"],
                        "threat_actor_presence": "unknown"
                    })
                    break
        
        # Enhance origin analysis with detected countries
        origin_analysis = analysis.get("geographic_origin_analysis", {})
        existing_origins = origin_analysis.get("likely_origin_countries", [])
        
        # Add detected countries if not already present
        existing_codes = [c.get("country_code") for c in existing_origins]
        for detected in detected_countries:
            if detected["country_code"] not in existing_codes:
                existing_origins.append(detected)
        
        # Threat-type specific geographic patterns
        threat_geographic_patterns = {
            "ransomware": {
                "common_origins": ["RU", "CN", "KP", "IR"],
                "preferred_targets": ["US", "EU", "AU", "CA"],
                "infrastructure_countries": ["NL", "DE", "SG", "US"]
            },
            "supply_chain": {
                "common_origins": ["CN", "RU", "KP"],
                "preferred_targets": ["US", "EU", "JP", "KR"],
                "infrastructure_countries": ["US", "DE", "SG", "NL"]
            },
            "phishing": {
                "common_origins": ["RU", "CN", "NG", "RO"],
                "preferred_targets": ["US", "GB", "DE", "AU"],
                "infrastructure_countries": ["US", "NL", "DE", "CA"]
            },
            "apt": {
                "common_origins": ["CN", "RU", "KP", "IR"],
                "preferred_targets": ["US", "EU", "JP", "AU"],
                "infrastructure_countries": ["US", "DE", "NL", "SG"]
            }
        }
        
        # Apply threat-type specific enhancements
        if threat_type in threat_geographic_patterns:
            pattern = threat_geographic_patterns[threat_type]
            
            # Enhance target geography
            target_analysis = analysis.get("target_geography_analysis", {})
            if not target_analysis.get("primary_target_regions"):
                target_analysis["primary_target_regions"] = [
                    {
                        "region": "North America",
                        "countries": ["US", "CA", "MX"],
                        "targeting_confidence": 0.7,
                        "targeting_reasons": ["economic_value", "infrastructure_density"]
                    },
                    {
                        "region": "Europe",
                        "countries": ["DE", "GB", "FR", "NL"],
                        "targeting_confidence": 0.6,
                        "targeting_reasons": ["economic_value", "regulatory_environment"]
                    }
                ]
            
            # Enhance infrastructure analysis
            infrastructure = analysis.get("ip_and_infrastructure_analysis", {})
            if not infrastructure.get("c2_infrastructure"):
                infrastructure["c2_infrastructure"] = {
                    "identified_servers": 3,
                    "geographic_distribution": pattern["infrastructure_countries"][:3],
                    "hosting_patterns": ["cloud_services", "bulletproof_hosting"],
                    "infrastructure_sophistication": "intermediate"
                }
        
        # Add logistics-specific geographic intelligence
        logistics_analysis = analysis.get("logistics_geographic_impact", {})
        if not logistics_analysis.get("critical_logistics_regions"):
            logistics_analysis["critical_logistics_regions"] = [
                {
                    "region": "Asia-Pacific",
                    "impact_level": "high",
                    "key_ports": ["Shanghai", "Singapore", "Hong Kong"],
                    "shipping_volume_at_risk": "25%",
                    "alternative_routes": ["Trans-Pacific Northern", "Indian Ocean"]
                },
                {
                    "region": "Europe",
                    "impact_level": "medium",
                    "key_ports": ["Rotterdam", "Hamburg", "Antwerp"],
                    "shipping_volume_at_risk": "15%",
                    "alternative_routes": ["Baltic Sea", "Mediterranean"]
                }
            ]
        
        # Add realistic coordinates if missing
        coordinates = analysis.get("coordinates_and_mapping", {})
        if not coordinates.get("threat_origin_coordinates"):
            # Default to common threat origin (Eastern Europe)
            coordinates["threat_origin_coordinates"] = {
                "latitude": 50.4501,  # Kiev area
                "longitude": 30.5234,
                "accuracy_radius_km": 500,
                "confidence": 0.4
            }
        
        # Add regional threat centers
        if not coordinates.get("target_region_centers"):
            coordinates["target_region_centers"] = [
                {
                    "region": "North America",
                    "latitude": 39.8283,
                    "longitude": -98.5795,
                    "threat_density": "high"
                },
                {
                    "region": "Europe",
                    "latitude": 54.5260,
                    "longitude": 15.2551,
                    "threat_density": "medium"
                },
                {
                    "region": "Asia-Pacific",
                    "latitude": 35.6762,
                    "longitude": 139.6503,
                    "threat_density": "high"
                }
            ]
        
        # Update analysis with enhancements
        analysis["geographic_origin_analysis"] = origin_analysis
        analysis["target_geography_analysis"] = target_analysis
        analysis["ip_and_infrastructure_analysis"] = infrastructure
        analysis["logistics_geographic_impact"] = logistics_analysis
        analysis["coordinates_and_mapping"] = coordinates
        
        # Add validation metadata
        analysis["validation_applied"] = True
        analysis["validation_timestamp"] = datetime.now().isoformat()
        analysis["validation_enhancements"] = {
            "countries_detected_from_content": len(detected_countries),
            "threat_pattern_applied": threat_type in threat_geographic_patterns,
            "logistics_intelligence_added": True,
            "coordinates_validated": True
        }
        
        return analysis

    def _fallback_geospatial_analysis(self, threat_type: str, title: str) -> Dict:
        """Provide basic fallback geospatial analysis when LLM fails"""
        
        # Basic geographic patterns by threat type
        fallback_patterns = {
            "ransomware": {
                "origins": [{"country": "Russia", "country_code": "RU", "confidence": 0.6}],
                "targets": ["North America", "Europe"],
                "infrastructure": ["US", "NL", "DE"]
            },
            "supply_chain": {
                "origins": [{"country": "China", "country_code": "CN", "confidence": 0.7}],
                "targets": ["North America", "Europe", "Asia-Pacific"],
                "infrastructure": ["US", "SG", "DE"]
            },
            "phishing": {
                "origins": [{"country": "Nigeria", "country_code": "NG", "confidence": 0.5}],
                "targets": ["Global"],
                "infrastructure": ["US", "CA", "NL"]
            },
            "apt": {
                "origins": [{"country": "China", "country_code": "CN", "confidence": 0.7}],
                "targets": ["North America", "Europe"],
                "infrastructure": ["US", "DE", "SG"]
            }
        }
        
        # Get pattern or use default
        pattern = fallback_patterns.get(threat_type, {
            "origins": [{"country": "Unknown", "country_code": "XX", "confidence": 0.3}],
            "targets": ["Global"],
            "infrastructure": ["US", "DE"]
        })
        
        # Check title for geographic indicators
        title_lower = title.lower()
        confidence_boost = 0.1 if any(geo in title_lower for geo in 
            ["global", "international", "worldwide", "multi-national"]) else 0
        
        return {
            "geographic_origin_analysis": {
                "likely_origin_countries": pattern["origins"],
                "origin_assessment_confidence": 0.4 + confidence_boost,
                "attribution_indicators": ["threat_type_pattern"],
                "geographic_scope": "global" if "global" in title_lower else "regional"
            },
            "target_geography_analysis": {
                "primary_target_regions": [
                    {
                        "region": region,
                        "countries": ["US", "DE", "JP"] if region == "Global" else ["US", "CA"],
                        "targeting_confidence": 0.5,
                        "targeting_reasons": ["economic_value"]
                    } for region in pattern["targets"][:2]
                ],
                "industry_geographic_focus": {
                    "logistics_hubs": ["Singapore", "Netherlands", "Germany"],
                    "port_cities": ["Shanghai", "Los Angeles", "Rotterdam"],
                    "shipping_lanes": ["Trans-Pacific", "Trans-Atlantic"]
                }
            },
            "ip_and_infrastructure_analysis": {
                "c2_infrastructure": {
                    "identified_servers": 2,
                    "geographic_distribution": pattern["infrastructure"],
                    "hosting_patterns": ["cloud_services"],
                    "infrastructure_sophistication": "basic"
                }
            },
            "logistics_geographic_impact": {
                "critical_logistics_regions": [
                    {
                        "region": "Asia-Pacific",
                        "impact_level": "medium",
                        "key_ports": ["Singapore", "Shanghai"],
                        "shipping_volume_at_risk": "unknown",
                        "alternative_routes": ["available"]
                    }
                ]
            },
            "coordinates_and_mapping": {
                "threat_origin_coordinates": {
                    "latitude": 50.0,
                    "longitude": 10.0,
                    "accuracy_radius_km": 1000,
                    "confidence": 0.3
                },
                "target_region_centers": [
                    {
                        "region": "Global",
                        "latitude": 40.0,
                        "longitude": -100.0,
                        "threat_density": "medium"
                    }
                ]
            },
            "confidence_and_limitations": {
                "overall_geographic_confidence": 0.3,
                "data_quality_assessment": "poor",
                "analysis_limitations": ["LLM analysis failed", "Using fallback patterns"],
                "recommendation_reliability": "low"
            },
            "fallback_mode": True,
            "threat_type_analyzed": threat_type,
            "analysis_timestamp": datetime.now().isoformat()
        }

    def get_geospatial_analysis_for_threat(self, threat_id: int) -> Optional[Dict]:
        """Retrieve geospatial analysis for a specific threat"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT analysis_result, created_at 
                FROM agent_analysis 
                WHERE raw_threat_id = ? AND agent_type = 'geospatial_intelligence'
                ORDER BY created_at DESC 
                LIMIT 1
            """, (threat_id,))
            
            result = cursor.fetchone()
            if result:
                analysis = json.loads(result[0])
                analysis['retrieved_at'] = result[1]
                return analysis
            return None
        except Exception as e:
            logger.error(f"Failed to retrieve geospatial analysis: {e}")
            return None

    def get_global_threat_map_data(self, days: int = 30) -> Dict:
        """Get comprehensive threat mapping data for global visualization"""
        try:
            cursor = self.conn.cursor()
            time_threshold = (datetime.now() - timedelta(days=days)).isoformat()
            
            cursor.execute("""
                SELECT a.analysis_result, r.title, r.collected_at, r.source, r.id
                FROM agent_analysis a
                JOIN raw_threats r ON a.raw_threat_id = r.id
                WHERE a.agent_type = 'geospatial_intelligence'
                AND r.collected_at > ?
                ORDER BY r.collected_at DESC
            """, (time_threshold,))
            
            results = cursor.fetchall()
            
            # Containers for map data
            threat_locations = []
            origin_countries = {}
            target_regions = {}
            infrastructure_locations = []
            threat_connections = []
            
            for row in results:
                try:
                    analysis = json.loads(row[0])
                    threat_title = row[1]
                    collected_at = row[2]
                    source = row[3]
                    threat_id = row[4]
                    
                    # Extract origin coordinates
                    coords = analysis.get("coordinates_and_mapping", {})
                    origin_coords = coords.get("threat_origin_coordinates", {})
                    
                    if origin_coords.get("latitude") and origin_coords.get("longitude"):
                        threat_locations.append({
                            "id": threat_id,
                            "title": threat_title[:100],
                            "latitude": float(origin_coords["latitude"]),
                            "longitude": float(origin_coords["longitude"]),
                            "confidence": origin_coords.get("confidence", 0.5),
                            "accuracy_km": origin_coords.get("accuracy_radius_km", 100),
                            "source": source,
                            "collected_at": collected_at,
                            "type": "threat_origin"
                        })
                    
                    # Count origin countries
                    origin_analysis = analysis.get("geographic_origin_analysis", {})
                    for country_data in origin_analysis.get("likely_origin_countries", []):
                        country = country_data.get("country", "Unknown")
                        country_code = country_data.get("country_code", "XX")
                        confidence = country_data.get("confidence", 0.5)
                        
                        if country_code not in origin_countries:
                            origin_countries[country_code] = {
                                "country": country,
                                "threat_count": 0,
                                "total_confidence": 0,
                                "threat_types": set(),
                                "recent_activity": []
                            }
                        
                        origin_countries[country_code]["threat_count"] += 1
                        origin_countries[country_code]["total_confidence"] += confidence
                        origin_countries[country_code]["recent_activity"].append(collected_at)
                    
                    # Count target regions
                    target_analysis = analysis.get("target_geography_analysis", {})
                    for region_data in target_analysis.get("primary_target_regions", []):
                        region = region_data.get("region", "Unknown")
                        confidence = region_data.get("targeting_confidence", 0.5)
                        
                        if region not in target_regions:
                            target_regions[region] = {
                                "threat_count": 0,
                                "total_confidence": 0,
                                "threat_origins": set(),
                                "recent_activity": []
                            }
                        
                        target_regions[region]["threat_count"] += 1
                        target_regions[region]["total_confidence"] += confidence
                        target_regions[region]["recent_activity"].append(collected_at)
                    
                    # Extract infrastructure locations
                    infrastructure = analysis.get("ip_and_infrastructure_analysis", {})
                    for ip_data in infrastructure.get("malicious_ip_indicators", []):
                        if ip_data.get("latitude") and ip_data.get("longitude"):
                            infrastructure_locations.append({
                                "ip": ip_data.get("ip_address", "unknown"),
                                "latitude": float(ip_data["latitude"]),
                                "longitude": float(ip_data["longitude"]),
                                "country": ip_data.get("country", "Unknown"),
                                "threat_type": ip_data.get("threat_type", "unknown"),
                                "confidence": ip_data.get("confidence", 0.5),
                                "related_threat_id": threat_id,
                                "type": "infrastructure"
                            })
                    
                    # Create threat connections (origin to target)
                    if origin_coords.get("latitude") and target_analysis.get("primary_target_regions"):
                        for region_data in target_analysis.get("primary_target_regions", [])[:2]:
                            # Use regional center coordinates
                            region_centers = coords.get("target_region_centers", [])
                            for center in region_centers:
                                if center.get("region") == region_data.get("region"):
                                    threat_connections.append({
                                        "origin_lat": float(origin_coords["latitude"]),
                                        "origin_lng": float(origin_coords["longitude"]),
                                        "target_lat": float(center.get("latitude", 0)),
                                        "target_lng": float(center.get("longitude", 0)),
                                        "threat_id": threat_id,
                                        "confidence": min(origin_coords.get("confidence", 0.5), 
                                                    region_data.get("targeting_confidence", 0.5)),
                                        "threat_title": threat_title[:50]
                                    })
                                    break
                    
                except (json.JSONDecodeError, ValueError, KeyError):
                    continue
            
            # Calculate country risk scores
            country_risk_data = {}
            for country_code, data in origin_countries.items():
                avg_confidence = data["total_confidence"] / max(data["threat_count"], 1)
                
                # Risk score based on threat count and confidence
                risk_score = min(100, data["threat_count"] * 15 + avg_confidence * 30)
                
                # Recent activity factor
                recent_threats = [
                    dt for dt in data["recent_activity"] 
                    if datetime.fromisoformat(dt) > datetime.now() - timedelta(days=7)
                ]
                recency_factor = len(recent_threats) * 10
                
                final_risk_score = min(100, risk_score + recency_factor)
                
                country_risk_data[country_code] = {
                    "country": data["country"],
                    "threat_count": data["threat_count"],
                    "avg_confidence": round(avg_confidence, 2),
                    "risk_score": round(final_risk_score, 1),
                    "recent_activity_7d": len(recent_threats),
                    "risk_level": (
                        "critical" if final_risk_score >= 80 else
                        "high" if final_risk_score >= 60 else
                        "medium" if final_risk_score >= 40 else
                        "low"
                    ),
                    "map_color": (
                        "#8b0000" if final_risk_score >= 80 else  # Dark red
                        "#ff4444" if final_risk_score >= 60 else  # Red
                        "#ff8800" if final_risk_score >= 40 else  # Orange
                        "#ffaa00"  # Yellow
                    )
                }
            
            # Calculate regional targeting intensity
            regional_data = {}
            for region, data in target_regions.items():
                avg_confidence = data["total_confidence"] / max(data["threat_count"], 1)
                
                regional_data[region] = {
                    "threat_count": data["threat_count"],
                    "avg_confidence": round(avg_confidence, 2),
                    "targeting_intensity": round(data["threat_count"] * avg_confidence, 1),
                    "recent_activity_count": len([
                        dt for dt in data["recent_activity"] 
                        if datetime.fromisoformat(dt) > datetime.now() - timedelta(days=7)
                    ])
                }
            
            # Generate threat flow analysis
            threat_flows = {}
            for connection in threat_connections:
                origin_key = f"{connection['origin_lat']:.1f},{connection['origin_lng']:.1f}"
                target_key = f"{connection['target_lat']:.1f},{connection['target_lng']:.1f}"
                flow_key = f"{origin_key}->{target_key}"
                
                if flow_key not in threat_flows:
                    threat_flows[flow_key] = {
                        "origin_lat": connection['origin_lat'],
                        "origin_lng": connection['origin_lng'],
                        "target_lat": connection['target_lat'],
                        "target_lng": connection['target_lng'],
                        "flow_count": 0,
                        "avg_confidence": 0,
                        "threat_ids": []
                    }
                
                threat_flows[flow_key]["flow_count"] += 1
                threat_flows[flow_key]["avg_confidence"] += connection["confidence"]
                threat_flows[flow_key]["threat_ids"].append(connection["threat_id"])
            
            # Finalize flow calculations
            for flow_data in threat_flows.values():
                flow_data["avg_confidence"] = flow_data["avg_confidence"] / flow_data["flow_count"]
                flow_data["flow_intensity"] = flow_data["flow_count"] * flow_data["avg_confidence"]
            
            return {
                "analysis_period_days": days,
                "data_summary": {
                    "total_threats_mapped": len(threat_locations),
                    "origin_countries_identified": len(origin_countries),
                    "target_regions_identified": len(target_regions),
                    "infrastructure_locations": len(infrastructure_locations),
                    "threat_connections": len(threat_connections)
                },
                "threat_locations": threat_locations,
                "country_risk_data": country_risk_data,
                "regional_targeting_data": regional_data,
                "infrastructure_map": infrastructure_locations,
                "threat_flow_analysis": list(threat_flows.values()),
                "map_visualization_config": {
                    "default_zoom": 2,
                    "center_lat": 30.0,
                    "center_lng": 0.0,
                    "heat_map_enabled": len(threat_locations) > 10,
                    "connection_lines_enabled": len(threat_connections) > 5,
                    "clustering_enabled": len(threat_locations) > 20
                },
                "threat_hotspots": self._identify_threat_hotspots(threat_locations),
                "geographic_trends": {
                    "most_active_origin": max(origin_countries.items(), 
                        key=lambda x: x[1]["threat_count"])[0] if origin_countries else "Unknown",
                    "most_targeted_region": max(regional_data.items(), 
                        key=lambda x: x[1]["threat_count"])[0] if regional_data else "Unknown",
                    "threat_distribution": "global" if len(origin_countries) > 5 else "regional"
                },
                "generated_at": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to get global threat map data: {e}")
            return {"error": str(e)}

    def _identify_threat_hotspots(self, locations: List[Dict]) -> List[Dict]:
        """Identify geographic threat hotspots using simple clustering"""
        if len(locations) < 3:
            return []
        
        hotspots = []
        cluster_radius = 5.0  # degrees (roughly 550km)
        
        # Simple clustering by proximity
        used_indices = set()
        
        for i, location in enumerate(locations):
            if i in used_indices:
                continue
                
            cluster_locations = [location]
            cluster_indices = {i}
            
            lat1, lng1 = location["latitude"], location["longitude"]
            
            # Find nearby locations
            for j, other_location in enumerate(locations):
                if j in used_indices or j == i:
                    continue
                    
                lat2, lng2 = other_location["latitude"], other_location["longitude"]
                
                # Simple distance calculation
                distance = ((lat2 - lat1)**2 + (lng2 - lng1)**2)**0.5
                
                if distance <= cluster_radius:
                    cluster_locations.append(other_location)
                    cluster_indices.add(j)
            
            # If cluster has multiple threats, it's a hotspot
            if len(cluster_locations) >= 2:
                used_indices.update(cluster_indices)
                
                # Calculate cluster center
                avg_lat = sum(loc["latitude"] for loc in cluster_locations) / len(cluster_locations)
                avg_lng = sum(loc["longitude"] for loc in cluster_locations) / len(cluster_locations)
                avg_confidence = sum(loc["confidence"] for loc in cluster_locations) / len(cluster_locations)
                
                hotspots.append({
                    "center_lat": avg_lat,
                    "center_lng": avg_lng,
                    "threat_count": len(cluster_locations),
                    "avg_confidence": round(avg_confidence, 2),
                    "radius_km": cluster_radius * 111,  # Convert to approximate km
                    "threat_ids": [loc["id"] for loc in cluster_locations],
                    "hotspot_intensity": len(cluster_locations) * avg_confidence,
                    "risk_level": (
                        "critical" if len(cluster_locations) >= 5 else
                        "high" if len(cluster_locations) >= 3 else
                        "medium"
                    )
                })
        
        # Sort hotspots by intensity
        hotspots.sort(key=lambda x: x["hotspot_intensity"], reverse=True)
        
        return hotspots[:10]  # Return top 10 hotspots

    def get_geospatial_analysis_for_threat(self, threat_id: int) -> Optional[Dict]:
        """Retrieve geospatial analysis for a specific threat"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT analysis_result, created_at 
                FROM agent_analysis 
                WHERE raw_threat_id = ? AND agent_type = 'geospatial_intelligence'
                ORDER BY created_at DESC 
                LIMIT 1
            """, (threat_id,))
            
            result = cursor.fetchone()
            if result:
                analysis = json.loads(result[0])
                analysis['retrieved_at'] = result[1]
                return analysis
            return None
        except Exception as e:
            logger.error(f"Failed to retrieve geospatial analysis: {e}")
            return None

    def get_global_threat_map_data(self, days: int = 30) -> Dict:
        """Get comprehensive threat mapping data for global visualization"""
        try:
            cursor = self.conn.cursor()
            time_threshold = (datetime.now() - timedelta(days=days)).isoformat()
            
            cursor.execute("""
                SELECT a.analysis_result, r.title, r.collected_at, r.source, r.id
                FROM agent_analysis a
                JOIN raw_threats r ON a.raw_threat_id = r.id
                WHERE a.agent_type = 'geospatial_intelligence'
                AND r.collected_at > ?
                ORDER BY r.collected_at DESC
            """, (time_threshold,))
            
            results = cursor.fetchall()
            
            # Containers for map data
            threat_locations = []
            origin_countries = {}
            target_regions = {}
            infrastructure_locations = []
            threat_connections = []
            
            for row in results:
                try:
                    analysis = json.loads(row[0])
                    threat_title = row[1]
                    collected_at = row[2]
                    source = row[3]
                    threat_id = row[4]
                    
                    # Extract origin coordinates
                    coords = analysis.get("coordinates_and_mapping", {})
                    origin_coords = coords.get("threat_origin_coordinates", {})
                    
                    if origin_coords.get("latitude") and origin_coords.get("longitude"):
                        threat_locations.append({
                            "id": threat_id,
                            "title": threat_title[:100],
                            "latitude": float(origin_coords["latitude"]),
                            "longitude": float(origin_coords["longitude"]),
                            "confidence": origin_coords.get("confidence", 0.5),
                            "accuracy_km": origin_coords.get("accuracy_radius_km", 100),
                            "source": source,
                            "collected_at": collected_at,
                            "type": "threat_origin"
                        })
                    
                    # Count origin countries
                    origin_analysis = analysis.get("geographic_origin_analysis", {})
                    for country_data in origin_analysis.get("likely_origin_countries", []):
                        country = country_data.get("country", "Unknown")
                        country_code = country_data.get("country_code", "XX")
                        confidence = country_data.get("confidence", 0.5)
                        
                        if country_code not in origin_countries:
                            origin_countries[country_code] = {
                                "country": country,
                                "threat_count": 0,
                                "total_confidence": 0,
                                "threat_types": set(),
                                "recent_activity": []
                            }
                        
                        origin_countries[country_code]["threat_count"] += 1
                        origin_countries[country_code]["total_confidence"] += confidence
                        origin_countries[country_code]["recent_activity"].append(collected_at)
                    
                    # Count target regions
                    target_analysis = analysis.get("target_geography_analysis", {})
                    for region_data in target_analysis.get("primary_target_regions", []):
                        region = region_data.get("region", "Unknown")
                        confidence = region_data.get("targeting_confidence", 0.5)
                        
                        if region not in target_regions:
                            target_regions[region] = {
                                "threat_count": 0,
                                "total_confidence": 0,
                                "threat_origins": set(),
                                "recent_activity": []
                            }
                        
                        target_regions[region]["threat_count"] += 1
                        target_regions[region]["total_confidence"] += confidence
                        target_regions[region]["recent_activity"].append(collected_at)
                    
                    # Extract infrastructure locations
                    infrastructure = analysis.get("ip_and_infrastructure_analysis", {})
                    for ip_data in infrastructure.get("malicious_ip_indicators", []):
                        if ip_data.get("latitude") and ip_data.get("longitude"):
                            infrastructure_locations.append({
                                "ip": ip_data.get("ip_address", "unknown"),
                                "latitude": float(ip_data["latitude"]),
                                "longitude": float(ip_data["longitude"]),
                                "country": ip_data.get("country", "Unknown"),
                                "threat_type": ip_data.get("threat_type", "unknown"),
                                "confidence": ip_data.get("confidence", 0.5),
                                "related_threat_id": threat_id,
                                "type": "infrastructure"
                            })
                    
                    # Create threat connections (origin to target)
                    if origin_coords.get("latitude") and target_analysis.get("primary_target_regions"):
                        for region_data in target_analysis.get("primary_target_regions", [])[:2]:
                            # Use regional center coordinates
                            region_centers = coords.get("target_region_centers", [])
                            for center in region_centers:
                                if center.get("region") == region_data.get("region"):
                                    threat_connections.append({
                                        "origin_lat": float(origin_coords["latitude"]),
                                        "origin_lng": float(origin_coords["longitude"]),
                                        "target_lat": float(center.get("latitude", 0)),
                                        "target_lng": float(center.get("longitude", 0)),
                                        "threat_id": threat_id,
                                        "confidence": min(origin_coords.get("confidence", 0.5), 
                                                    region_data.get("targeting_confidence", 0.5)),
                                        "threat_title": threat_title[:50]
                                    })
                                    break
                    
                except (json.JSONDecodeError, ValueError, KeyError):
                    continue
            
            # Calculate country risk scores
            country_risk_data = {}
            for country_code, data in origin_countries.items():
                avg_confidence = data["total_confidence"] / max(data["threat_count"], 1)
                
                # Risk score based on threat count and confidence
                risk_score = min(100, data["threat_count"] * 15 + avg_confidence * 30)
                
                # Recent activity factor
                recent_threats = [
                    dt for dt in data["recent_activity"] 
                    if datetime.fromisoformat(dt) > datetime.now() - timedelta(days=7)
                ]
                recency_factor = len(recent_threats) * 10
                
                final_risk_score = min(100, risk_score + recency_factor)
                
                country_risk_data[country_code] = {
                    "country": data["country"],
                    "threat_count": data["threat_count"],
                    "avg_confidence": round(avg_confidence, 2),
                    "risk_score": round(final_risk_score, 1),
                    "recent_activity_7d": len(recent_threats),
                    "risk_level": (
                        "critical" if final_risk_score >= 80 else
                        "high" if final_risk_score >= 60 else
                        "medium" if final_risk_score >= 40 else
                        "low"
                    ),
                    "map_color": (
                        "#8b0000" if final_risk_score >= 80 else  # Dark red
                        "#ff4444" if final_risk_score >= 60 else  # Red
                        "#ff8800" if final_risk_score >= 40 else  # Orange
                        "#ffaa00"  # Yellow
                    )
                }
            
            # Calculate regional targeting intensity
            regional_data = {}
            for region, data in target_regions.items():
                avg_confidence = data["total_confidence"] / max(data["threat_count"], 1)
                
                regional_data[region] = {
                    "threat_count": data["threat_count"],
                    "avg_confidence": round(avg_confidence, 2),
                    "targeting_intensity": round(data["threat_count"] * avg_confidence, 1),
                    "recent_activity_count": len([
                        dt for dt in data["recent_activity"] 
                        if datetime.fromisoformat(dt) > datetime.now() - timedelta(days=7)
                    ])
                }
            
            # Generate threat flow analysis
            threat_flows = {}
            for connection in threat_connections:
                origin_key = f"{connection['origin_lat']:.1f},{connection['origin_lng']:.1f}"
                target_key = f"{connection['target_lat']:.1f},{connection['target_lng']:.1f}"
                flow_key = f"{origin_key}->{target_key}"
                
                if flow_key not in threat_flows:
                    threat_flows[flow_key] = {
                        "origin_lat": connection['origin_lat'],
                        "origin_lng": connection['origin_lng'],
                        "target_lat": connection['target_lat'],
                        "target_lng": connection['target_lng'],
                        "flow_count": 0,
                        "avg_confidence": 0,
                        "threat_ids": []
                    }
                
                threat_flows[flow_key]["flow_count"] += 1
                threat_flows[flow_key]["avg_confidence"] += connection["confidence"]
                threat_flows[flow_key]["threat_ids"].append(connection["threat_id"])
            
            # Finalize flow calculations
            for flow_data in threat_flows.values():
                flow_data["avg_confidence"] = flow_data["avg_confidence"] / flow_data["flow_count"]
                flow_data["flow_intensity"] = flow_data["flow_count"] * flow_data["avg_confidence"]
            
            return {
                "analysis_period_days": days,
                "data_summary": {
                    "total_threats_mapped": len(threat_locations),
                    "origin_countries_identified": len(origin_countries),
                    "target_regions_identified": len(target_regions),
                    "infrastructure_locations": len(infrastructure_locations),
                    "threat_connections": len(threat_connections)
                },
                "threat_locations": threat_locations,
                "country_risk_data": country_risk_data,
                "regional_targeting_data": regional_data,
                "infrastructure_map": infrastructure_locations,
                "threat_flow_analysis": list(threat_flows.values()),
                "map_visualization_config": {
                    "default_zoom": 2,
                    "center_lat": 30.0,
                    "center_lng": 0.0,
                    "heat_map_enabled": len(threat_locations) > 10,
                    "connection_lines_enabled": len(threat_connections) > 5,
                    "clustering_enabled": len(threat_locations) > 20
                },
                "threat_hotspots": self._identify_threat_hotspots(threat_locations),
                "geographic_trends": {
                    "most_active_origin": max(origin_countries.items(), 
                        key=lambda x: x[1]["threat_count"])[0] if origin_countries else "Unknown",
                    "most_targeted_region": max(regional_data.items(), 
                        key=lambda x: x[1]["threat_count"])[0] if regional_data else "Unknown",
                    "threat_distribution": "global" if len(origin_countries) > 5 else "regional"
                },
                "generated_at": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to get global threat map data: {e}")
            return {"error": str(e)}

    def _identify_threat_hotspots(self, locations: List[Dict]) -> List[Dict]:
        """Identify geographic threat hotspots using simple clustering"""
        if len(locations) < 3:
            return []
        
        hotspots = []
        cluster_radius = 5.0  # degrees (roughly 550km)
        
        # Simple clustering by proximity
        used_indices = set()
        
        for i, location in enumerate(locations):
            if i in used_indices:
                continue
                
            cluster_locations = [location]
            cluster_indices = {i}
            
            lat1, lng1 = location["latitude"], location["longitude"]
            
            # Find nearby locations
            for j, other_location in enumerate(locations):
                if j in used_indices or j == i:
                    continue
                    
                lat2, lng2 = other_location["latitude"], other_location["longitude"]
                
                # Simple distance calculation
                distance = ((lat2 - lat1)**2 + (lng2 - lng1)**2)**0.5
                
                if distance <= cluster_radius:
                    cluster_locations.append(other_location)
                    cluster_indices.add(j)
            
            # If cluster has multiple threats, it's a hotspot
            if len(cluster_locations) >= 2:
                used_indices.update(cluster_indices)
                
                # Calculate cluster center
                avg_lat = sum(loc["latitude"] for loc in cluster_locations) / len(cluster_locations)
                avg_lng = sum(loc["longitude"] for loc in cluster_locations) / len(cluster_locations)
                avg_confidence = sum(loc["confidence"] for loc in cluster_locations) / len(cluster_locations)
                
                hotspots.append({
                    "center_lat": avg_lat,
                    "center_lng": avg_lng,
                    "threat_count": len(cluster_locations),
                    "avg_confidence": round(avg_confidence, 2),
                    "radius_km": cluster_radius * 111,  # Convert to approximate km
                    "threat_ids": [loc["id"] for loc in cluster_locations],
                    "hotspot_intensity": len(cluster_locations) * avg_confidence,
                    "risk_level": (
                        "critical" if len(cluster_locations) >= 5 else
                        "high" if len(cluster_locations) >= 3 else
                        "medium"
                    )
                })
        
        # Sort hotspots by intensity
        hotspots.sort(key=lambda x: x["hotspot_intensity"], reverse=True)
        
        return hotspots[:10]  # Return top 10 hotspots
    
    def _determine_assessment_quality(self, confidence: float) -> str:
        """Determine overall assessment quality based on confidence"""
        if confidence >= 0.8:
            return "excellent"
        elif confidence >= 0.65:
            return "good"
        elif confidence >= 0.5:
            return "fair"
        else:
            return "limited"

    def _determine_priority(self, risk_score: int, severity: str, threat_type: str) -> str:
        """Determine threat priority classification"""
        if risk_score >= 85 or severity == "CRITICAL":
            return "P0_CRITICAL"
        elif risk_score >= 70 or severity == "HIGH" or threat_type in ["ransomware", "supply_chain", "apt"]:
            return "P1_HIGH"
        elif risk_score >= 50 or severity == "MEDIUM":
            return "P2_MEDIUM"
        else:
            return "P3_LOW"

    def _build_intelligence_highlights(self, mitre_mapping: Dict, impact_assessment: Dict, executive_summary: Dict) -> Dict:
        """Build key intelligence highlights section"""
        return {
            "key_intelligence_highlights": {
                "primary_concerns": self._extract_primary_concerns(mitre_mapping, impact_assessment, executive_summary),
                "immediate_actions_required": executive_summary.get("strategic_recommendations", {}).get("immediate_actions", []),
                "business_systems_at_risk": executive_summary.get("key_findings", {}).get("business_systems_at_risk", []),
                "mitigation_priorities": self._extract_mitigation_priorities(impact_assessment, mitre_mapping),
                "stakeholder_notifications": self._determine_stakeholder_notifications(executive_summary, impact_assessment.get("business_impact_assessment", {}).get("risk_level", "medium"))
            }
        }

    def _extract_primary_concerns(self, mitre_mapping: Dict, impact_assessment: Dict, executive_summary: Dict) -> List[str]:
        """Extract primary concerns from all analyses"""
        concerns = []
        
        # From MITRE analysis
        threat_type = mitre_mapping.get("threat_categorization", {}).get("threat_type", "")
        if threat_type:
            concerns.append(f"{threat_type.replace('_', ' ').title()} attack detected")
        
        # From impact assessment
        operational_impact = impact_assessment.get("business_impact_assessment", {}).get("operational_impact", {})
        if operational_impact.get("severity") in ["critical", "high"]:
            concerns.append("Critical operational systems at risk")
        
        # From executive summary
        business_impact = executive_summary.get("key_findings", {}).get("primary_threat", "")
        if business_impact:
            concerns.append(business_impact)
        
        return concerns[:5]  # Limit to top 5 concerns

    def _extract_mitigation_priorities(self, impact_assessment: Dict, mitre_mapping: Dict) -> List[str]:
        """Extract mitigation priorities"""
        priorities = []
        
        # From impact assessment
        immediate_actions = impact_assessment.get("recommended_response", {}).get("immediate_actions", [])
        priorities.extend(immediate_actions[:3])
        
        # From MITRE mapping
        mitigations = mitre_mapping.get("mitigations", [])
        for mitigation in mitigations[:2]:
            if mitigation.get("implementation_priority") == "immediate":
                priorities.append(f"Implement {mitigation.get('name', 'security control')}")
        
        return priorities

    def _determine_stakeholder_notifications(self, executive_summary: Dict, risk_level: str) -> List[str]:
        """Determine required stakeholder notifications"""
        notifications = []
        
        communication_guidance = executive_summary.get("communication_guidance", {})
        
        if communication_guidance.get("board_briefing_points"):
            notifications.append("board_of_directors")
        
        if communication_guidance.get("customer_communication") == "required":
            notifications.append("customers")
        
        if communication_guidance.get("regulatory_notification") == "required":
            notifications.append("regulatory_authorities")
        
        if risk_level in ["critical", "high"]:
            notifications.extend(["executive_team", "security_team", "operations_team"])
        
        return list(set(notifications))  # Remove duplicates


    def _build_quality_metrics(self, state: ThreatProcessingState, total_processing_time: float, overall_confidence: float) -> Dict:
        """Build analysis quality metrics section"""
        return {
            "analysis_quality_metrics": {
                "data_completeness": self._calculate_data_completeness(state),
                "confidence_distribution": {
                    "source_analysis": state.get("source_analysis", {}).get('confidence_in_analysis', 0.5),
                    "mitre_mapping": state.get("mitre_mapping", {}).get('mitre_confidence_overall', 0.5),
                    "impact_assessment": state.get("impact_assessment", {}).get("confidence_assessment", {}).get("impact_confidence", 0.5),
                    "executive_summary": state.get("executive_summary", {}).get("confidence_and_limitations", {}).get("assessment_confidence", 0.5)
                },
                "processing_efficiency": {
                    "total_processing_time_seconds": total_processing_time,
                    "average_agent_time": total_processing_time / 4,
                    "workflow_efficiency": "optimal" if total_processing_time < 30 else "acceptable" if total_processing_time < 60 else "slow"
                },
                "error_analysis": {
                    "errors_encountered": len(state.get("error_log", [])),
                    "error_details": state.get("error_log", []),
                    "fallback_modes_used": self._count_fallback_modes(state)
                }
            }
        }

    def _calculate_data_completeness(self, state: ThreatProcessingState) -> float:
        """Calculate how complete the analysis data is"""
        total_sections = 4  # source, mitre, impact, executive
        completed_sections = 0
        
        if state.get("source_analysis") and not state["source_analysis"].get("fallback_mode"):
            completed_sections += 1
        
        if state.get("mitre_mapping") and state["mitre_mapping"].get("techniques"):
            completed_sections += 1
        
        if state.get("impact_assessment") and state["impact_assessment"].get("business_impact_assessment"):
            completed_sections += 1
        
        if state.get("executive_summary") and state["executive_summary"].get("executive_overview"):
            completed_sections += 1
        
        return round(completed_sections / total_sections, 2)

    def _count_fallback_modes(self, state: ThreatProcessingState) -> int:
        """Count how many agents used fallback mode"""
        fallback_count = 0
        
        for agent_result in ["source_analysis", "mitre_mapping", "impact_assessment", "executive_summary"]:
            if state.get(agent_result, {}).get("fallback_mode"):
                fallback_count += 1
        
        return fallback_count

    def _build_actionable_intelligence(self, risk_score: int, threat_type: str, sophistication: str, 
                                     max_financial_impact: int, executive_summary: Dict) -> Dict:
        """Build actionable intelligence section"""
        return {
            "actionable_intelligence": {
                "recommended_response_level": self._determine_response_level(risk_score, threat_type),
                "resource_allocation": {
                    "security_team_priority": "p0" if risk_score >= 85 else "p1" if risk_score >= 70 else "p2",
                    "budget_approval_needed": max_financial_impact > 1000000,
                    "external_expertise_recommended": sophistication in ["advanced", "expert"] or threat_type in ["apt", "supply_chain"]
                },
                "timeline_recommendations": {
                    "immediate_response": executive_summary.get("executive_overview", {}).get("timeline_for_action", "24_hours"),
                    "full_assessment_timeline": "24-48 hours" if risk_score >= 80 else "1 week",
                    "monitoring_duration": "continuous" if threat_type in ["apt", "supply_chain"] else "30 days"
                },
                "success_criteria": {
                    "threat_containment_targets": self._define_containment_targets(threat_type, risk_score),
                    "business_continuity_goals": ["maintain_operations", "protect_customer_data", "preserve_reputation"],
                    "recovery_objectives": {
                        "rto_hours": 4 if risk_score >= 85 else 8 if risk_score >= 70 else 24,
                        "rpo_hours": 1 if risk_score >= 85 else 4 if risk_score >= 70 else 8
                    }
                }
            },
            "strategic_context": {
                "threat_landscape_position": self._assess_threat_landscape_position(threat_type, sophistication),
                "competitive_implications": executive_summary.get("competitive_intelligence", {}).get("competitive_advantage_opportunity", "unknown"),
                "regulatory_considerations": [],  # Will be populated from impact assessment
                "supply_chain_implications": executive_summary.get("risk_context", {}).get("supply_chain_implications", "unknown")
            },
            "continuous_monitoring_recommendations": {
                "threat_indicators_to_monitor": self._extract_monitoring_indicators(threat_type),
                "business_metrics_to_track": ["system_availability", "customer_satisfaction", "operational_efficiency"],
                "intelligence_gaps_to_address": executive_summary.get("confidence_and_limitations", {}).get("intelligence_gaps", []),
                "follow_up_analysis_needed": self._determine_follow_up_needs(risk_score, threat_type)
            },
            "final_recommendations": {
                "executive_briefing_required": executive_summary.get("executive_overview", {}).get("executive_attention_required", False),
                "board_notification": risk_score >= 85 or max_financial_impact > 10000000,
                "customer_communication": executive_summary.get("communication_guidance", {}).get("customer_communication", "not_needed"),
                "regulatory_reporting": risk_score >= 80,
                "incident_response_activation": risk_score >= 70,
                "crisis_management_activation": risk_score >= 85 and threat_type in ["ransomware", "supply_chain", "apt"]
            }
        }

    def _determine_response_level(self, risk_score: int, threat_type: str) -> str:
        """Determine recommended response level"""
        if risk_score >= 85 or threat_type in ["ransomware", "apt"]:
            return "CRISIS_RESPONSE"
        elif risk_score >= 70:
            return "ELEVATED_RESPONSE"
        elif risk_score >= 50:
            return "STANDARD_RESPONSE"
        else:
            return "MONITORING_RESPONSE"

    def _define_containment_targets(self, threat_type: str, risk_score: int) -> List[str]:
        """Define threat containment targets based on threat type"""
        targets = ["prevent_lateral_movement", "protect_critical_systems"]
        
        if threat_type == "ransomware":
            targets.extend(["prevent_encryption", "backup_isolation", "payment_prevention"])
        elif threat_type == "supply_chain":
            targets.extend(["vendor_isolation", "supply_chain_verification", "upstream_notification"])
        elif threat_type == "phishing":
            targets.extend(["email_blocking", "credential_reset", "user_awareness"])
        elif threat_type == "malware":
            targets.extend(["malware_quarantine", "system_cleaning", "network_segmentation"])
        
        if risk_score >= 80:
            targets.append("business_continuity_activation")
        
        return targets

    def _assess_threat_landscape_position(self, threat_type: str, sophistication: str) -> str:
        """Assess where this threat fits in the current landscape"""
        if sophistication == "expert" and threat_type in ["apt", "supply_chain"]:
            return "ADVANCED_PERSISTENT_THREAT"
        elif threat_type == "ransomware" and sophistication in ["advanced", "expert"]:
            return "SOPHISTICATED_CYBERCRIME"
        elif threat_type in ["phishing", "malware"] and sophistication == "basic":
            return "COMMODITY_THREAT"
        elif threat_type == "supply_chain":
            return "STRATEGIC_COMPROMISE"
        else:
            return "STANDARD_CYBER_THREAT"

    def _extract_monitoring_indicators(self, threat_type: str) -> List[str]:
        """Extract indicators to monitor based on threat type"""
        base_indicators = ["network_anomalies", "authentication_failures", "system_performance"]
        
        type_specific = {
            "ransomware": ["file_encryption_activity", "backup_access_attempts", "crypto_payment_addresses"],
            "supply_chain": ["vendor_communication_anomalies", "software_update_requests", "third_party_access"],
            "phishing": ["email_pattern_changes", "credential_usage_anomalies", "user_behavior_changes"],
            "malware": ["process_anomalies", "network_connections", "file_system_changes"],
            "ddos": ["traffic_volume_spikes", "service_availability", "bandwidth_utilization"]
        }
        
        return base_indicators + type_specific.get(threat_type, [])

    def _determine_follow_up_needs(self, risk_score: int, threat_type: str) -> List[str]:
        """Determine what follow-up analysis is needed"""
        follow_ups = []
        
        if risk_score >= 80:
            follow_ups.append("detailed_forensic_analysis")
        
        if threat_type in ["apt", "supply_chain"]:
            follow_ups.append("attribution_analysis")
        
        if threat_type == "ransomware":
            follow_ups.append("ransom_payment_analysis")
        
        follow_ups.extend(["trend_analysis", "threat_hunting", "vulnerability_assessment"])
        
        return follow_ups

    def _fallback_final_analysis(self, raw_threat: Dict, state: ThreatProcessingState) -> Dict:
        """Provide minimal final analysis when finalization fails"""
        
        # Extract what we can from existing state
        risk_score = 50
        risk_level = "medium"
        threat_type = "unknown"
        
        # Try to get risk info from impact assessment
        if state.get("impact_assessment"):
            impact = state["impact_assessment"].get("business_impact_assessment", {})
            risk_score = impact.get("overall_risk_score", 50)
            risk_level = impact.get("risk_level", "medium")
        
        # Try to get threat type from MITRE mapping
        if state.get("mitre_mapping"):
            threat_cat = state["mitre_mapping"].get("threat_categorization", {})
            threat_type = threat_cat.get("threat_type", "unknown")
        
        return {
            "threat_intelligence_summary": {
                "threat_id": raw_threat.get('id'),
                "threat_title": raw_threat.get('title', ''),
                "source": raw_threat.get('source', ''),
                "analysis_timestamp": datetime.now().isoformat(),
                "processing_version": "1.0_fallback"
            },
            "overall_assessment": {
                "final_risk_score": risk_score,
                "risk_level": risk_level,
                "severity_rating": "MEDIUM",
                "threat_classification": threat_type,
                "sophistication_level": "unknown",
                "overall_confidence": 0.2,
                "assessment_quality": "limited",
                "priority_classification": "P2_MEDIUM"
            },
            "key_intelligence_highlights": {
                "primary_concerns": ["Analysis incomplete due to processing error"],
                "immediate_actions_required": ["Manual threat assessment required", "Activate security team"],
                "business_systems_at_risk": ["unknown"],
                "mitigation_priorities": ["Complete manual analysis"],
                "stakeholder_notifications": ["security_team"]
            },
            "analysis_quality_metrics": {
                "data_completeness": self._calculate_data_completeness(state),
                "processing_efficiency": {
                    "workflow_efficiency": "failed"
                },
                "error_analysis": {
                    "errors_encountered": len(state.get("error_log", [])),
                    "error_details": state.get("error_log", []),
                    "fallback_modes_used": self._count_fallback_modes(state)
                }
            },
            "final_recommendations": {
                "executive_briefing_required": True,
                "manual_analysis_required": True,
                "incident_response_activation": risk_score >= 70
            },
            "fallback_mode": True,
            "analysis_timestamp": datetime.now().isoformat()
        }

    def get_final_analysis_for_threat(self, threat_id: int) -> Optional[Dict]:
        """Retrieve final comprehensive analysis for a specific threat"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT analysis_result, created_at 
                FROM agent_analysis 
                WHERE raw_threat_id = ? AND agent_type = 'finalization'
                ORDER BY created_at DESC 
                LIMIT 1
            """, (threat_id,))
            
            result = cursor.fetchone()
            if result:
                analysis = json.loads(result[0])
                analysis['retrieved_at'] = result[1]
                return analysis
            return None
        except Exception as e:
            logger.error(f"Failed to retrieve final analysis: {e}")
            return None

    def get_multi_agent_workflow_results(self, threat_id: int) -> Optional[Dict]:
        """Get complete multi-agent workflow results for a threat"""
        try:
            cursor = self.conn.cursor()
            
            # Get all agent results for this threat
            cursor.execute("""
                SELECT agent_type, analysis_result, confidence_score, processing_time, created_at
                FROM agent_analysis 
                WHERE raw_threat_id = ?
                ORDER BY created_at ASC
            """, (threat_id,))
            
            agent_results = cursor.fetchall()
            
            # Get workflow metadata
            cursor.execute("""
                SELECT workflow_status, overall_confidence, final_analysis, processing_metadata, created_at
                FROM multi_agent_results 
                WHERE raw_threat_id = ?
                ORDER BY created_at DESC 
                LIMIT 1
            """, (threat_id,))
            
            workflow_result = cursor.fetchone()
            
            if not agent_results:
                return None
            
            # Compile comprehensive results
            compiled_results = {
                "threat_id": threat_id,
                "workflow_metadata": {
                    "status": workflow_result[0] if workflow_result else "unknown",
                    "overall_confidence": workflow_result[1] if workflow_result else 0.5,
                    "completed_at": workflow_result[4] if workflow_result else None
                },
                "agent_results": {},
                "processing_timeline": [],
                "confidence_progression": [],
                "error_summary": []
            }
            
            # Process individual agent results
            total_processing_time = 0
            confidence_values = []
            
            for agent_type, analysis_json, confidence, proc_time, created_at in agent_results:
                try:
                    analysis_data = json.loads(analysis_json)
                    compiled_results["agent_results"][agent_type] = {
                        "analysis": analysis_data,
                        "confidence": confidence,
                        "processing_time": proc_time,
                        "completed_at": created_at,
                        "status": "completed" if not analysis_data.get("fallback_mode") else "fallback"
                    }
                    
                    compiled_results["processing_timeline"].append({
                        "agent": agent_type,
                        "timestamp": created_at,
                        "duration_seconds": proc_time,
                        "status": "success" if not analysis_data.get("fallback_mode") else "fallback"
                    })
                    
                    confidence_values.append(confidence)
                    total_processing_time += proc_time
                    
                    # Collect errors if any
                    if analysis_data.get("error_log"):
                        compiled_results["error_summary"].extend(analysis_data["error_log"])
                    
                except json.JSONDecodeError:
                    compiled_results["error_summary"].append(f"Failed to parse {agent_type} results")
            
            # Calculate summary statistics
            compiled_results["summary_statistics"] = {
                "total_agents_executed": len(agent_results),
                "successful_agents": len([r for r in compiled_results["agent_results"].values() if r["status"] == "completed"]),
                "fallback_agents": len([r for r in compiled_results["agent_results"].values() if r["status"] == "fallback"]),
                "total_processing_time": total_processing_time,
                "average_confidence": sum(confidence_values) / len(confidence_values) if confidence_values else 0,
                "workflow_efficiency": "optimal" if total_processing_time < 30 else "acceptable" if total_processing_time < 60 else "slow"
            }
            
            # Add final analysis if available
            if workflow_result and workflow_result[2]:
                try:
                    compiled_results["final_analysis"] = json.loads(workflow_result[2])
                except json.JSONDecodeError:
                    compiled_results["error_summary"].append("Failed to parse final analysis")
            
            return compiled_results
            
        except Exception as e:
            logger.error(f"Failed to get multi-agent workflow results: {e}")
            return {"error": str(e)}

    def get_workflow_performance_analytics(self, days: int = 30) -> Dict:
        """Get performance analytics for multi-agent workflows"""
        try:
            cursor = self.conn.cursor()
            time_threshold = (datetime.now() - timedelta(days=days)).isoformat()
            
            # Get workflow performance data
            cursor.execute("""
                SELECT 
                    m.workflow_status,
                    m.overall_confidence,
                    m.processing_metadata,
                    m.created_at,
                    r.source,
                    COUNT(a.agent_type) as agents_executed
                FROM multi_agent_results m
                JOIN raw_threats r ON m.raw_threat_id = r.id
                LEFT JOIN agent_analysis a ON m.raw_threat_id = a.raw_threat_id
                WHERE m.created_at > ?
                GROUP BY m.raw_threat_id
                ORDER BY m.created_at DESC
            """, (time_threshold,))
            
            workflow_data = cursor.fetchall()
            
            # Get agent-specific performance
            cursor.execute("""
                SELECT 
                    agent_type,
                    AVG(processing_time) as avg_processing_time,
                    AVG(confidence_score) as avg_confidence,
                    COUNT(*) as total_executions,
                    SUM(CASE WHEN json_extract(analysis_result, '$.fallback_mode') = 1 THEN 1 ELSE 0 END) as fallback_count
                FROM agent_analysis a
                JOIN raw_threats r ON a.raw_threat_id = r.id
                WHERE r.collected_at > ?
                GROUP BY agent_type
            """, (time_threshold,))
            
            agent_performance = cursor.fetchall()
            
            # Process workflow statistics
            workflow_stats = {
                "total_workflows": len(workflow_data),
                "completed_workflows": 0,
                "failed_workflows": 0,
                "average_confidence": 0,
                "confidence_distribution": {"excellent": 0, "good": 0, "fair": 0, "limited": 0},
                "processing_time_stats": [],
                "source_performance": {}
            }
            
            total_confidence = 0
            processing_times = []
            
            for row in workflow_data:
                status, confidence, metadata_json, created_at, source, agents_count = row
                
                if status == "completed":
                    workflow_stats["completed_workflows"] += 1
                else:
                    workflow_stats["failed_workflows"] += 1
                
                if confidence:
                    total_confidence += confidence
                    
                    # Classify confidence
                    if confidence >= 0.8:
                        workflow_stats["confidence_distribution"]["excellent"] += 1
                    elif confidence >= 0.65:
                        workflow_stats["confidence_distribution"]["good"] += 1
                    elif confidence >= 0.5:
                        workflow_stats["confidence_distribution"]["fair"] += 1
                    else:
                        workflow_stats["confidence_distribution"]["limited"] += 1
                
                # Process metadata for timing
                try:
                    if metadata_json:
                        metadata = json.loads(metadata_json)
                        total_time = metadata.get("total_workflow_time", 0)
                        if total_time > 0:
                            processing_times.append(total_time)
                except:
                    pass
                
                # Track source performance
                if source not in workflow_stats["source_performance"]:
                    workflow_stats["source_performance"][source] = {
                        "workflow_count": 0,
                        "avg_confidence": 0,
                        "total_confidence": 0
                    }
                
                workflow_stats["source_performance"][source]["workflow_count"] += 1
                if confidence:
                    workflow_stats["source_performance"][source]["total_confidence"] += confidence
            
            # Calculate averages
            if workflow_stats["total_workflows"] > 0:
                workflow_stats["average_confidence"] = round(total_confidence / workflow_stats["total_workflows"], 3)
            
            if processing_times:
                workflow_stats["processing_time_stats"] = {
                    "average_seconds": round(sum(processing_times) / len(processing_times), 1),
                    "min_seconds": min(processing_times),
                    "max_seconds": max(processing_times),
                    "median_seconds": sorted(processing_times)[len(processing_times)//2]
                }
            
            # Finalize source performance
            for source_data in workflow_stats["source_performance"].values():
                if source_data["workflow_count"] > 0:
                    source_data["avg_confidence"] = round(
                        source_data["total_confidence"] / source_data["workflow_count"], 3
                    )
            
            # Process agent performance
            agent_stats = {}
            for agent_type, avg_time, avg_conf, total_exec, fallback_count in agent_performance:
                agent_stats[agent_type] = {
                    "average_processing_time": round(avg_time, 2),
                    "average_confidence": round(avg_conf, 3),
                    "total_executions": total_exec,
                    "fallback_rate": round((fallback_count / total_exec) * 100, 1) if total_exec > 0 else 0,
                    "reliability_score": round((1 - (fallback_count / total_exec)) * avg_conf * 100, 1) if total_exec > 0 else 0
                }
            
            return {
                "analysis_period_days": days,
                "workflow_performance": workflow_stats,
                "agent_performance": agent_stats,
                "overall_system_health": {
                    "workflow_success_rate": round((workflow_stats["completed_workflows"] / max(workflow_stats["total_workflows"], 1)) * 100, 1),
                    "average_system_confidence": workflow_stats["average_confidence"],
                    "system_reliability": "excellent" if workflow_stats["average_confidence"] > 0.8 else "good" if workflow_stats["average_confidence"] > 0.65 else "fair",
                    "performance_trend": self._assess_performance_trend(workflow_data)
                },
                "recommendations": self._generate_performance_recommendations(workflow_stats, agent_stats),
                "generated_at": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to get workflow performance analytics: {e}")
            return {"error": str(e)}

    def _assess_performance_trend(self, workflow_data: List) -> str:
        """Assess if performance is improving, declining, or stable"""
        if len(workflow_data) < 10:
            return "insufficient_data"
        
        # Split data into recent and older halves
        mid_point = len(workflow_data) // 2
        recent_data = workflow_data[:mid_point]  # More recent (higher indices)
        older_data = workflow_data[mid_point:]
        
        # Calculate average confidence for each period
        recent_confidence = sum(row[1] for row in recent_data if row[1]) / len([row for row in recent_data if row[1]])
        older_confidence = sum(row[1] for row in older_data if row[1]) / len([row for row in older_data if row[1]])
        
        confidence_change = recent_confidence - older_confidence
        
        if confidence_change > 0.05:
            return "improving"
        elif confidence_change < -0.05:
            return "declining"
        else:
            return "stable"

    def _generate_performance_recommendations(self, workflow_stats: Dict, agent_stats: Dict) -> List[str]:
        """Generate recommendations based on performance analysis"""
        recommendations = []
        
        # Overall workflow recommendations
        if workflow_stats["average_confidence"] < 0.6:
            recommendations.append("Consider improving data quality and source reliability")
        
        success_rate = workflow_stats["completed_workflows"] / max(workflow_stats["total_workflows"], 1)
        if success_rate < 0.9:
            recommendations.append("Investigate workflow failure patterns and improve error handling")
        
        # Agent-specific recommendations
        for agent_type, stats in agent_stats.items():
            if stats["fallback_rate"] > 20:
                recommendations.append(f"Improve {agent_type} reliability - high fallback rate ({stats['fallback_rate']}%)")
            
            if stats["average_processing_time"] > 15:
                recommendations.append(f"Optimize {agent_type} performance - slow processing time ({stats['average_processing_time']}s)")
            
            if stats["average_confidence"] < 0.5:
                recommendations.append(f"Enhance {agent_type} analysis quality - low confidence scores")
        
        # Performance optimization
        avg_processing_time = workflow_stats.get("processing_time_stats", {}).get("average_seconds", 0)
        if avg_processing_time > 60:
            recommendations.append("Consider parallel processing or performance optimization")
        
        return recommendations[:5]  # Limit to top 5 recommendations


    def get_executive_summary_for_threat(self, threat_id: int) -> Optional[Dict]:
        """Retrieve executive summary for a specific threat"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT analysis_result, created_at 
                FROM agent_analysis 
                WHERE raw_threat_id = ? AND agent_type = 'executive_summary'
                ORDER BY created_at DESC 
                LIMIT 1
            """, (threat_id,))
            
            result = cursor.fetchone()
            if result:
                analysis = json.loads(result[0])
                analysis['retrieved_at'] = result[1]
                return analysis
            return None
        except Exception as e:
            logger.error(f"Failed to retrieve executive summary: {e}")
            return None

    def get_executive_dashboard_data(self, days: int = 30) -> Dict:
        """Get comprehensive executive dashboard data"""
        try:
            cursor = self.conn.cursor()
            time_threshold = (datetime.now() - timedelta(days=days)).isoformat()
            
            # Get executive summaries and related data
            cursor.execute("""
                SELECT 
                    a.analysis_result,
                    r.title,
                    r.source,
                    r.collected_at,
                    r.id
                FROM agent_analysis a
                JOIN raw_threats r ON a.raw_threat_id = r.id
                WHERE a.agent_type = 'executive_summary'
                AND r.collected_at > ?
                ORDER BY r.collected_at DESC
            """, (time_threshold,))
            
            exec_results = cursor.fetchall()
            
            # Initialize dashboard data containers
            dashboard_data = {
                "executive_overview": {
                    "total_threats_analyzed": len(exec_results),
                    "critical_threats": 0,
                    "high_threats": 0,
                    "executive_attention_required": 0,
                    "immediate_action_required": 0
                },
                "severity_distribution": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
                "business_impact_summary": {
                    "operations_at_risk": {},
                    "financial_exposure_ranges": {},
                    "customer_impact_levels": {},
                    "reputation_risks": {}
                },
                "action_timeline_analysis": {
                    "immediate": 0,
                    "24_hours": 0,
                    "this_week": 0,
                    "this_month": 0
                },
                "strategic_priorities": {
                    "most_common_immediate_actions": {},
                    "recurring_short_term_priorities": {},
                    "strategic_initiative_themes": {}
                },
                "confidence_metrics": {
                    "high_confidence_assessments": 0,
                    "medium_confidence_assessments": 0,
                    "low_confidence_assessments": 0,
                    "average_confidence": 0
                },
                "threat_intelligence_highlights": [],
                "executive_attention_items": [],
                "board_notification_items": []
            }
            
            total_confidence = 0
            confidence_count = 0
                        # Process each executive summary
            for row in exec_results:
                try:
                    analysis = json.loads(row[0])
                    threat_title = row[1]
                    source = row[2]
                    collected_at = row[3]
                    threat_id = row[4]
                    
                    # Executive overview metrics
                    exec_overview = analysis.get("executive_overview", {})
                    severity = exec_overview.get("severity_rating", "MEDIUM")
                    timeline = exec_overview.get("timeline_for_action", "this_week")
                    attention_required = exec_overview.get("executive_attention_required", False)
                    
                    # Count severity levels
                    dashboard_data["severity_distribution"][severity] = dashboard_data["severity_distribution"].get(severity, 0) + 1
                    
                    if severity == "CRITICAL":
                        dashboard_data["executive_overview"]["critical_threats"] += 1
                    elif severity == "HIGH":
                        dashboard_data["executive_overview"]["high_threats"] += 1
                    
                    if attention_required:
                        dashboard_data["executive_overview"]["executive_attention_required"] += 1
                        
                        # Add to executive attention items
                        dashboard_data["executive_attention_items"].append({
                            "threat_id": threat_id,
                            "threat_title": threat_title[:100],
                            "severity": severity,
                            "business_impact": exec_overview.get("business_impact", "Unknown impact"),
                            "recommended_action": exec_overview.get("recommended_action", "Review required"),
                            "source": source,
                            "date": collected_at[:10]
                        })
                    
                    if timeline == "immediate":
                        dashboard_data["executive_overview"]["immediate_action_required"] += 1
                    
                    # Timeline analysis
                    dashboard_data["action_timeline_analysis"][timeline] = dashboard_data["action_timeline_analysis"].get(timeline, 0) + 1
                    
                    # Business impact analysis
                    business_impact = analysis.get("business_impact_summary", {})
                    
                    # Operations affected
                    operations = business_impact.get("operations_affected", [])
                    for operation in operations:
                        dashboard_data["business_impact_summary"]["operations_at_risk"][operation] = \
                            dashboard_data["business_impact_summary"]["operations_at_risk"].get(operation, 0) + 1
                    
                    # Customer impact
                    customer_impact = business_impact.get("customer_impact", "unknown")
                    dashboard_data["business_impact_summary"]["customer_impact_levels"][customer_impact] = \
                        dashboard_data["business_impact_summary"]["customer_impact_levels"].get(customer_impact, 0) + 1
                    
                    # Reputation risk
                    reputation_risk = business_impact.get("reputation_risk", "unknown")
                    dashboard_data["business_impact_summary"]["reputation_risks"][reputation_risk] = \
                        dashboard_data["business_impact_summary"]["reputation_risks"].get(reputation_risk, 0) + 1
                    
                                        # Strategic recommendations analysis
                    strategic_recs = analysis.get("strategic_recommendations", {})
                    
                    # Immediate actions
                    immediate_actions = strategic_recs.get("immediate_actions", [])
                    for action in immediate_actions:
                        action_key = action[:50]  # Truncate for grouping
                        dashboard_data["strategic_priorities"]["most_common_immediate_actions"][action_key] = \
                            dashboard_data["strategic_priorities"]["most_common_immediate_actions"].get(action_key, 0) + 1
                    
                    # Short-term priorities
                    short_term = strategic_recs.get("short_term_priorities", [])
                    for priority in short_term:
                        priority_key = priority[:50]
                        dashboard_data["strategic_priorities"]["recurring_short_term_priorities"][priority_key] = \
                            dashboard_data["strategic_priorities"]["recurring_short_term_priorities"].get(priority_key, 0) + 1
                    
                    # Confidence metrics
                    confidence_data = analysis.get("confidence_and_limitations", {})
                    assessment_confidence = confidence_data.get("assessment_confidence", 0.5)
                    
                    total_confidence += assessment_confidence
                    confidence_count += 1
                    
                    if assessment_confidence >= 0.8:
                        dashboard_data["confidence_metrics"]["high_confidence_assessments"] += 1
                    elif assessment_confidence >= 0.6:
                        dashboard_data["confidence_metrics"]["medium_confidence_assessments"] += 1
                    else:
                        dashboard_data["confidence_metrics"]["low_confidence_assessments"] += 1
                    
                    # Collect high-impact intelligence highlights
                    if severity in ["CRITICAL", "HIGH"] or attention_required:
                        dashboard_data["threat_intelligence_highlights"].append({
                            "threat_id": threat_id,
                            "title": threat_title[:100],
                            "severity": severity,
                            "key_finding": analysis.get("key_findings", {}).get("primary_threat", "Unknown threat"),
                            "business_systems_at_risk": analysis.get("key_findings", {}).get("business_systems_at_risk", []),
                            "source": source,
                            "date": collected_at[:10],
                            "confidence": assessment_confidence
                        })
                    
                    # Board notification items (very high severity/impact)
                    financial_exposure = business_impact.get("financial_exposure", {})
                    if (severity == "CRITICAL" or 
                        "million" in str(financial_exposure.get("potential_losses", "")).lower() or
                        business_impact.get("business_continuity_risk") == "critical"):
                        
                        dashboard_data["board_notification_items"].append({
                            "threat_id": threat_id,
                            "title": threat_title[:100],
                            "severity": severity,
                            "financial_exposure": financial_exposure.get("potential_losses", "TBD"),
                            "business_continuity_risk": business_impact.get("business_continuity_risk", "unknown"),
                            "recommended_action": exec_overview.get("recommended_action", "Review required"),
                            "date": collected_at[:10]
                        })
                
                except json.JSONDecodeError:
                    continue

                            # Calculate final metrics
            if confidence_count > 0:
                dashboard_data["confidence_metrics"]["average_confidence"] = round(total_confidence / confidence_count, 3)
            
            # Sort and limit collections
            dashboard_data["threat_intelligence_highlights"] = sorted(
                dashboard_data["threat_intelligence_highlights"], 
                key=lambda x: (x["severity"] == "CRITICAL", x["confidence"]), 
                reverse=True
            )[:10]
            
            dashboard_data["executive_attention_items"] = sorted(
                dashboard_data["executive_attention_items"],
                key=lambda x: (x["severity"] == "CRITICAL", x["date"]),
                reverse=True
            )[:15]
            
            dashboard_data["board_notification_items"] = sorted(
                dashboard_data["board_notification_items"],
                key=lambda x: x["date"],
                reverse=True
            )[:10]
            
            # Sort strategic priorities by frequency
            dashboard_data["strategic_priorities"]["most_common_immediate_actions"] = dict(sorted(
                dashboard_data["strategic_priorities"]["most_common_immediate_actions"].items(),
                key=lambda x: x[1], reverse=True
            )[:10])
            
            dashboard_data["strategic_priorities"]["recurring_short_term_priorities"] = dict(sorted(
                dashboard_data["strategic_priorities"]["recurring_short_term_priorities"].items(),
                key=lambda x: x[1], reverse=True
            )[:10])
            
            # Add trend analysis
            dashboard_data["trend_analysis"] = self._calculate_executive_trends(exec_results, days)
            
            # Add risk posture assessment
            dashboard_data["risk_posture"] = self._assess_organizational_risk_posture(dashboard_data)
            
            dashboard_data["analysis_period_days"] = days
            dashboard_data["generated_at"] = datetime.now().isoformat()
            
            return dashboard_data
            
        except Exception as e:
            logger.error(f"Failed to get executive dashboard data: {e}")
            return {"error": str(e)}


    def _calculate_executive_trends(self, exec_results: List, days: int) -> Dict:
        """Calculate trends for executive dashboard"""
        if len(exec_results) < 7:
            return {"trend_analysis": "insufficient_data"}
        
        # Split data into periods for trend analysis
        mid_point = len(exec_results) // 2
        recent_data = exec_results[:mid_point]
        older_data = exec_results[mid_point:]
        
        def analyze_period(data):
            critical_count = 0
            high_count = 0
            exec_attention_count = 0
            total_count = len(data)
            
            for row in data:
                try:
                    analysis = json.loads(row[0])
                    severity = analysis.get("executive_overview", {}).get("severity_rating", "MEDIUM")
                    attention = analysis.get("executive_overview", {}).get("executive_attention_required", False)
                    
                    if severity == "CRITICAL":
                        critical_count += 1
                    elif severity == "HIGH":
                        high_count += 1
                    
                    if attention:
                        exec_attention_count += 1
                        
                except:
                    continue
            
            return {
                "critical_rate": critical_count / max(total_count, 1),
                "high_rate": high_count / max(total_count, 1),
                "attention_rate": exec_attention_count / max(total_count, 1)
            }
        
        recent_metrics = analyze_period(recent_data)
        older_metrics = analyze_period(older_data)
        
        return {
            "critical_threat_trend": "increasing" if recent_metrics["critical_rate"] > older_metrics["critical_rate"] else "decreasing" if recent_metrics["critical_rate"] < older_metrics["critical_rate"] else "stable",
            "high_threat_trend": "increasing" if recent_metrics["high_rate"] > older_metrics["high_rate"] else "decreasing" if recent_metrics["high_rate"] < older_metrics["high_rate"] else "stable",
            "executive_attention_trend": "increasing" if recent_metrics["attention_rate"] > older_metrics["attention_rate"] else "decreasing" if recent_metrics["attention_rate"] < older_metrics["attention_rate"] else "stable",
            "overall_threat_landscape": "escalating" if recent_metrics["critical_rate"] + recent_metrics["high_rate"] > older_metrics["critical_rate"] + older_metrics["high_rate"] + 0.1 else "improving" if recent_metrics["critical_rate"] + recent_metrics["high_rate"] < older_metrics["critical_rate"] + older_metrics["high_rate"] - 0.1 else "stable"
        }

    def get_comprehensive_threat_intelligence_summary(self, days: int = 7) -> Dict:
        """Get comprehensive threat intelligence summary for recent period"""
        try:
            cursor = self.conn.cursor()
            time_threshold = (datetime.now() - timedelta(days=days)).isoformat()
            
            # Get all agent results for recent threats
            cursor.execute("""
                SELECT 
                    r.id,
                    r.title,
                    r.source,
                    r.collected_at,
                    a.agent_type,
                    a.analysis_result,
                    a.confidence_score
                FROM raw_threats r
                LEFT JOIN agent_analysis a ON r.id = a.raw_threat_id
                WHERE r.collected_at > ?
                ORDER BY r.collected_at DESC, a.agent_type
            """, (time_threshold,))
            
            results = cursor.fetchall()
            
            # Organize results by threat
            threats_data = {}
            for row in results:
                threat_id, title, source, collected_at, agent_type, analysis_result, confidence = row
                
                if threat_id not in threats_data:
                    threats_data[threat_id] = {
                        "id": threat_id,
                        "title": title,
                        "source": source,
                        "collected_at": collected_at,
                        "agent_results": {},
                        "overall_confidence": 0,
                        "analysis_complete": False
                    }
                
                if agent_type and analysis_result:
                    try:
                        threats_data[threat_id]["agent_results"][agent_type] = {
                            "analysis": json.loads(analysis_result),
                            "confidence": confidence
                        }
                    except json.JSONDecodeError:
                        continue
            
            # Generate comprehensive summary
            summary_data = {
                "summary_period": f"Last {days} days",
                "total_threats_processed": len(threats_data),
                "analysis_coverage": {
                    "fully_analyzed": 0,
                    "partially_analyzed": 0,
                    "analysis_pending": 0
                },
                "threat_landscape_overview": {
                    "dominant_threat_types": {},
                    "primary_attack_vectors": {},
                    "target_sectors": {},
                    "geographic_patterns": {}
                },
                "business_impact_overview": {
                    "high_impact_threats": [],
                    "financial_exposure_summary": {"total_min": 0, "total_max": 0},
                    "operational_risks": {},
                    "compliance_implications": {}
                },
                "strategic_intelligence": {
                    "emerging_threat_patterns": [],
                    "attribution_insights": {},
                    "campaign_tracking": {},
                    "threat_actor_activities": {}
                },
                "actionable_recommendations": {
                    "immediate_priorities": [],
                    "strategic_investments": [],
                    "process_improvements": [],
                    "capability_gaps": []
                }
            }
            
            # Process each threat's data
            for threat_data in threats_data.values():
                agent_results = threat_data["agent_results"]
                
                # Determine analysis completeness
                expected_agents = ["source_analysis", "mitre_mapping", "impact_assessment", "executive_summary"]
                completed_agents = len([agent for agent in expected_agents if agent in agent_results])
                
                if completed_agents == len(expected_agents):
                    summary_data["analysis_coverage"]["fully_analyzed"] += 1
                    threat_data["analysis_complete"] = True
                elif completed_agents > 0:
                    summary_data["analysis_coverage"]["partially_analyzed"] += 1
                else:
                    summary_data["analysis_coverage"]["analysis_pending"] += 1
                    continue
                
                # Extract threat intelligence insights
                if "mitre_mapping" in agent_results:
                    mitre_data = agent_results["mitre_mapping"]["analysis"]
                    threat_type = mitre_data.get("threat_categorization", {}).get("threat_type", "unknown")
                    summary_data["threat_landscape_overview"]["dominant_threat_types"][threat_type] = \
                        summary_data["threat_landscape_overview"]["dominant_threat_types"].get(threat_type, 0) + 1
                    
                    # Attack vectors
                    techniques = mitre_data.get("techniques", [])
                    for technique in techniques:
                        tech_name = technique.get("name", "Unknown")
                        summary_data["threat_landscape_overview"]["primary_attack_vectors"][tech_name] = \
                            summary_data["threat_landscape_overview"]["primary_attack_vectors"].get(tech_name, 0) + 1
                
                # Business impact analysis
                if "impact_assessment" in agent_results:
                    impact_data = agent_results["impact_assessment"]["analysis"]
                    business_impact = impact_data.get("business_impact_assessment", {})
                    
                    risk_score = business_impact.get("overall_risk_score", 0)
                    if risk_score >= 80:
                        financial_impact = business_impact.get("potential_financial_impact", {})
                        summary_data["business_impact_overview"]["high_impact_threats"].append({
                            "threat_id": threat_data["id"],
                            "title": threat_data["title"][:100],
                            "risk_score": risk_score,
                            "max_financial_impact": financial_impact.get("max_estimate_usd", 0)
                        })
                        
                        # Aggregate financial exposure
                        summary_data["business_impact_overview"]["financial_exposure_summary"]["total_min"] += \
                            financial_impact.get("min_estimate_usd", 0)
                        summary_data["business_impact_overview"]["financial_exposure_summary"]["total_max"] += \
                            financial_impact.get("max_estimate_usd", 0)
                
                # Executive insights
                if "executive_summary" in agent_results:
                    exec_data = agent_results["executive_summary"]["analysis"]
                    strategic_recs = exec_data.get("strategic_recommendations", {})
                    
                    # Collect immediate actions
                    immediate_actions = strategic_recs.get("immediate_actions", [])
                    for action in immediate_actions:
                        if action not in summary_data["actionable_recommendations"]["immediate_priorities"]:
                            summary_data["actionable_recommendations"]["immediate_priorities"].append(action)
            
            # Limit and sort collections
            summary_data["threat_landscape_overview"]["dominant_threat_types"] = dict(sorted(
                summary_data["threat_landscape_overview"]["dominant_threat_types"].items(),
                key=lambda x: x[1], reverse=True
            )[:5])
            
            summary_data["threat_landscape_overview"]["primary_attack_vectors"] = dict(sorted(
                summary_data["threat_landscape_overview"]["primary_attack_vectors"].items(),
                key=lambda x: x[1], reverse=True
            )[:8])
            
            summary_data["business_impact_overview"]["high_impact_threats"] = sorted(
                summary_data["business_impact_overview"]["high_impact_threats"],
                key=lambda x: x["risk_score"], reverse=True
            )[:10]
            
            summary_data["actionable_recommendations"]["immediate_priorities"] = \
                summary_data["actionable_recommendations"]["immediate_priorities"][:10]
            
            summary_data["generated_at"] = datetime.now().isoformat()
            summary_data["threats_analyzed"] = list(threats_data.values())[:20]  # Include sample threats
            
            return summary_data
            
        except Exception as e:
            logger.error(f"Failed to get comprehensive threat intelligence summary: {e}")
            return {"error": str(e)}

    def cleanup_old_agent_results(self, days_to_keep: int = 90) -> Dict:
        """Clean up old agent analysis results to manage database size"""
        try:
            cursor = self.conn.cursor()
            cutoff_date = (datetime.now() - timedelta(days=days_to_keep)).isoformat()
            
            # Count records to be deleted
            cursor.execute("""
                SELECT COUNT(*) FROM agent_analysis 
                WHERE created_at < ?
            """, (cutoff_date,))
            
            old_agent_count = cursor.fetchone()[0]
            
            cursor.execute("""
                SELECT COUNT(*) FROM multi_agent_results 
                WHERE created_at < ?
            """, (cutoff_date,))
            
            old_workflow_count = cursor.fetchone()[0]
            
            # Delete old records
            cursor.execute("""
                DELETE FROM agent_analysis 
                WHERE created_at < ?
            """, (cutoff_date,))
            
            cursor.execute("""
                DELETE FROM multi_agent_results 
                WHERE created_at < ?
            """, (cutoff_date,))
            
            self.conn.commit()
            
            logger.info(f"🧹 Cleaned up {old_agent_count} agent results and {old_workflow_count} workflow results older than {days_to_keep} days")
            
            return {
                "cleanup_completed": True,
                "agent_records_deleted": old_agent_count,
                "workflow_records_deleted": old_workflow_count,
                "cutoff_date": cutoff_date,
                "days_kept": days_to_keep,
                "cleanup_timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to cleanup old agent results: {e}")
            return {"error": str(e), "cleanup_completed": False}

    def get_database_statistics(self) -> Dict:
        """Get database statistics for monitoring and maintenance"""
        try:
            cursor = self.conn.cursor()
            
            # Count records in each table
            cursor.execute("SELECT COUNT(*) FROM raw_threats")
            raw_threats_count = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM agent_analysis")
            agent_analysis_count = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM multi_agent_results")
            workflow_results_count = cursor.fetchone()[0]
            
            # Get date ranges
            cursor.execute("SELECT MIN(collected_at), MAX(collected_at) FROM raw_threats")
            threat_date_range = cursor.fetchone()
            
            cursor.execute("SELECT MIN(created_at), MAX(created_at) FROM agent_analysis")
            analysis_date_range = cursor.fetchone()
            
            # Get agent type distribution
            cursor.execute("""
                SELECT agent_type, COUNT(*) 
                FROM agent_analysis 
                GROUP BY agent_type 
                ORDER BY COUNT(*) DESC
            """)
            agent_type_distribution = dict(cursor.fetchall())
            
            # Get recent activity (last 7 days)
            week_ago = (datetime.now() - timedelta(days=7)).isoformat()
            cursor.execute("""
                SELECT COUNT(*) FROM raw_threats 
                WHERE collected_at > ?
            """, (week_ago,))
            recent_threats = cursor.fetchone()[0]
            
            cursor.execute("""
                SELECT COUNT(*) FROM agent_analysis 
                WHERE created_at > ?
            """, (week_ago,))
            recent_analyses = cursor.fetchone()[0]
            
            # Calculate workflow completion rates
            cursor.execute("""
                SELECT workflow_status, COUNT(*) 
                FROM multi_agent_results 
                GROUP BY workflow_status
            """)
            workflow_status_distribution = dict(cursor.fetchall())
            
            return {
                "database_overview": {
                    "total_raw_threats": raw_threats_count,
                    "total_agent_analyses": agent_analysis_count,
                    "total_workflow_results": workflow_results_count,
                    "database_size_estimate": "Not available in SQLite"
                },
                "date_ranges": {
                    "threats_date_range": {
                        "earliest": threat_date_range[0] if threat_date_range[0] else "No data",
                        "latest": threat_date_range[1] if threat_date_range[1] else "No data"
                    },
                    "analysis_date_range": {
                        "earliest": analysis_date_range[0] if analysis_date_range[0] else "No data",
                        "latest": analysis_date_range[1] if analysis_date_range[1] else "No data"
                    }
                },
                "agent_type_distribution": agent_type_distribution,
                "workflow_status_distribution": workflow_status_distribution,
                "recent_activity_7_days": {
                    "new_threats": recent_threats,
                    "new_analyses": recent_analyses,
                    "analysis_rate": round(recent_analyses / max(recent_threats, 1), 2)
                },
                "system_health_indicators": {
                    "workflow_completion_rate": round(
                        workflow_status_distribution.get("completed", 0) / 
                        max(sum(workflow_status_distribution.values()), 1) * 100, 1
                    ),
                    "average_analyses_per_threat": round(
                        agent_analysis_count / max(raw_threats_count, 1), 2
                    ),
                    "data_freshness": "current" if recent_threats > 0 else "stale"
                },
                "generated_at": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to get database statistics: {e}")
            return {"error": str(e)}

    def retry_failed_workflow(self, threat_id: int) -> Dict:
        """Retry a failed workflow for a specific threat"""
        try:
            cursor = self.conn.cursor()
            
            # Get the threat data
            cursor.execute("""
                SELECT id, title, content, source, url, collected_at
                FROM raw_threats 
                WHERE id = ?
            """, (threat_id,))
            
            threat_row = cursor.fetchone()
            if not threat_row:
                return {"error": f"Threat {threat_id} not found", "retry_successful": False}
            
            # Convert to threat data format
            threat_data = {
                "id": threat_row[0],
                "title": threat_row[1],
                "content": threat_row[2],
                "source": threat_row[3],
                "url": threat_row[4],
                "collected_at": threat_row[5]
            }
            
            # Mark previous results as retry
            cursor.execute("""
                UPDATE agent_analysis 
                SET analysis_result = json_set(analysis_result, '$.retry_marker', 'replaced_by_retry')
                WHERE raw_threat_id = ?
            """, (threat_id,))
            
            cursor.execute("""
                UPDATE multi_agent_results 
                SET workflow_status = 'retried'
                WHERE raw_threat_id = ?
            """, (threat_id,))
            
            self.conn.commit()
            
            logger.info(f"🔄 Retrying workflow for threat {threat_id}: {threat_data['title'][:50]}...")
            
            # Re-run the workflow
            result = asyncio.run(self.process_threat(threat_data))
            
            return {
                "retry_successful": True,
                "threat_id": threat_id,
                "retry_timestamp": datetime.now().isoformat(),
                "workflow_result": result
            }
            
        except Exception as e:
            logger.error(f"Failed to retry workflow for threat {threat_id}: {e}")
            return {"error": str(e), "retry_successful": False}

    def get_failed_workflows(self, days: int = 30) -> List[Dict]:
        """Get list of failed workflows that might need retry"""
        try:
            cursor = self.conn.cursor()
            time_threshold = (datetime.now() - timedelta(days=days)).isoformat()
            
            cursor.execute("""
                SELECT 
                    m.raw_threat_id,
                    r.title,
                    r.source,
                    m.workflow_status,
                    m.created_at,
                    m.processing_metadata
                FROM multi_agent_results m
                JOIN raw_threats r ON m.raw_threat_id = r.id
                WHERE m.workflow_status != 'completed'
                AND m.created_at > ?
                ORDER BY m.created_at DESC
            """, (time_threshold,))
            
            failed_workflows = []
            for row in cursor.fetchall():
                threat_id, title, source, status, created_at, metadata_json = row
                
                metadata = {}
                if metadata_json:
                    try:
                        metadata = json.loads(metadata_json)
                    except:
                        pass
                
                failed_workflows.append({
                    "threat_id": threat_id,
                    "title": title[:100],
                    "source": source,
                    "workflow_status": status,
                    "failed_at": created_at,
                    "error_summary": metadata.get("error_summary", "Unknown error"),
                    "can_retry": status in ["failed", "partial_completion"]
                })
            
            return failed_workflows
            
        except Exception as e:
            logger.error(f"Failed to get failed workflows: {e}")
            return []

    def batch_retry_failed_workflows(self, max_retries: int = 5) -> Dict:
        """Retry multiple failed workflows in batch"""
        failed_workflows = self.get_failed_workflows()
        retryable_workflows = [w for w in failed_workflows if w["can_retry"]][:max_retries]
        
        results = {
            "total_retries_attempted": len(retryable_workflows),
            "successful_retries": 0,
            "failed_retries": 0,
            "retry_details": []
        }
        
        for workflow in retryable_workflows:
            try:
                retry_result = self.retry_failed_workflow(workflow["threat_id"])
                
                if retry_result.get("retry_successful"):
                    results["successful_retries"] += 1
                else:
                    results["failed_retries"] += 1
                
                results["retry_details"].append({
                    "threat_id": workflow["threat_id"],
                    "title": workflow["title"],
                    "retry_successful": retry_result.get("retry_successful", False),
                    "error": retry_result.get("error", None)
                })
                
            except Exception as e:
                results["failed_retries"] += 1
                results["retry_details"].append({
                    "threat_id": workflow["threat_id"],
                    "title": workflow["title"],
                    "retry_successful": False,
                    "error": str(e)
                })
        
        results["batch_retry_timestamp"] = datetime.now().isoformat()
        results["success_rate"] = round(
            results["successful_retries"] / max(results["total_retries_attempted"], 1) * 100, 1
        )
        
        logger.info(f"🔄 Batch retry completed: {results['successful_retries']}/{results['total_retries_attempted']} successful")
        
        return results
    
    def get_agent_performance_metrics(self, days: int = 30) -> Dict:
        """Get detailed performance metrics for each agent"""
        try:
            cursor = self.conn.cursor()
            time_threshold = (datetime.now() - timedelta(days=days)).isoformat()
            
            cursor.execute("""
                SELECT 
                    agent_type,
                    processing_time,
                    confidence_score,
                    created_at,
                    analysis_result
                FROM agent_analysis
                WHERE created_at > ?
                ORDER BY created_at DESC
            """, (time_threshold,))
            
            results = cursor.fetchall()
            
            # Organize by agent type
            agent_metrics = {}
            
            for agent_type, proc_time, confidence, created_at, analysis_json in results:
                if agent_type not in agent_metrics:
                    agent_metrics[agent_type] = {
                        "execution_count": 0,
                        "total_processing_time": 0,
                        "processing_times": [],
                        "confidence_scores": [],
                        "error_count": 0,
                        "fallback_count": 0,
                        "daily_performance": {}
                    }
                
                metrics = agent_metrics[agent_type]
                metrics["execution_count"] += 1
                metrics["total_processing_time"] += proc_time
                metrics["processing_times"].append(proc_time)
                metrics["confidence_scores"].append(confidence)
                
                # Check for errors and fallbacks
                try:
                    analysis_data = json.loads(analysis_json)
                    if analysis_data.get("error") or analysis_data.get("error_log"):
                        metrics["error_count"] += 1
                    if analysis_data.get("fallback_mode"):
                        metrics["fallback_count"] += 1
                except:
                    metrics["error_count"] += 1
                
                # Daily breakdown
                date_key = created_at[:10]  # YYYY-MM-DD
                if date_key not in metrics["daily_performance"]:
                    metrics["daily_performance"][date_key] = {
                        "executions": 0,
                        "avg_processing_time": 0,
                        "avg_confidence": 0,
                        "errors": 0
                    }
                
                daily = metrics["daily_performance"][date_key]
                daily["executions"] += 1
                daily["avg_processing_time"] = (daily["avg_processing_time"] * (daily["executions"] - 1) + proc_time) / daily["executions"]
                daily["avg_confidence"] = (daily["avg_confidence"] * (daily["executions"] - 1) + confidence) / daily["executions"]
                if analysis_data.get("error") or analysis_data.get("fallback_mode"):
                    daily["errors"] += 1
            
            # Calculate derived metrics
            performance_summary = {}
            for agent_type, metrics in agent_metrics.items():
                processing_times = metrics["processing_times"]
                confidence_scores = metrics["confidence_scores"]
                
                performance_summary[agent_type] = {
                    "execution_statistics": {
                        "total_executions": metrics["execution_count"],
                        "error_rate": round((metrics["error_count"] / max(metrics["execution_count"], 1)) * 100, 2),
                        "fallback_rate": round((metrics["fallback_count"] / max(metrics["execution_count"], 1)) * 100, 2),
                        "success_rate": round(((metrics["execution_count"] - metrics["error_count"]) / max(metrics["execution_count"], 1)) * 100, 2)
                    },
                    "performance_metrics": {
                        "avg_processing_time": round(sum(processing_times) / len(processing_times), 2),
                        "min_processing_time": min(processing_times) if processing_times else 0,
                        "max_processing_time": max(processing_times) if processing_times else 0,
                        "median_processing_time": sorted(processing_times)[len(processing_times)//2] if processing_times else 0,
                        "processing_time_std": round(self._calculate_std_dev(processing_times), 2)
                    },
                    "quality_metrics": {
                        "avg_confidence": round(sum(confidence_scores) / len(confidence_scores), 3),
                        "min_confidence": min(confidence_scores) if confidence_scores else 0,
                        "max_confidence": max(confidence_scores) if confidence_scores else 0,
                        "confidence_std": round(self._calculate_std_dev(confidence_scores), 3)
                    },
                    "reliability_score": round(
                        (1 - (metrics["error_count"] / max(metrics["execution_count"], 1))) * 
                        (sum(confidence_scores) / max(len(confidence_scores), 1)) * 100, 1
                    ),
                    "performance_grade": self._calculate_performance_grade(
                        metrics["execution_count"],
                        metrics["error_count"],
                        processing_times,
                        confidence_scores
                    ),
                    "daily_performance": metrics["daily_performance"]
                }
            
            return {
                "analysis_period_days": days,
                "agent_performance_summary": performance_summary,
                "overall_system_performance": self._calculate_overall_system_performance(performance_summary),
                "performance_trends": self._analyze_performance_trends(agent_metrics, days),
                "optimization_recommendations": self._generate_optimization_recommendations(performance_summary),
                "generated_at": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to get agent performance metrics: {e}")
            return {"error": str(e)}

    def _calculate_std_dev(self, values: List[float]) -> float:
        """Calculate standard deviation"""
        if len(values) < 2:
            return 0.0
        
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        return variance ** 0.5

    def _calculate_performance_grade(self, executions: int, errors: int, proc_times: List[float], confidences: List[float]) -> str:
        """Calculate performance grade for an agent"""
        if executions == 0:
            return "N/A"
        
        error_rate = errors / executions
        avg_proc_time = sum(proc_times) / len(proc_times) if proc_times else 30
        avg_confidence = sum(confidences) / len(confidences) if confidences else 0.5
        
        # Scoring factors
        error_score = max(0, 100 - (error_rate * 200))  # Penalize errors heavily
        speed_score = max(0, 100 - max(0, (avg_proc_time - 5) * 2))  # Penalize slow processing
        quality_score = avg_confidence * 100
        
        overall_score = (error_score * 0.4 + speed_score * 0.3 + quality_score * 0.3)
        
        if overall_score >= 85:
            return "A"
        elif overall_score >= 70:
            return "B"
        elif overall_score >= 55:
            return "C"
        elif overall_score >= 40:
            return "D"
        else:
            return "F"

    def _calculate_overall_system_performance(self, performance_summary: Dict) -> Dict:
        """Calculate overall system performance metrics"""
        if not performance_summary:
            return {"status": "no_data"}
        
        total_executions = sum(
            agent_data["execution_statistics"]["total_executions"] 
            for agent_data in performance_summary.values()
        )
        
        weighted_error_rate = sum(
            agent_data["execution_statistics"]["error_rate"] * 
            agent_data["execution_statistics"]["total_executions"]
            for agent_data in performance_summary.values()
        ) / max(total_executions, 1)
        
        weighted_avg_processing_time = sum(
            agent_data["performance_metrics"]["avg_processing_time"] * 
            agent_data["execution_statistics"]["total_executions"]
            for agent_data in performance_summary.values()
        ) / max(total_executions, 1)
        
        weighted_avg_confidence = sum(
            agent_data["quality_metrics"]["avg_confidence"] * 
            agent_data["execution_statistics"]["total_executions"]
            for agent_data in performance_summary.values()
        ) / max(total_executions, 1)
        
        # Count performance grades
        grade_distribution = {}
        for agent_data in performance_summary.values():
            grade = agent_data["performance_grade"]
            grade_distribution[grade] = grade_distribution.get(grade, 0) + 1
        
        return {
            "overall_metrics": {
                "total_system_executions": total_executions,
                "system_error_rate": round(weighted_error_rate, 2),
                "system_avg_processing_time": round(weighted_avg_processing_time, 2),
                "system_avg_confidence": round(weighted_avg_confidence, 3)
            },
            "performance_distribution": grade_distribution,
            "system_health_status": (
                "excellent" if weighted_error_rate < 5 and weighted_avg_confidence > 0.8 else
                "good" if weighted_error_rate < 10 and weighted_avg_confidence > 0.65 else
                "fair" if weighted_error_rate < 20 and weighted_avg_confidence > 0.5 else
                "poor"
            ),
            "bottleneck_agents": [
                agent_type for agent_type, data in performance_summary.items()
                if data["performance_metrics"]["avg_processing_time"] > 20 or
                data["execution_statistics"]["error_rate"] > 15
            ],
            "top_performing_agents": [
                agent_type for agent_type, data in performance_summary.items()
                if data["performance_grade"] in ["A", "B"] and
                data["execution_statistics"]["total_executions"] > 5
            ]
        }

    def _analyze_performance_trends(self, agent_metrics: Dict, days: int) -> Dict:
        """Analyze performance trends over time"""
        trends = {}
        
        for agent_type, metrics in agent_metrics.items():
            daily_data = metrics["daily_performance"]
            
            if len(daily_data) < 3:
                trends[agent_type] = {"trend": "insufficient_data"}
                continue
            
            # Sort by date
            sorted_dates = sorted(daily_data.keys())
            recent_half = sorted_dates[len(sorted_dates)//2:]
            older_half = sorted_dates[:len(sorted_dates)//2]
            
            # Calculate averages for each period
            recent_avg_time = sum(daily_data[date]["avg_processing_time"] for date in recent_half) / len(recent_half)
            older_avg_time = sum(daily_data[date]["avg_processing_time"] for date in older_half) / len(older_half)
            
            recent_avg_confidence = sum(daily_data[date]["avg_confidence"] for date in recent_half) / len(recent_half)
            older_avg_confidence = sum(daily_data[date]["avg_confidence"] for date in older_half) / len(older_half)
            
            recent_error_rate = sum(daily_data[date]["errors"] for date in recent_half) / sum(daily_data[date]["executions"] for date in recent_half)
            older_error_rate = sum(daily_data[date]["errors"] for date in older_half) / sum(daily_data[date]["executions"] for date in older_half)
            
            trends[agent_type] = {
                "processing_time_trend": "improving" if recent_avg_time < older_avg_time * 0.9 else "degrading" if recent_avg_time > older_avg_time * 1.1 else "stable",
                "confidence_trend": "improving" if recent_avg_confidence > older_avg_confidence * 1.05 else "degrading" if recent_avg_confidence < older_avg_confidence * 0.95 else "stable",
                "error_rate_trend": "improving" if recent_error_rate < older_error_rate * 0.8 else "degrading" if recent_error_rate > older_error_rate * 1.2 else "stable",
                "overall_trend": "improving" if (recent_avg_time < older_avg_time and recent_avg_confidence > older_avg_confidence) else "degrading" if (recent_avg_time > older_avg_time or recent_avg_confidence < older_avg_confidence) else "stable"
            }
        
        return trends

    def _generate_optimization_recommendations(self, performance_summary: Dict) -> List[str]:
        """Generate optimization recommendations based on performance analysis"""
        recommendations = []
        
        for agent_type, data in performance_summary.items():
            error_rate = data["execution_statistics"]["error_rate"]
            avg_processing_time = data["performance_metrics"]["avg_processing_time"]
            avg_confidence = data["quality_metrics"]["avg_confidence"]
            grade = data["performance_grade"]
            
            if error_rate > 15:
                recommendations.append(f"🔧 {agent_type}: High error rate ({error_rate}%) - review error handling and input validation")
            
            if avg_processing_time > 20:
                recommendations.append(f"⚡ {agent_type}: Slow processing ({avg_processing_time}s) - consider prompt optimization or timeout adjustments")
            
            if avg_confidence < 0.6:
                recommendations.append(f"📊 {agent_type}: Low confidence scores ({avg_confidence:.2f}) - improve prompt engineering or data quality")
            
            if grade in ["D", "F"]:
                recommendations.append(f"🚨 {agent_type}: Poor overall performance (Grade {grade}) - requires immediate attention")
        
        # System-wide recommendations
        total_agents = len(performance_summary)
        poor_performers = len([data for data in performance_summary.values() if data["performance_grade"] in ["D", "F"]])
        
        if poor_performers / max(total_agents, 1) > 0.3:
            recommendations.append("🔄 System-wide performance issues detected - consider infrastructure review")
        
        # Add general optimization suggestions
        if not recommendations:
            recommendations.append("✅ All agents performing within acceptable ranges - monitor for maintenance opportunities")
        
        return recommendations[:8]  # Limit to top 8 recommendations
    

    def _calculate_std_dev(self, values: List[float]) -> float:
        """Calculate standard deviation"""
        if len(values) < 2:
            return 0.0
        
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        return variance ** 0.5

    def _calculate_performance_grade(self, executions: int, errors: int, proc_times: List[float], confidences: List[float]) -> str:
        """Calculate performance grade for an agent"""
        if executions == 0:
            return "N/A"
        
        error_rate = errors / executions
        avg_proc_time = sum(proc_times) / len(proc_times) if proc_times else 30
        avg_confidence = sum(confidences) / len(confidences) if confidences else 0.5
        
        # Scoring factors
        error_score = max(0, 100 - (error_rate * 200))  # Penalize errors heavily
        speed_score = max(0, 100 - max(0, (avg_proc_time - 5) * 2))  # Penalize slow processing
        quality_score = avg_confidence * 100
        
        overall_score = (error_score * 0.4 + speed_score * 0.3 + quality_score * 0.3)
        
        if overall_score >= 85:
            return "A"
        elif overall_score >= 70:
            return "B"
        elif overall_score >= 55:
            return "C"
        elif overall_score >= 40:
            return "D"
        else:
            return "F"

    def _calculate_overall_system_performance(self, performance_summary: Dict) -> Dict:
        """Calculate overall system performance metrics"""
        if not performance_summary:
            return {"status": "no_data"}
        
        total_executions = sum(
            agent_data["execution_statistics"]["total_executions"] 
            for agent_data in performance_summary.values()
        )
        
        weighted_error_rate = sum(
            agent_data["execution_statistics"]["error_rate"] * 
            agent_data["execution_statistics"]["total_executions"]
            for agent_data in performance_summary.values()
        ) / max(total_executions, 1)
        
        weighted_avg_processing_time = sum(
            agent_data["performance_metrics"]["avg_processing_time"] * 
            agent_data["execution_statistics"]["total_executions"]
            for agent_data in performance_summary.values()
        ) / max(total_executions, 1)
        
        weighted_avg_confidence = sum(
            agent_data["quality_metrics"]["avg_confidence"] * 
            agent_data["execution_statistics"]["total_executions"]
            for agent_data in performance_summary.values()
        ) / max(total_executions, 1)
        
        # Count performance grades
        grade_distribution = {}
        for agent_data in performance_summary.values():
            grade = agent_data["performance_grade"]
            grade_distribution[grade] = grade_distribution.get(grade, 0) + 1
        
        return {
            "overall_metrics": {
                "total_system_executions": total_executions,
                "system_error_rate": round(weighted_error_rate, 2),
                "system_avg_processing_time": round(weighted_avg_processing_time, 2),
                "system_avg_confidence": round(weighted_avg_confidence, 3)
            },
            "performance_distribution": grade_distribution,
            "system_health_status": (
                "excellent" if weighted_error_rate < 5 and weighted_avg_confidence > 0.8 else
                "good" if weighted_error_rate < 10 and weighted_avg_confidence > 0.65 else
                "fair" if weighted_error_rate < 20 and weighted_avg_confidence > 0.5 else
                "poor"
            ),
            "bottleneck_agents": [
                agent_type for agent_type, data in performance_summary.items()
                if data["performance_metrics"]["avg_processing_time"] > 20 or
                data["execution_statistics"]["error_rate"] > 15
            ],
            "top_performing_agents": [
                agent_type for agent_type, data in performance_summary.items()
                if data["performance_grade"] in ["A", "B"] and
                data["execution_statistics"]["total_executions"] > 5
            ]
        }

    def _analyze_performance_trends(self, agent_metrics: Dict, days: int) -> Dict:
        """Analyze performance trends over time"""
        trends = {}
        
        for agent_type, metrics in agent_metrics.items():
            daily_data = metrics["daily_performance"]
            
            if len(daily_data) < 3:
                trends[agent_type] = {"trend": "insufficient_data"}
                continue
            
            # Sort by date
            sorted_dates = sorted(daily_data.keys())
            recent_half = sorted_dates[len(sorted_dates)//2:]
            older_half = sorted_dates[:len(sorted_dates)//2]
            
            # Calculate averages for each period
            recent_avg_time = sum(daily_data[date]["avg_processing_time"] for date in recent_half) / len(recent_half)
            older_avg_time = sum(daily_data[date]["avg_processing_time"] for date in older_half) / len(older_half)
            
            recent_avg_confidence = sum(daily_data[date]["avg_confidence"] for date in recent_half) / len(recent_half)
            older_avg_confidence = sum(daily_data[date]["avg_confidence"] for date in older_half) / len(older_half)
            
            recent_error_rate = sum(daily_data[date]["errors"] for date in recent_half) / sum(daily_data[date]["executions"] for date in recent_half)
            older_error_rate = sum(daily_data[date]["errors"] for date in older_half) / sum(daily_data[date]["executions"] for date in older_half)
            
            trends[agent_type] = {
                "processing_time_trend": "improving" if recent_avg_time < older_avg_time * 0.9 else "degrading" if recent_avg_time > older_avg_time * 1.1 else "stable",
                "confidence_trend": "improving" if recent_avg_confidence > older_avg_confidence * 1.05 else "degrading" if recent_avg_confidence < older_avg_confidence * 0.95 else "stable",
                "error_rate_trend": "improving" if recent_error_rate < older_error_rate * 0.8 else "degrading" if recent_error_rate > older_error_rate * 1.2 else "stable",
                "overall_trend": "improving" if (recent_avg_time < older_avg_time and recent_avg_confidence > older_avg_confidence) else "degrading" if (recent_avg_time > older_avg_time or recent_avg_confidence < older_avg_confidence) else "stable"
            }
        
        return trends

    def _generate_optimization_recommendations(self, performance_summary: Dict) -> List[str]:
        """Generate optimization recommendations based on performance analysis"""
        recommendations = []
        
        for agent_type, data in performance_summary.items():
            error_rate = data["execution_statistics"]["error_rate"]
            avg_processing_time = data["performance_metrics"]["avg_processing_time"]
            avg_confidence = data["quality_metrics"]["avg_confidence"]
            grade = data["performance_grade"]
            
            if error_rate > 15:
                recommendations.append(f"🔧 {agent_type}: High error rate ({error_rate}%) - review error handling and input validation")
            
            if avg_processing_time > 20:
                recommendations.append(f"⚡ {agent_type}: Slow processing ({avg_processing_time}s) - consider prompt optimization or timeout adjustments")
            
            if avg_confidence < 0.6:
                recommendations.append(f"📊 {agent_type}: Low confidence scores ({avg_confidence:.2f}) - improve prompt engineering or data quality")
            
            if grade in ["D", "F"]:
                recommendations.append(f"🚨 {agent_type}: Poor overall performance (Grade {grade}) - requires immediate attention")
        
        # System-wide recommendations
        total_agents = len(performance_summary)
        poor_performers = len([data for data in performance_summary.values() if data["performance_grade"] in ["D", "F"]])
        
        if poor_performers / max(total_agents, 1) > 0.3:
            recommendations.append("🔄 System-wide performance issues detected - consider infrastructure review")
        
        # Add general optimization suggestions
        if not recommendations:
            recommendations.append("✅ All agents performing within acceptable ranges - monitor for maintenance opportunities")
        
        return recommendations[:8]  # Limit to top 8 recommendations
    
    def get_system_health_report(self) -> Dict:
        """Get comprehensive system health report"""
        try:
            # Get various health metrics
            db_stats = self.get_database_statistics()
            performance_metrics = self.get_agent_performance_metrics(days=7)
            failed_workflows = self.get_failed_workflows(days=7)
            
            # Recent activity analysis
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT COUNT(*) FROM raw_threats 
                WHERE collected_at > datetime('now', '-24 hours')
            """)
            threats_24h = cursor.fetchone()[0]
            
            cursor.execute("""
                SELECT COUNT(*) FROM agent_analysis 
                WHERE created_at > datetime('now', '-24 hours')
            """)
            analyses_24h = cursor.fetchone()[0]
            
            cursor.execute("""
                SELECT COUNT(*) FROM multi_agent_results 
                WHERE created_at > datetime('now', '-24 hours')
                AND workflow_status = 'completed'
            """)
            completed_workflows_24h = cursor.fetchone()[0]

                        # Calculate health scores
            health_indicators = {
                "database_health": self._assess_database_health(db_stats),
                "agent_performance_health": self._assess_agent_performance_health(performance_metrics),
                "workflow_health": self._assess_workflow_health(failed_workflows, threats_24h, completed_workflows_24h),
                "data_freshness_health": self._assess_data_freshness_health(threats_24h, analyses_24h)
            }
            
            # Overall system health score
            health_scores = [h["score"] for h in health_indicators.values() if "score" in h]
            overall_health_score = sum(health_scores) / len(health_scores) if health_scores else 0
            
            # Generate health status
            if overall_health_score >= 85:
                overall_status = "🟢 HEALTHY"
                status_level = "healthy"
            elif overall_health_score >= 70:
                overall_status = "🟡 FAIR"
                status_level = "fair"
            elif overall_health_score >= 50:
                overall_status = "🟠 DEGRADED"
                status_level = "degraded"
            else:
                overall_status = "🔴 CRITICAL"
                status_level = "critical"

                        # Collect all alerts and recommendations
            all_alerts = []
            all_recommendations = []
            
            for indicator_name, indicator_data in health_indicators.items():
                all_alerts.extend(indicator_data.get("alerts", []))
                all_recommendations.extend(indicator_data.get("recommendations", []))
            
            # Priority alerts (critical issues)
            priority_alerts = [alert for alert in all_alerts if "🔴" in alert or "CRITICAL" in alert.upper()]
            
            return {
                "system_health_overview": {
                    "overall_status": overall_status,
                    "overall_health_score": round(overall_health_score, 1),
                    "status_level": status_level,
                    "assessment_timestamp": datetime.now().isoformat()
                },
                "health_indicators": health_indicators,
                "recent_activity_24h": {
                    "new_threats": threats_24h,
                    "analyses_completed": analyses_24h,
                    "workflows_completed": completed_workflows_24h,
                    "processing_rate": round(analyses_24h / max(threats_24h, 1), 2)
                },
                "system_alerts": {
                    "priority_alerts": priority_alerts,
                    "all_alerts": all_alerts[:15],  # Limit display
                    "total_alert_count": len(all_alerts)
                },
                "recommendations": {
                    "immediate_actions": [r for r in all_recommendations if "immediate" in r.lower() or "🚨" in r][:5],
                    "maintenance_suggestions": [r for r in all_recommendations if "maintenance" in r.lower() or "optimize" in r.lower()][:5],
                    "all_recommendations": all_recommendations[:10]
                },
                "system_metrics_summary": {
                    "database_record_count": db_stats.get("database_overview", {}).get("total_raw_threats", 0),
                    "agent_types_active": len(performance_metrics.get("agent_performance_summary", {})),
                    "failed_workflows_count": len(failed_workflows),
                    "system_uptime_indicator": "operational" if threats_24h > 0 else "idle"
                },
                "next_health_check_recommended": (datetime.now() + timedelta(hours=24 if status_level == "healthy" else 12 if status_level == "fair" else 6)).isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to generate system health report: {e}")
            return {
                "system_health_overview": {
                    "overall_status": "🔴 HEALTH CHECK FAILED",
                    "status_level": "error",
                    "error": str(e)
                },
                "error_details": str(e),
                "assessment_timestamp": datetime.now().isoformat()
            }


    def _assess_database_health(self, db_stats: Dict) -> Dict:
        """Assess database health indicators"""
        if "error" in db_stats:
            return {
                "score": 0,
                "status": "🔴 DATABASE ERROR",
                "alerts": [f"🔴 Database connectivity issues: {db_stats['error']}"],
                "recommendations": ["🚨 Immediate database troubleshooting required"]
            }
        
        overview = db_stats.get("database_overview", {})
        recent_activity = db_stats.get("recent_activity_7_days", {})
        
        total_threats = overview.get("total_raw_threats", 0)
        total_analyses = overview.get("total_agent_analyses", 0)
        recent_threats = recent_activity.get("new_threats", 0)
        analysis_rate = recent_activity.get("analysis_rate", 0)
        
        score = 100
        alerts = []
        recommendations = []
        
        # Check data volume
        if total_threats == 0:
            score -= 30
            alerts.append("🟡 No threat data in database")
            recommendations.append("Import threat intelligence data")
        elif total_threats < 10:
            score -= 15
            alerts.append("🟡 Low threat data volume")
        
        # Check analysis coverage
        if total_threats > 0 and analysis_rate < 0.5:
            score -= 20
            alerts.append("🟠 Low analysis coverage - many threats unprocessed")
            recommendations.append("Review agent processing capacity")
        
        # Check recent activity
        if recent_threats == 0:
            score -= 15
            alerts.append("🟡 No recent threat data ingestion")
            recommendations.append("Check data collection pipelines")
        
        # Database size considerations
        if total_threats > 10000:
            recommendations.append("Consider database cleanup for old records")
        
        status = "🟢 HEALTHY" if score >= 80 else "🟡 FAIR" if score >= 60 else "🟠 DEGRADED"
        
        return {
            "score": max(0, score),
            "status": status,
            "alerts": alerts,
            "recommendations": recommendations,
            "metrics": {
                "total_threats": total_threats,
                "total_analyses": total_analyses,
                "recent_activity": recent_threats,
                "analysis_coverage": round(analysis_rate * 100, 1)
            }
        }
    
    def _assess_agent_performance_health(self, performance_metrics: Dict) -> Dict:
        """Assess agent performance health"""
        if "error" in performance_metrics:
            return {
                "score": 0,
                "status": "🔴 PERFORMANCE CHECK FAILED",
                "alerts": [f"🔴 Unable to assess agent performance: {performance_metrics['error']}"],
                "recommendations": ["🚨 Investigate performance monitoring system"]
            }
        
        agent_summary = performance_metrics.get("agent_performance_summary", {})
        system_performance = performance_metrics.get("overall_system_performance", {})
        
        if not agent_summary:
            return {
                "score": 50,
                "status": "🟡 NO PERFORMANCE DATA",
                "alerts": ["🟡 No recent agent performance data available"],
                "recommendations": ["Run agents to generate performance metrics"]
            }
        
        score = 100
        alerts = []
        recommendations = []
        
        # Check overall system performance
        system_error_rate = system_performance.get("overall_metrics", {}).get("system_error_rate", 0)
        system_confidence = system_performance.get("overall_metrics", {}).get("system_avg_confidence", 0.5)
        
        if system_error_rate > 20:
            score -= 30
            alerts.append(f"🔴 High system error rate: {system_error_rate}%")
            recommendations.append("🚨 Immediate agent debugging required")
        elif system_error_rate > 10:
            score -= 15
            alerts.append(f"🟠 Elevated error rate: {system_error_rate}%")
            recommendations.append("Review agent error patterns")
        
        if system_confidence < 0.5:
            score -= 20
            alerts.append(f"🟠 Low system confidence: {system_confidence:.2f}")
            recommendations.append("Improve agent prompt engineering")
        
        # Check individual agent performance
        poor_performers = 0
        excellent_performers = 0
        
        for agent_type, agent_data in agent_summary.items():
            grade = agent_data.get("performance_grade", "F")
            error_rate = agent_data.get("execution_statistics", {}).get("error_rate", 100)
            
            if grade in ["D", "F"]:
                poor_performers += 1
                alerts.append(f"🔴 {agent_type}: Poor performance (Grade {grade})")
            elif grade == "A":
                excellent_performers += 1
        
        if poor_performers > len(agent_summary) * 0.3:
            score -= 25
            recommendations.append("🚨 Multiple agents underperforming - system review needed")
        
        # Performance trends
        trends = performance_metrics.get("performance_trends", {})
        degrading_agents = [agent for agent, trend in trends.items() 
                          if trend.get("overall_trend") == "degrading"]
        
        if len(degrading_agents) > 1:
            score -= 10
            alerts.append(f"🟡 Performance degradation detected in: {', '.join(degrading_agents)}")
            recommendations.append("Monitor degrading agents closely")
        
        status = "🟢 HEALTHY" if score >= 85 else "🟡 FAIR" if score >= 70 else "🟠 DEGRADED" if score >= 50 else "🔴 CRITICAL"
        
        return {
            "score": max(0, score),
            "status": status,
            "alerts": alerts,
            "recommendations": recommendations,
            "metrics": {
                "system_error_rate": system_error_rate,
                "system_confidence": system_confidence,
                "poor_performers": poor_performers,
                "excellent_performers": excellent_performers,
                "total_agents": len(agent_summary)
            }
        }

    def _assess_workflow_health(self, failed_workflows: List[Dict], threats_24h: int, completed_workflows_24h: int) -> Dict:
        """Assess workflow execution health"""
        score = 100
        alerts = []
        recommendations = []
        
        failed_count = len(failed_workflows)
        total_workflows_24h = threats_24h  # Assuming one workflow per threat
        completion_rate = completed_workflows_24h / max(total_workflows_24h, 1) * 100 if total_workflows_24h > 0 else 0
        
        # Check failure rate
        if failed_count > 0:
            recent_failures = len([w for w in failed_workflows if 
                                 datetime.fromisoformat(w["failed_at"]) > datetime.now() - timedelta(hours=24)])
            
            if recent_failures > 3:
                score -= 25
                alerts.append(f"🔴 {recent_failures} workflow failures in last 24 hours")
                recommendations.append("🚨 Investigate workflow failure patterns")
            elif recent_failures > 0:
                score -= 10
                alerts.append(f"🟡 {recent_failures} workflow failures in last 24 hours")
        
        # Check completion rate
        if completion_rate < 70:
            score -= 20
            alerts.append(f"🟠 Low workflow completion rate: {completion_rate:.1f}%")
            recommendations.append("Review workflow execution capacity")
        elif completion_rate < 85:
            score -= 10
            alerts.append(f"🟡 Moderate workflow completion rate: {completion_rate:.1f}%")
        
        # Check processing backlog
        if threats_24h > completed_workflows_24h * 2:
            score -= 15
            alerts.append("🟠 Processing backlog detected")
            recommendations.append("Consider scaling agent processing")
        
        status = "🟢 HEALTHY" if score >= 80 else "🟡 FAIR" if score >= 60 else "🟠 DEGRADED"
        
        return {
            "score": max(0, score),
            "status": status,
            "alerts": alerts,
            "recommendations": recommendations,
            "metrics": {
                "failed_workflows": failed_count,
                "completion_rate": round(completion_rate, 1),
                "workflows_completed_24h": completed_workflows_24h,
                "threats_processed_24h": threats_24h
            }
        }

    def _assess_data_freshness_health(self, threats_24h: int, analyses_24h: int) -> Dict:
        """Assess data freshness and processing currency"""
        score = 100
        alerts = []
        recommendations = []
        
        # Check threat data ingestion
        if threats_24h == 0:
            score -= 30
            alerts.append("🟠 No new threat data in last 24 hours")
            recommendations.append("Check threat data collection sources")
        elif threats_24h < 5:
            score -= 15
            alerts.append("🟡 Low threat data ingestion rate")
        
        # Check analysis processing
        if analyses_24h == 0:
            score -= 25
            alerts.append("🟠 No threat analyses completed in last 24 hours")
            recommendations.append("Check agent processing pipeline")
        
        # Check processing lag
        processing_ratio = analyses_24h / max(threats_24h, 1)
        if threats_24h > 0 and processing_ratio < 0.5:
            score -= 20
            alerts.append("🟠 Analysis processing lagging behind threat ingestion")
            recommendations.append("Increase analysis processing capacity")
        
        status = "🟢 HEALTHY" if score >= 80 else "🟡 FAIR" if score >= 60 else "🟠 DEGRADED"
        
        return {
            "score": max(0, score),
            "status": status,
            "alerts": alerts,
            "recommendations": recommendations,
            "metrics": {
                "threats_24h": threats_24h,
                "analyses_24h": analyses_24h,
                "processing_ratio": round(processing_ratio, 2)
            }
        }

    async def _executive_summary_agent(self, state: ThreatProcessingState) -> ThreatProcessingState:
        """
        Agent 5: Executive Summary Agent
        Creates executive-level summaries and strategic recommendations
        """
        logger.info("📋 Executive Summary Agent processing...")
        start_time = datetime.now()
        
        try:
            raw_threat = state["raw_threat"]
            source_analysis = state.get("source_analysis", {})
            mitre_mapping = state.get("mitre_mapping", {})
            impact_assessment = state.get("impact_assessment", {})
            geospatial_intel = state.get("geospatial_intelligence", {})
            
            # Extract key data for summary
            title = raw_threat.get('title', '')
            source = raw_threat.get('source', 'unknown')
            
            # Key metrics extraction
            credibility_score = source_analysis.get('credibility_score', 50)
            risk_score = impact_assessment.get("business_impact_assessment", {}).get("overall_risk_score", 50)
            risk_level = impact_assessment.get("business_impact_assessment", {}).get("risk_level", "medium")
            threat_type = mitre_mapping.get("threat_categorization", {}).get("threat_type", "unknown")
            
            # Financial impact
            financial_impact = impact_assessment.get("business_impact_assessment", {}).get("potential_financial_impact", {})
            max_financial_impact = financial_impact.get("max_estimate_usd", 0)
            
            # Geographic context
            origin_countries = geospatial_intel.get("geographic_origin_analysis", {}).get("likely_origin_countries", [])
            origin_summary = ", ".join([c.get("country", "Unknown") for c in origin_countries[:3]])
            
            # MITRE techniques
            techniques = mitre_mapping.get("techniques", [])
            key_techniques = [f"{t.get('id', 'unknown')}: {t.get('name', 'Unknown')}" for t in techniques[:3]]
            
            prompt = f"""
            You are a cybersecurity executive advisor creating strategic threat briefings for C-suite leadership.
            
            Create an executive summary for this threat intelligence:
            
            THREAT: {title}
            SOURCE: {source} (Credibility: {credibility_score}/100)
            THREAT TYPE: {threat_type}
            RISK LEVEL: {risk_level} (Score: {risk_score}/100)
            MAX FINANCIAL IMPACT: ${max_financial_impact:,}
            LIKELY ORIGINS: {origin_summary or "Unknown"}
            KEY ATTACK METHODS: {', '.join(key_techniques) if key_techniques else "Under analysis"}
            
            Provide an executive summary in this EXACT JSON format:
            {{
                "executive_summary": {{
                    "threat_headline": "Concise, impactful headline for executives",
                    "severity_assessment": "critical|high|medium|low",
                    "business_impact_summary": "2-3 sentence summary of business impact",
                    "key_findings": [
                        "Finding 1: Specific actionable insight",
                        "Finding 2: Another key insight",
                        "Finding 3: Third critical insight"
                    ],
                    "strategic_implications": {{
                        "immediate_concerns": [
                            "Concern 1",
                            "Concern 2"
                        ],
                        "medium_term_risks": [
                            "Risk 1",
                            "Risk 2"
                        ],
                        "competitive_implications": "How this might affect competitive position",
                        "regulatory_considerations": "Regulatory or compliance implications"
                    }}
                }},
                "recommendation_framework": {{
                    "immediate_actions": {{
                        "priority_1": {{
                            "action": "Highest priority action",
                            "rationale": "Why this is critical",
                            "timeline": "Immediate|24 hours|This week",
                            "resources_required": "Brief resource description",
                            "success_criteria": "How to measure success"
                        }},
                        "priority_2": {{
                            "action": "Second priority action",
                            "rationale": "Why this matters",
                            "timeline": "24-72 hours|This week",
                            "resources_required": "Resource requirements",
                            "success_criteria": "Success measurement"
                        }}
                    }},
                    "strategic_investments": [
                        {{
                            "investment_area": "Technology|Process|People|Partnerships",
                            "description": "What to invest in",
                            "business_justification": "Why this investment is needed",
                            "estimated_timeline": "Timeline for implementation",
                            "expected_roi": "Expected return or risk reduction"
                        }}
                    ],
                    "risk_mitigation_strategy": {{
                        "defensive_measures": [
                            "Specific defensive action 1",
                            "Specific defensive action 2"
                        ],
                        "detection_improvements": [
                            "Detection capability 1",
                            "Detection capability 2"
                        ],
                        "response_preparedness": [
                            "Response preparation 1",
                            "Response preparation 2"
                        ]
                    }}
                }},
                "communication_guidance": {{
                    "stakeholder_notifications": {{
                        "board_of_directors": {{
                            "notify": true,
                            "key_message": "Main message for board",
                            "urgency": "immediate|scheduled|next_meeting"
                        }},
                        "customers": {{
                            "notify": true,
                            "communication_type": "proactive|reactive|none",
                            "key_message": "Customer communication message"
                        }},
                        "employees": {{
                            "notify": true,
                            "communication_scope": "all_staff|security_team|it_department|executives",
                            "key_message": "Employee communication message"
                        }},
                        "regulators": {{
                            "notify": false,
                            "trigger_conditions": "When to notify regulators",
                            "required_timeline": "Regulatory notification timeline"
                        }}
                    }},
                    "media_strategy": {{
                        "proactive_disclosure": false,
                        "prepared_statements": "If media inquiries arise...",
                        "spokesperson_guidance": "Who should speak and key messages"
                    }}
                }},
                "success_metrics": {{
                    "short_term_kpis": [
                        {{
                            "metric": "Incident response time",
                            "target": "< 4 hours",
                            "measurement_method": "How to measure"
                        }},
                        {{
                            "metric": "System availability",
                            "target": "> 99.5%",
                            "measurement_method": "Monitoring tools"
                        }}
                    ],
                    "long_term_objectives": [
                        {{
                            "objective": "Enhanced threat detection",
                            "timeline": "6 months",
                            "success_criteria": "Specific criteria"
                        }}
                    ],
                    "risk_reduction_targets": {{
                        "current_risk_level": "{risk_level}",
                        "target_risk_level": "lower level",
                        "timeline_to_achieve": "3-6 months",
                        "investment_required": "Estimated investment"
                    }}
                }},
                "confidence_and_assumptions": {{
                    "summary_confidence": 0.85,
                    "key_assumptions": [
                        "Assumption 1 about threat actor",
                        "Assumption 2 about attack methods"
                    ],
                    "information_gaps": [
                        "Gap 1: What we don't know",
                        "Gap 2: Additional intelligence needed"
                    ],
                    "recommendation_caveats": [
                        "Caveat 1: Limitation in recommendations",
                        "Caveat 2: Uncertainty factor"
                    ]
                }}
            }}
            
            Guidelines for executive communication:
            1. Focus on business impact and strategic implications
            2. Provide clear, actionable recommendations
            3. Use business language, not technical jargon
            4. Emphasize risk management and competitive advantage
            5. Include resource and timeline considerations
            6. Address stakeholder communication needs
            
            Respond with ONLY the JSON object, no additional text.
            """
            
            # Query LLM for executive summary
            response = await self._query_llm_async(prompt)
            executive_summary = self._parse_json_response(response)
            
            # Validate and enhance the executive summary
            executive_summary = self._validate_executive_summary(executive_summary, threat_type, risk_level, max_financial_impact)
            
            # Calculate processing time
            processing_time = (datetime.now() - start_time).total_seconds()
            
            # Store individual agent result
            await self._store_individual_agent_result(
                raw_threat.get('id'), 
                'executive_summary', 
                executive_summary, 
                processing_time
            )
            
            # Update state
            state["executive_summary"] = executive_summary
            state["current_agent"] = "summarizer"
            state["processing_metadata"]["executive_summary_time"] = processing_time
            
            # Log results
            headline = executive_summary.get("executive_summary", {}).get("threat_headline", "Summary generated")
            severity = executive_summary.get("executive_summary", {}).get("severity_assessment", "unknown")
            confidence = executive_summary.get("confidence_and_assumptions", {}).get("summary_confidence", 0.5)
            
            logger.info(f"✅ Executive summary completed - Severity: {severity}, Confidence: {confidence:.2f}")
            logger.info(f"📋 Headline: {headline[:100]}...")
            
        except Exception as e:
            error_msg = f"Executive summary failed: {str(e)}"
            logger.error(f"❌ {error_msg}")
            state["error_log"].append(error_msg)
            
            # Provide fallback executive summary
            state["executive_summary"] = self._fallback_executive_summary(threat_type, risk_level, max_financial_impact)
            state["current_agent"] = "summarizer"
            state["processing_metadata"]["executive_summary_time"] = (datetime.now() - start_time).total_seconds()
        
        return state

    def cleanup_old_data(self, days_to_keep: int = 90) -> Dict:
        """Clean up old data from database"""
        try:
            cursor = self.conn.cursor()
            cutoff_date = (datetime.now() - timedelta(days=days_to_keep)).isoformat()
            
            # Count records to be deleted
            cursor.execute("SELECT COUNT(*) FROM raw_threats WHERE collected_at < ?", (cutoff_date,))
            old_threats = cursor.fetchone()[0]
            
            cursor.execute("""
                SELECT COUNT(*) FROM agent_analysis 
                WHERE created_at < ?
            """, (cutoff_date,))
            old_analyses = cursor.fetchone()[0]
            
            cursor.execute("""
                SELECT COUNT(*) FROM multi_agent_results 
                WHERE created_at < ?
            """, (cutoff_date,))
            old_results = cursor.fetchone()[0]
            
            if old_threats == 0 and old_analyses == 0 and old_results == 0:
                return {
                    "cleanup_performed": False,
                    "reason": "No old data found to cleanup",
                    "cutoff_date": cutoff_date
                }
            
            # Perform cleanup
            cursor.execute("DELETE FROM agent_analysis WHERE created_at < ?", (cutoff_date,))
            deleted_analyses = cursor.rowcount
            
            cursor.execute("DELETE FROM multi_agent_results WHERE created_at < ?", (cutoff_date,))
            deleted_results = cursor.rowcount
            
            cursor.execute("DELETE FROM raw_threats WHERE collected_at < ?", (cutoff_date,))
            deleted_threats = cursor.rowcount
            
            self.conn.commit()
            
            return {
                "cleanup_performed": True,
                "cutoff_date": cutoff_date,
                "records_deleted": {
                    "threats": deleted_threats,
                    "analyses": deleted_analyses,
                    "results": deleted_results,
                    "total": deleted_threats + deleted_analyses + deleted_results
                },
                "cleanup_timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Cleanup failed: {e}")
            return {"cleanup_performed": False, "error": str(e)}

    def get_workflow_status(self, workflow_id: str) -> Optional[Dict]:
        """Get status of a specific workflow"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT 
                    workflow_status,
                    overall_confidence,
                    final_analysis,
                    processing_metadata,
                    created_at
                FROM multi_agent_results 
                WHERE json_extract(processing_metadata, '$.workflow_id') = ?
                ORDER BY created_at DESC
                LIMIT 1
            """, (workflow_id,))
            
            result = cursor.fetchone()
            if result:
                return {
                    "workflow_id": workflow_id,
                    "status": result[0],
                    "confidence": result[1],
                    "final_analysis": json.loads(result[2]) if result[2] else None,
                    "metadata": json.loads(result[3]) if result[3] else {},
                    "created_at": result[4]
                }
            return None
            
        except Exception as e:
            logger.error(f"Failed to get workflow status: {e}")
            return None

    def __del__(self):
        """Cleanup database connection on object destruction"""
        try:
            if hasattr(self, 'conn') and self.conn:
                self.conn.close()
                logger.info("🔒 Database connection closed")
        except:
            pass  # Ignore errors during cleanup

    





# Test function
async def test_orchestrator():
    """Test the orchestrator with sample data"""
    orchestrator = ThreatAgentOrchestrator()
    
    sample_threat = {
        "id": 999,
        "title": "Critical Ransomware Campaign Targeting Transportation Companies",
        "content": "Security researchers have identified a new ransomware campaign specifically targeting logistics and transportation companies worldwide...",
        "source": "security-vendor-blog.com",
        "url": "https://example.com/threat-report"
    }
    
    result = await orchestrator.process_threat(sample_threat)
    print("🧪 Test completed:", json.dumps(result, indent=2, default=str)[:500])


    


if __name__ == "__main__":
    asyncio.run(test_orchestrator())