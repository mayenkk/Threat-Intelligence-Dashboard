#!/usr/bin/env python3
"""
AI-Powered Threat Intelligence Analyzer
Uses Google Vertex AI for advanced threat analysis
"""

import asyncio
import json
import re
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Union
import logging
import hashlib

# Vertex AI imports
import vertexai
from vertexai.generative_models import GenerativeModel, SafetySetting, HarmCategory
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ThreatAIAnalyzer:
    """
    AI-powered threat intelligence analyzer using Google Vertex AI
    """
    
    def __init__(self, model_name: str = "gemini-2.5-flash"):
        """
        Initialize the AI analyzer with Vertex AI
        
        Args:
            model_name: Vertex AI model to use
        """
        self.model_name = model_name
        self.project_id = "itd-ai-interns"
        self.region = "us-central1"
        
        # Initialize Vertex AI
        self._init_vertex_ai()
        
        # Initialize database connection
        self.conn = sqlite3.connect('../data/threats.db', check_same_thread=False)
        self._init_analysis_tables()
        
        logger.info(f"✅ ThreatAIAnalyzer initialized with Vertex AI model: {model_name}")
    
    def _init_vertex_ai(self):
        """Initialize Vertex AI connection"""
        try:
            # Set environment variables
            os.environ['GOOGLE_CLOUD_LOCATION'] = self.region
            os.environ['GOOGLE_GENAI_USE_VERTEXAI'] = 'True'
            os.environ['GOOGLE_CLOUD_PROJECT'] = self.project_id
            
            # Initialize Vertex AI
            vertexai.init(project=self.project_id, location=self.region)
            
            # Test connection with a simple query
            test_model = GenerativeModel(self.model_name)
            test_response = test_model.generate_content("Test connection")
            
            logger.info("✅ Vertex AI connection established successfully")
            
        except Exception as e:
            logger.error(f"❌ Vertex AI initialization failed: {e}")
            logger.info("💡 Make sure you're authenticated: gcloud auth application-default login")
            raise
    
    def _init_analysis_tables(self):
        """Initialize analysis tables in database"""
        cursor = self.conn.cursor()
        
        # Create processed threats table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS processed_threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                raw_threat_id INTEGER,
                threat_name TEXT,
                threat_type TEXT,
                severity TEXT,
                targeted_countries TEXT,
                targeted_industries TEXT,
                threat_actors TEXT,
                attack_vectors TEXT,
                iocs TEXT,
                latitude REAL,
                longitude REAL,
                confidence_score REAL,
                analysis_timestamp TEXT,
                logistics_impact_score INTEGER,
                supply_chain_risk TEXT,
                mitigation_recommendations TEXT,
                analysis_model TEXT,
                content_hash TEXT,
                geographic_focus TEXT,
                mitigation_priority TEXT,
                logistics_relevance_score INTEGER,
                FOREIGN KEY (raw_threat_id) REFERENCES raw_threats (id)
            )
        ''')
        
        # Create analysis sessions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS analysis_sessions (
                session_id TEXT PRIMARY KEY,
                start_time TEXT,
                end_time TEXT,
                threats_analyzed INTEGER DEFAULT 0,
                model_used TEXT,
                avg_confidence_score REAL,
                session_status TEXT DEFAULT 'active',
                total_analysis_time REAL DEFAULT 0
            )
        ''')
        
        # Create analysis performance metrics
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS analysis_metrics (
                metric_id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                analysis_time_seconds REAL,
                model_response_time REAL,
                confidence_score REAL,
                threat_complexity_score INTEGER,
                analysis_success BOOLEAN,
                model_used TEXT,
                logistics_relevance INTEGER
            )
        ''')
        
        self.conn.commit()
        logger.info("✅ Analysis database tables initialized")
    
    async def analyze_threat(self, threat_data: Dict) -> Dict:
        """
        Analyze a single threat using Vertex AI
        
        Args:
            threat_data: Dictionary containing threat information
            
        Returns:
            Dictionary with comprehensive analysis results
        """
        analysis_start = datetime.now()
        
        try:
            # Generate content hash to avoid re-analyzing same content
            content_hash = self._generate_content_hash(threat_data)
            
            # Check if already analyzed
            existing_analysis = self._get_existing_analysis(content_hash)
            if existing_analysis:
                logger.info(f"📋 Using cached analysis for threat: {threat_data.get('title', 'Unknown')[:50]}")
                return existing_analysis
            
            # Prepare analysis prompt
            analysis_prompt = self._create_analysis_prompt(threat_data)
            
            # Call Vertex AI
            ai_response = await self._query_vertex_ai(analysis_prompt)
            
            # Parse AI response
            analysis_result = self._parse_ai_response(ai_response, threat_data)
            
            # Add logistics-specific analysis
            analysis_result = self._enhance_logistics_analysis(analysis_result, threat_data)
            
            # Save analysis to database
            self._save_analysis(threat_data, analysis_result, content_hash)
            
            # Record performance metrics
            analysis_time = (datetime.now() - analysis_start).total_seconds()
            self._record_analysis_metrics(analysis_time, analysis_result)
            
            logger.info(f"✅ Analyzed threat: {threat_data.get('title', 'Unknown')[:50]} (confidence: {analysis_result.get('confidence_score', 0):.1f}%)")
            
            return analysis_result
            
        except Exception as e:
            logger.error(f"❌ Threat analysis failed: {e}")
            return self._create_fallback_analysis(threat_data)
    
    def _create_analysis_prompt(self, threat_data: Dict) -> str:
        """Create structured prompt for Vertex AI analysis"""
        
        title = threat_data.get('title', '')
        content = threat_data.get('content', '')[:3000]  # Vertex AI can handle more content
        source = threat_data.get('source', '')
        
        prompt = f"""
You are an expert cybersecurity threat intelligence analyst specializing in logistics and supply chain security for a global logistics company. 

Analyze this cybersecurity threat report and provide comprehensive structured intelligence:

THREAT TITLE: {title}

THREAT CONTENT: {content}

SOURCE: {source}

Your analysis must be precise and actionable. Provide your response in this exact JSON format:

{{
    "threat_name": "Specific descriptive name for this threat",
    "threat_type": "One of: malware, vulnerability, data_breach, apt_campaign, ransomware, phishing, ddos, supply_chain_attack, iot_compromise, zero_day, insider_threat",
    "severity": "One of: critical, high, medium, low",
    "targeted_countries": ["ISO country codes like US, CN, DE, GB"],
    "targeted_industries": ["specific industries mentioned or logically targeted"],
    "threat_actors": ["specific threat groups, APTs, or criminal organizations"],
    "attack_vectors": ["specific attack methods and techniques"],
    "iocs": ["domains, IPs, file hashes, malware names, or other indicators"],
    "logistics_impact": 7,
    "supply_chain_risk": "One of: critical, high, medium, low, minimal",
    "geographic_focus": "Primary geographic region (e.g., North America, Europe, Asia-Pacific, Global)",
    "mitigation_priority": "One of: immediate, high, medium, low",
    "confidence_score": 85
}}

ANALYSIS GUIDELINES:

For logistics_impact (1-10 scale), consider threats to:
- Maritime shipping, ports, and cargo operations
- Fleet management and vehicle tracking systems
- Warehouse management and distribution centers
- Supply chain software and ERP systems
- Transportation networks and logistics hubs
- Customs and border control systems

For threat_type classification:
- Use "supply_chain_attack" for threats targeting vendor/supplier relationships
- Use "iot_compromise" for threats against connected vehicles, sensors, tracking devices
- Use "apt_campaign" for sophisticated state-sponsored operations
- Use "ransomware" for encryption-based extortion attacks

Be specific and accurate. Base your analysis only on information provided in the threat report.

Respond with ONLY the JSON object, no additional text.
"""
        return prompt
    
    async def _query_vertex_ai(self, prompt: str) -> str:
        """Query Vertex AI asynchronously"""
        try:
            query_start = datetime.now()
            
            # Initialize the generative model
            model = GenerativeModel(self.model_name)
            
            # Configure generation parameters for consistent analysis
            generation_config = {
                "temperature": 0.1,  # Low temperature for consistent, factual analysis
                "top_p": 0.8,
                "top_k": 40,
                "max_output_tokens": 4096,
            }
            
            # Generate content asynchronously
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: model.generate_content(
                    prompt,
                    generation_config=generation_config
                )
            )
            
            query_time = (datetime.now() - query_start).total_seconds()
            logger.debug(f"🤖 Vertex AI query completed in {query_time:.2f}s")
            
            return response.text
            
        except Exception as e:
            logger.error(f"❌ Vertex AI query failed: {e}")
            raise Exception(f"Vertex AI analysis failed: {str(e)}")
    
    def _parse_ai_response(self, ai_response: str, threat_data: Dict) -> Dict:
        """Parse Vertex AI response and extract structured data"""
        try:
            # Clean the response - remove markdown formatting if present
            cleaned_response = ai_response.strip()
            if cleaned_response.startswith(''):
                cleaned_response = cleaned_response[7:-3].strip()
            elif cleaned_response.startswith(''):
                cleaned_response = cleaned_response[3:-3].strip()
            
            # Try to extract JSON from response
            json_match = re.search(r'\{.*\}', cleaned_response, re.DOTALL)
            
            if json_match:
                analysis_json = json.loads(json_match.group())
                
                # Validate and clean the analysis
                analysis = {
                    "threat_name": self._clean_string(analysis_json.get("threat_name", threat_data.get('title', 'Unknown Threat'))),
                    "threat_type": self._validate_threat_type(analysis_json.get("threat_type", "unknown")),
                    "severity": self._validate_severity(analysis_json.get("severity", "medium")),
                    "targeted_countries": self._validate_country_list(analysis_json.get("targeted_countries", ["US"])),
                    "targeted_industries": self._clean_list(analysis_json.get("targeted_industries", ["technology"])),
                    "threat_actors": self._clean_list(analysis_json.get("threat_actors", [])),
                    "attack_vectors": self._clean_list(analysis_json.get("attack_vectors", [])),
                    "iocs": self._clean_list(analysis_json.get("iocs", [])),
                    "logistics_impact": self._validate_score(analysis_json.get("logistics_impact", 5), 1, 10),
                    "supply_chain_risk": self._validate_risk_level(analysis_json.get("supply_chain_risk", "medium")),
                    "geographic_focus": self._clean_string(analysis_json.get("geographic_focus", "Global")),
                    "mitigation_priority": self._validate_priority(analysis_json.get("mitigation_priority", "medium")),
                    "confidence_score": self._validate_score(analysis_json.get("confidence_score", 70), 0, 95)
                }
                
                return analysis
            else:
                logger.warning("⚠️ No valid JSON found in Vertex AI response")
                logger.debug(f"Response content: {ai_response[:200]}...")
                raise ValueError("No JSON in response")
                
        except json.JSONDecodeError as e:
            logger.error(f"❌ JSON parsing failed: {e}")
            logger.debug(f"Response that failed to parse: {ai_response[:500]}...")
            return self._create_fallback_analysis(threat_data)
        except Exception as e:
            logger.error(f"❌ Failed to parse Vertex AI response: {e}")
            return self._create_fallback_analysis(threat_data)
        
        # Continuing from Part 1...
    
    def _clean_string(self, value: str) -> str:
        """Clean and validate string values"""
        if not isinstance(value, str):
            return str(value) if value else ""
        return value.strip()[:200]  # Limit length
    
    def _clean_list(self, value: List) -> List[str]:
        """Clean and validate list values"""
        if not isinstance(value, list):
            return []
        return [str(item).strip() for item in value if item][:10]  # Limit to 10 items
    
    def _validate_threat_type(self, threat_type: str) -> str:
        """Validate threat type against known categories"""
        valid_types = [
            "malware", "vulnerability", "data_breach", "apt_campaign", 
            "ransomware", "phishing", "ddos", "supply_chain_attack", 
            "iot_compromise", "zero_day", "insider_threat", "unknown"
        ]
        
        threat_type = threat_type.lower().strip()
        return threat_type if threat_type in valid_types else "unknown"
    
    def _validate_severity(self, severity: str) -> str:
        """Validate severity level"""
        valid_severities = ["critical", "high", "medium", "low"]
        severity = severity.lower().strip()
        return severity if severity in valid_severities else "medium"
    
    def _validate_risk_level(self, risk: str) -> str:
        """Validate risk level"""
        valid_risks = ["critical", "high", "medium", "low", "minimal"]
        risk = risk.lower().strip()
        return risk if risk in valid_risks else "medium"
    
    def _validate_priority(self, priority: str) -> str:
        """Validate mitigation priority"""
        valid_priorities = ["immediate", "high", "medium", "low"]
        priority = priority.lower().strip()
        return priority if priority in valid_priorities else "medium"
    
    def _validate_country_list(self, countries: List) -> List[str]:
        """Validate and clean country codes"""
        if not isinstance(countries, list):
            return ["US"]
        
        # Common country codes
        valid_countries = {
            "US", "CN", "RU", "DE", "GB", "FR", "JP", "KR", "IN", "CA", 
            "AU", "SG", "NL", "IT", "ES", "BR", "MX", "AE", "SA", "IL"
        }
        
        cleaned = []
        for country in countries:
            country_code = str(country).upper().strip()
            if len(country_code) == 2:
                cleaned.append(country_code)
            elif country_code in valid_countries:
                cleaned.append(country_code)
        
        return cleaned[:5] if cleaned else ["US"]  # Limit to 5 countries
    
    def _validate_score(self, score: Union[int, float, str], min_val: int, max_val: int) -> int:
        """Validate numeric scores within range"""
        try:
            score_int = int(float(score))
            return max(min_val, min(score_int, max_val))
        except (ValueError, TypeError):
            return (min_val + max_val) // 2  # Return middle value as default
    
    def _enhance_logistics_analysis(self, analysis: Dict, threat_data: Dict) -> Dict:
        """Add comprehensive logistics-specific enhancements"""
        
        # Calculate logistics relevance score based on content analysis
        logistics_relevance = self._calculate_logistics_relevance(threat_data)
        
        # Get geographic coordinates for mapping
        coordinates = self._get_geographic_coordinates(analysis.get('targeted_countries', ['US']))
        
        # Generate detailed mitigation recommendations
        mitigation_recommendations = self._generate_mitigation_recommendations(analysis, threat_data)
        
        # Enhanced analysis with logistics intelligence
        analysis.update({
            "logistics_relevance_score": logistics_relevance,
            "latitude": coordinates['lat'],
            "longitude": coordinates['lng'],
            "analysis_timestamp": datetime.now().isoformat(),
            "analysis_model": self.model_name,
            "mitigation_recommendations": mitigation_recommendations,
            "supply_chain_impact_details": self._analyze_supply_chain_impact(analysis, threat_data),
            "business_continuity_risk": self._assess_business_continuity_risk(analysis),
            "estimated_financial_impact": self._estimate_financial_impact(analysis)
        })
        
        return analysis
    
    def _calculate_logistics_relevance(self, threat_data: Dict) -> int:
        """Calculate how relevant this threat is to logistics operations (0-100)"""
        
        # Logistics-specific keywords with weights
        logistics_keywords = {
            # High relevance (weight 3)
            'supply chain': 3, 'logistics': 3, 'shipping': 3, 'maritime': 3, 
            'port': 3, 'cargo': 3, 'fleet': 3, 'transportation': 3,
            
            # Medium relevance (weight 2)
            'warehouse': 2, 'distribution': 2, 'customs': 2, 'freight': 2,
            'container': 2, 'vessel': 2, 'truck': 2, 'delivery': 2,
            'tracking': 2, 'inventory': 2, 'scada': 2,
            
            # Lower relevance (weight 1)
            'iot': 1, 'sensor': 1, 'gps': 1, 'rfid': 1, 'erp': 1,
            'manufacturing': 1, 'industrial': 1, 'vehicle': 1
        }
        
        content_text = (threat_data.get('title', '') + ' ' + threat_data.get('content', '')).lower()
        
        relevance_score = 0
        for keyword, weight in logistics_keywords.items():
            if keyword in content_text:
                # Count occurrences and multiply by weight
                occurrences = content_text.count(keyword)
                relevance_score += min(occurrences * weight, weight * 3)  # Cap per keyword
        
        # Normalize to 0-100 scale
        max_possible_score = sum(weight * 3 for weight in logistics_keywords.values())
        normalized_score = min(int((relevance_score / max_possible_score) * 100), 100)
        
        # Boost score for certain threat types
        threat_type = threat_data.get('threat_type', '')
        if threat_type in ['supply_chain_attack', 'iot_compromise']:
            normalized_score = min(normalized_score + 20, 100)
        
        return normalized_score
    
    def _get_geographic_coordinates(self, countries: List[str]) -> Dict[str, float]:
        """Get coordinates for the primary target country for mapping"""
        country_coords = {
            "US": {"lat": 39.8283, "lng": -98.5795},
            "CN": {"lat": 35.8617, "lng": 104.1954},
            "RU": {"lat": 61.5240, "lng": 105.3188},
            "DE": {"lat": 51.1657, "lng": 10.4515},
            "GB": {"lat": 55.3781, "lng": -3.4360},
            "JP": {"lat": 36.2048, "lng": 138.2529},
            "KR": {"lat": 35.9078, "lng": 127.7669},
            "FR": {"lat": 46.6034, "lng": 1.8883},
            "IN": {"lat": 20.5937, "lng": 78.9629},
            "AU": {"lat": -25.2744, "lng": 133.7751},
            "CA": {"lat": 56.1304, "lng": -106.3468},
            "SG": {"lat": 1.3521, "lng": 103.8198},
            "NL": {"lat": 52.3676, "lng": 4.9041},
            "IT": {"lat": 41.8719, "lng": 12.5674},
            "ES": {"lat": 40.4637, "lng": -3.7492},
            "BR": {"lat": -14.2350, "lng": -51.9253},
            "MX": {"lat": 23.6345, "lng": -102.5528},
            "AE": {"lat": 23.4241, "lng": 53.8478},
            "SA": {"lat": 23.8859, "lng": 45.0792},
            "IL": {"lat": 31.0461, "lng": 34.8516}
        }
        
        primary_country = countries[0] if countries else "US"
        return country_coords.get(primary_country, country_coords["US"])
    
    def _generate_mitigation_recommendations(self, analysis: Dict, threat_data: Dict) -> str:
        """Generate detailed mitigation recommendations based on threat analysis"""
        
        threat_type = analysis.get('threat_type', 'unknown')
        severity = analysis.get('severity', 'medium')
        logistics_impact = analysis.get('logistics_impact', 5)
        
        recommendations = []
        
        # Base recommendations by threat type
        if threat_type == 'ransomware':
            recommendations.extend([
                "Implement comprehensive backup strategy with offline storage",
                "Deploy advanced endpoint detection and response (EDR) solutions",
                "Conduct regular ransomware simulation exercises",
                "Establish incident response playbook for ransomware events"
            ])
        
        elif threat_type == 'supply_chain_attack':
            recommendations.extend([
                "Enhance vendor security assessment procedures",
                "Implement software bill of materials (SBOM) tracking",
                "Deploy code signing verification for all software updates",
                "Establish trusted supplier network with security requirements"
            ])
        
        elif threat_type == 'iot_compromise':
            recommendations.extend([
                "Implement network segmentation for IoT devices",
                "Deploy IoT device monitoring and anomaly detection",
                "Enforce strong authentication for all connected devices",
                "Regular firmware updates and security patching"
            ])
        
        elif threat_type in ['malware', 'apt_campaign']:
            recommendations.extend([
                "Deploy advanced threat detection and hunting capabilities",
                "Implement zero-trust network architecture",
                "Enhance email security and anti-phishing measures",
                "Conduct regular security awareness training"
            ])
        
        # Logistics-specific recommendations
        if logistics_impact >= 7:
            recommendations.extend([
                "Implement business continuity plans for logistics operations",
                "Deploy redundant communication channels for fleet management",
                "Establish manual fallback procedures for automated systems",
                "Create incident response team with logistics expertise"
            ])
        
        # Severity-based urgency
        if severity == 'critical':
            recommendations.insert(0, "IMMEDIATE ACTION REQUIRED: Activate incident response team")
            recommendations.append("Consider temporary system isolation if compromise suspected")
        
        elif severity == 'high':
            recommendations.insert(0, "HIGH PRIORITY: Review and enhance security controls within 24 hours")
        
        return "; ".join(recommendations[:8])  # Limit to top 8 recommendations
    
    def _analyze_supply_chain_impact(self, analysis: Dict, threat_data: Dict) -> str:
        """Analyze specific supply chain impact"""
        
        threat_type = analysis.get('threat_type', '')
        targeted_industries = analysis.get('targeted_industries', [])
        
        impact_areas = []
        
        if 'maritime' in str(targeted_industries).lower() or 'shipping' in threat_data.get('content', '').lower():
            impact_areas.append("Port operations and vessel tracking systems")
        
        if 'manufacturing' in targeted_industries:
            impact_areas.append("Production scheduling and inventory management")
        
        if 'technology' in targeted_industries or threat_type == 'supply_chain_attack':
            impact_areas.append("Software and technology vendor relationships")
        
        if threat_type == 'iot_compromise':
            impact_areas.append("Connected vehicle fleets and tracking devices")
        
        if not impact_areas:
            impact_areas.append("General supply chain coordination and communication")
        
        return "; ".join(impact_areas)
    
    def _assess_business_continuity_risk(self, analysis: Dict) -> str:
        """Assess business continuity risk level"""
        
        severity = analysis.get('severity', 'medium')
        logistics_impact = analysis.get('logistics_impact', 5)
        threat_type = analysis.get('threat_type', '')
        
        # Calculate risk score
        risk_score = 0
        
        # Severity impact
        severity_scores = {'critical': 40, 'high': 30, 'medium': 20, 'low': 10}
        risk_score += severity_scores.get(severity, 20)
        
        # Logistics impact
        risk_score += logistics_impact * 3
        
        # Threat type impact
        high_impact_threats = ['ransomware', 'supply_chain_attack', 'iot_compromise']
        if threat_type in high_impact_threats:
            risk_score += 20
        
        # Determine risk level
        if risk_score >= 80:
            return "Critical - Potential for significant operational disruption"
        elif risk_score >= 60:
            return "High - May cause operational delays and increased costs"
        elif risk_score >= 40:
            return "Medium - Limited impact on operations with proper controls"
        else:
            return "Low - Minimal expected impact on business operations"
    
    def _estimate_financial_impact(self, analysis: Dict) -> str:
        """Estimate potential financial impact"""
        
        severity = analysis.get('severity', 'medium')
        logistics_impact = analysis.get('logistics_impact', 5)
        threat_type = analysis.get('threat_type', '')
        
        # Base financial impact by severity
        base_impacts = {
            'critical': '$1M-10M+ potential losses',
            'high': '$100K-1M potential losses', 
            'medium': '$10K-100K potential losses',
            'low': '$1K-10K potential losses'
        }
        
        base_impact = base_impacts.get(severity, base_impacts['medium'])
        
        # Adjust for logistics-specific factors
        if logistics_impact >= 8:
            base_impact = base_impact.replace('potential losses', 'potential losses (supply chain disruption)')
        elif threat_type == 'ransomware':
            base_impact = base_impact.replace('potential losses', 'potential losses (ransom + downtime)')
        
        return base_impact
    
        # Continuing from Part 2...
    
    def _generate_content_hash(self, threat_data: Dict) -> str:
        """Generate hash for threat content to avoid duplicate analysis"""
        content = threat_data.get('title', '') + threat_data.get('content', '')
        return hashlib.md5(content.encode('utf-8')).hexdigest()
    
    def _get_existing_analysis(self, content_hash: str) -> Optional[Dict]:
        """Check if threat has already been analyzed"""
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                SELECT 
                    threat_name, threat_type, severity, targeted_countries,
                    targeted_industries, threat_actors, attack_vectors, iocs,
                    latitude, longitude, confidence_score, logistics_impact_score,
                    supply_chain_risk, mitigation_recommendations, geographic_focus,
                    mitigation_priority, logistics_relevance_score, analysis_timestamp
                FROM processed_threats 
                WHERE content_hash = ?
                ORDER BY analysis_timestamp DESC
                LIMIT 1
            ''', (content_hash,))
            
            result = cursor.fetchone()
            
            if result:
                return {
                    "threat_name": result[0],
                    "threat_type": result[1],
                    "severity": result[2],
                    "targeted_countries": json.loads(result[3]) if result[3] else [],
                    "targeted_industries": json.loads(result[4]) if result[4] else [],
                    "threat_actors": json.loads(result[5]) if result[5] else [],
                    "attack_vectors": json.loads(result[6]) if result[6] else [],
                    "iocs": json.loads(result[7]) if result[7] else [],
                    "latitude": result[8],
                    "longitude": result[9],
                    "confidence_score": result[10],
                    "logistics_impact": result[11],
                    "supply_chain_risk": result[12],
                    "mitigation_recommendations": result[13],
                    "geographic_focus": result[14],
                    "mitigation_priority": result[15],
                    "logistics_relevance_score": result[16],
                    "analysis_timestamp": result[17],
                    "cached": True
                }
            
            return None
            
        except Exception as e:
            logger.error(f"Error checking existing analysis: {e}")
            return None
    
    def _save_analysis(self, threat_data: Dict, analysis: Dict, content_hash: str):
        """Save analysis results to database"""
        try:
            cursor = self.conn.cursor()
            
            # Get raw threat ID if available
            raw_threat_id = threat_data.get('id')
            
            cursor.execute('''
                INSERT INTO processed_threats (
                    raw_threat_id, threat_name, threat_type, severity,
                    targeted_countries, targeted_industries, threat_actors,
                    attack_vectors, iocs, latitude, longitude, confidence_score,
                    analysis_timestamp, logistics_impact_score, supply_chain_risk,
                    mitigation_recommendations, analysis_model, content_hash,
                    geographic_focus, mitigation_priority, logistics_relevance_score
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                raw_threat_id,
                analysis['threat_name'],
                analysis['threat_type'],
                analysis['severity'],
                json.dumps(analysis['targeted_countries']),
                json.dumps(analysis['targeted_industries']),
                json.dumps(analysis['threat_actors']),
                json.dumps(analysis['attack_vectors']),
                json.dumps(analysis['iocs']),
                analysis['latitude'],
                analysis['longitude'],
                analysis['confidence_score'],
                analysis['analysis_timestamp'],
                analysis['logistics_impact'],
                analysis['supply_chain_risk'],
                analysis['mitigation_recommendations'],
                self.model_name,
                content_hash,
                analysis['geographic_focus'],
                analysis['mitigation_priority'],
                analysis['logistics_relevance_score']
            ))
            
            self.conn.commit()
            
        except Exception as e:
            logger.error(f"Failed to save analysis: {e}")
    
    def _record_analysis_metrics(self, analysis_time: float, analysis_result: Dict):
        """Record performance metrics for analysis"""
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT INTO analysis_metrics (
                    timestamp, analysis_time_seconds, model_response_time,
                    confidence_score, threat_complexity_score, analysis_success,
                    model_used, logistics_relevance
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                datetime.now().isoformat(),
                analysis_time,
                analysis_time * 0.8,  # Estimate model response time
                analysis_result.get('confidence_score', 0),
                analysis_result.get('logistics_impact', 5),
                True,
                self.model_name,
                analysis_result.get('logistics_relevance_score', 0)
            ))
            
            self.conn.commit()
            
        except Exception as e:
            logger.error(f"Failed to record metrics: {e}")
    
    def _create_fallback_analysis(self, threat_data: Dict) -> Dict:
        """Create fallback analysis when AI fails"""
        return {
            "threat_name": threat_data.get('title', 'Unknown Threat')[:100],
            "threat_type": "unknown",
            "severity": "medium",
            "targeted_countries": ["US"],
            "targeted_industries": ["technology"],
            "threat_actors": [],
            "attack_vectors": [],
            "iocs": [],
            "logistics_impact": 5,
            "supply_chain_risk": "medium",
            "geographic_focus": "Global",
            "mitigation_priority": "medium",
            "confidence_score": 30,
            "latitude": 39.8283,
            "longitude": -98.5795,
            "analysis_timestamp": datetime.now().isoformat(),
            "analysis_model": "fallback",
            "logistics_relevance_score": 50,
            "mitigation_recommendations": "Implement standard security controls; Monitor for indicators of compromise; Maintain updated security policies",
            "supply_chain_impact_details": "General security concern requiring standard precautions",
            "business_continuity_risk": "Low - Minimal expected impact with proper controls",
            "estimated_financial_impact": "$10K-100K potential losses",
            "fallback": True
        }

        # Continuing from Part 3a...
    
    async def process_unprocessed_threats(self, limit: int = 10) -> Dict:
        """Process all unprocessed threats in batch"""
        session_id = f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        session_start = datetime.now()
        
        try:
            # Start analysis session
            self._start_analysis_session(session_id)
            
            # Get unprocessed threats
            cursor = self.conn.cursor()
            cursor.execute('''
                SELECT id, title, content, source, url, collected_at
                FROM raw_threats 
                WHERE processed = FALSE OR processed IS NULL
                ORDER BY collected_at DESC
                LIMIT ?
            ''', (limit,))
            
            threats = cursor.fetchall()
            
            if not threats:
                logger.info("📭 No unprocessed threats found")
                return {
                    "session_id": session_id,
                    "threats_processed": 0,
                    "session_time": 0,
                    "status": "no_threats"
                }
            
            logger.info(f"🔄 Processing {len(threats)} unprocessed threats...")
            
            processed_count = 0
            total_confidence = 0
            failed_count = 0
            
            for threat_row in threats:
                threat_dict = {
                    'id': threat_row[0],
                    'title': threat_row[1],
                    'content': threat_row[2],
                    'source': threat_row[3],
                    'url': threat_row[4],
                    'collected_at': threat_row[5]
                }
                
                logger.info(f"🤖 Analyzing: {threat_dict['title'][:60]}...")
                
                try:
                    # Analyze threat
                    analysis = await self.analyze_threat(threat_dict)
                    
                    # Mark as processed
                    cursor.execute('UPDATE raw_threats SET processed = TRUE WHERE id = ?', (threat_row[0],))
                    
                    processed_count += 1
                    total_confidence += analysis.get('confidence_score', 0)
                    
                    logger.info(f"✅ Processed {processed_count}/{len(threats)} - Confidence: {analysis.get('confidence_score', 0):.1f}%")
                    
                except Exception as e:
                    logger.error(f"❌ Failed to analyze threat {threat_row[0]}: {e}")
                    failed_count += 1
                    # Mark as processed even if failed to avoid reprocessing
                    cursor.execute('UPDATE raw_threats SET processed = TRUE WHERE id = ?', (threat_row[0],))
            
            self.conn.commit()
            
            # End analysis session
            session_time = (datetime.now() - session_start).total_seconds()
            avg_confidence = total_confidence / max(processed_count, 1)
            
            self._end_analysis_session(session_id, processed_count, avg_confidence, session_time)
            
            logger.info(f"🎯 Batch analysis complete: {processed_count} threats processed, {failed_count} failed in {session_time:.1f}s")
            
            return {
                "session_id": session_id,
                "threats_processed": processed_count,
                "threats_failed": failed_count,
                "avg_confidence_score": round(avg_confidence, 1),
                "session_time": round(session_time, 1),
                "status": "completed"
            }
            
        except Exception as e:
            logger.error(f"❌ Batch processing failed: {e}")
            self._end_analysis_session(session_id, 0, 0, 0, "failed")
            
            return {
                "session_id": session_id,
                "threats_processed": 0,
                "session_time": 0,
                "status": "failed",
                "error": str(e)
            }
    
    def _start_analysis_session(self, session_id: str):
        """Start a new analysis session"""
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT INTO analysis_sessions (
                    session_id, start_time, model_used, session_status
                ) VALUES (?, ?, ?, ?)
            ''', (session_id, datetime.now().isoformat(), self.model_name, 'active'))
            
            self.conn.commit()
            logger.debug(f"Started analysis session: {session_id}")
            
        except Exception as e:
            logger.error(f"Failed to start analysis session: {e}")
    
    def _end_analysis_session(self, session_id: str, threats_analyzed: int, 
                             avg_confidence: float, total_time: float, status: str = "completed"):
        """End analysis session and record results"""
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                UPDATE analysis_sessions 
                SET end_time = ?, threats_analyzed = ?, avg_confidence_score = ?,
                    total_analysis_time = ?, session_status = ?
                WHERE session_id = ?
            ''', (
                datetime.now().isoformat(), threats_analyzed, avg_confidence,
                total_time, status, session_id
            ))
            
            self.conn.commit()
            logger.debug(f"Ended analysis session: {session_id} - Status: {status}")
            
        except Exception as e:
            logger.error(f"Failed to end analysis session: {e}")
    
    def get_recent_analysis_sessions(self, limit: int = 10) -> List[Dict]:
        """Get recent analysis sessions"""
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                SELECT 
                    session_id, start_time, end_time, threats_analyzed,
                    model_used, avg_confidence_score, session_status, total_analysis_time
                FROM analysis_sessions 
                ORDER BY start_time DESC 
                LIMIT ?
            ''', (limit,))
            
            sessions = cursor.fetchall()
            
            return [
                {
                    "session_id": session[0],
                    "start_time": session[1],
                    "end_time": session[2],
                    "threats_analyzed": session[3],
                    "model_used": session[4],
                    "avg_confidence_score": session[5],
                    "session_status": session[6],
                    "total_analysis_time": session[7],
                    "duration_minutes": round((datetime.fromisoformat(session[2]) - datetime.fromisoformat(session[1])).total_seconds() / 60, 1) if session[2] else None
                }
                for session in sessions
            ]
            
        except Exception as e:
            logger.error(f"Failed to get analysis sessions: {e}")
            return []
    
    async def analyze_single_threat_by_id(self, threat_id: int) -> Dict:
        """Analyze a specific threat by its database ID"""
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                SELECT id, title, content, source, url, collected_at
                FROM raw_threats 
                WHERE id = ?
            ''', (threat_id,))
            
            threat_row = cursor.fetchone()
            
            if not threat_row:
                return {
                    "error": f"Threat with ID {threat_id} not found",
                    "status": "not_found"
                }
            
            threat_dict = {
                'id': threat_row[0],
                'title': threat_row[1],
                'content': threat_row[2],
                'source': threat_row[3],
                'url': threat_row[4],
                'collected_at': threat_row[5]
            }
            
            logger.info(f"🔍 Analyzing specific threat ID {threat_id}: {threat_dict['title'][:50]}...")
            
            # Analyze the threat
            analysis = await self.analyze_threat(threat_dict)
            
            # Mark as processed
            cursor.execute('UPDATE raw_threats SET processed = TRUE WHERE id = ?', (threat_id,))
            self.conn.commit()
            
            analysis['status'] = 'completed'
            analysis['threat_id'] = threat_id
            
            return analysis
            
        except Exception as e:
            logger.error(f"Failed to analyze threat ID {threat_id}: {e}")
            return {
                "error": str(e),
                "status": "failed",
                "threat_id": threat_id
            }
    
    def get_processed_threats(self, limit: int = 50, severity_filter: str = None) -> List[Dict]:
        """Get processed threats with optional severity filtering"""
        try:
            cursor = self.conn.cursor()
            
            base_query = '''
                SELECT 
                    p.id, p.raw_threat_id, p.threat_name, p.threat_type, p.severity,
                    p.targeted_countries, p.targeted_industries, p.threat_actors,
                    p.confidence_score, p.logistics_impact_score, p.supply_chain_risk,
                    p.geographic_focus, p.mitigation_priority, p.logistics_relevance_score,
                    p.analysis_timestamp, r.title, r.source
                FROM processed_threats p
                LEFT JOIN raw_threats r ON p.raw_threat_id = r.id
            '''
            
            params = []
            
            if severity_filter:
                base_query += ' WHERE p.severity = ?'
                params.append(severity_filter)
            
            base_query += ' ORDER BY p.analysis_timestamp DESC LIMIT ?'
            params.append(limit)
            
            cursor.execute(base_query, params)
            threats = cursor.fetchall()
            
            return [
                {
                    "id": threat[0],
                    "raw_threat_id": threat[1],
                    "threat_name": threat[2],
                    "threat_type": threat[3],
                    "severity": threat[4],
                    "targeted_countries": json.loads(threat[5]) if threat[5] else [],
                    "targeted_industries": json.loads(threat[6]) if threat[6] else [],
                    "threat_actors": json.loads(threat[7]) if threat[7] else [],
                    "confidence_score": threat[8],
                    "logistics_impact_score": threat[9],
                    "supply_chain_risk": threat[10],
                    "geographic_focus": threat[11],
                    "mitigation_priority": threat[12],
                    "logistics_relevance_score": threat[13],
                    "analysis_timestamp": threat[14],
                    "original_title": threat[15],
                    "source": threat[16]
                }
                for threat in threats
            ]
            
        except Exception as e:
            logger.error(f"Failed to get processed threats: {e}")
            return []

        # Continuing from Part 3b...
    
    def get_analysis_summary(self, days: int = 7) -> Dict:
        """Get comprehensive analysis summary for the last N days"""
        try:
            cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()
            cursor = self.conn.cursor()
            
            # Get basic analysis statistics
            cursor.execute('''
                SELECT 
                    COUNT(*) as total_analyzed,
                    AVG(confidence_score) as avg_confidence,
                    COUNT(CASE WHEN severity = 'critical' THEN 1 END) as critical_threats,
                    COUNT(CASE WHEN severity = 'high' THEN 1 END) as high_threats,
                    COUNT(CASE WHEN severity = 'medium' THEN 1 END) as medium_threats,
                    COUNT(CASE WHEN severity = 'low' THEN 1 END) as low_threats,
                    AVG(logistics_relevance_score) as avg_logistics_relevance,
                    COUNT(CASE WHEN logistics_impact_score >= 8 THEN 1 END) as high_impact_logistics,
                    COUNT(CASE WHEN supply_chain_risk = 'critical' THEN 1 END) as critical_supply_chain,
                    COUNT(CASE WHEN mitigation_priority = 'immediate' THEN 1 END) as immediate_priority
                FROM processed_threats 
                WHERE analysis_timestamp > ?
            ''', (cutoff_date,))
            
            stats = cursor.fetchone()
            
            # Get top threat types
            cursor.execute('''
                SELECT threat_type, COUNT(*) as count
                FROM processed_threats 
                WHERE analysis_timestamp > ?
                GROUP BY threat_type
                ORDER BY count DESC
                LIMIT 5
            ''', (cutoff_date,))
            
            top_threat_types = dict(cursor.fetchall())
            
            # Get top targeted industries (flatten JSON arrays)
            cursor.execute('''
                SELECT targeted_industries
                FROM processed_threats 
                WHERE analysis_timestamp > ? AND targeted_industries IS NOT NULL
            ''', (cutoff_date,))
            
            industry_data = cursor.fetchall()
            industry_counts = {}
            
            for (industries_json,) in industry_data:
                try:
                    industries = json.loads(industries_json) if industries_json else []
                    for industry in industries:
                        industry_counts[industry] = industry_counts.get(industry, 0) + 1
                except:
                    continue
            
            top_industries = dict(sorted(industry_counts.items(), key=lambda x: x[1], reverse=True)[:5])
            
            # Get geographic distribution
            cursor.execute('''
                SELECT geographic_focus, COUNT(*) as count
                FROM processed_threats 
                WHERE analysis_timestamp > ?
                GROUP BY geographic_focus
                ORDER BY count DESC
                LIMIT 5
            ''', (cutoff_date,))
            
            geographic_distribution = dict(cursor.fetchall())
            
            # Analysis performance metrics
            cursor.execute('''
                SELECT 
                    AVG(analysis_time_seconds) as avg_analysis_time,
                    COUNT(CASE WHEN analysis_success = 1 THEN 1 END) as successful_analyses,
                    COUNT(*) as total_attempts,
                    MIN(analysis_time_seconds) as fastest_analysis,
                    MAX(analysis_time_seconds) as slowest_analysis
                FROM analysis_metrics 
                WHERE timestamp > ?
            ''', (cutoff_date,))
            
            performance = cursor.fetchone()
            
            # Session statistics
            cursor.execute('''
                SELECT 
                    COUNT(*) as total_sessions,
                    SUM(threats_analyzed) as total_threats_in_sessions,
                    AVG(total_analysis_time) as avg_session_time,
                    COUNT(CASE WHEN session_status = 'completed' THEN 1 END) as successful_sessions
                FROM analysis_sessions 
                WHERE start_time > ?
            ''', (cutoff_date,))
            
            session_stats = cursor.fetchone()
            
            return {
                "analysis_period_days": days,
                "summary_generated": datetime.now().isoformat(),
                "model_used": self.model_name,
                
                # Basic statistics
                "threat_statistics": {
                    "total_threats_analyzed": stats[0] or 0,
                    "avg_confidence_score": round(stats[1] or 0, 1),
                    "severity_breakdown": {
                        "critical": stats[2] or 0,
                        "high": stats[3] or 0,
                        "medium": stats[4] or 0,
                        "low": stats[5] or 0
                    }
                },
                
                # Logistics-specific metrics
                "logistics_intelligence": {
                    "avg_logistics_relevance": round(stats[6] or 0, 1),
                    "high_impact_logistics_threats": stats[7] or 0,
                    "critical_supply_chain_risks": stats[8] or 0,
                    "immediate_priority_threats": stats[9] or 0
                },
                
                # Threat landscape
                "threat_landscape": {
                    "top_threat_types": top_threat_types,
                    "top_targeted_industries": top_industries,
                    "geographic_distribution": geographic_distribution
                },
                
                # Performance metrics
                "performance_metrics": {
                    "avg_analysis_time_seconds": round(performance[0] or 0, 2),
                    "success_rate_percentage": round((performance[1] / max(performance[2], 1)) * 100, 1),
                    "total_analysis_attempts": performance[2] or 0,
                    "fastest_analysis_seconds": round(performance[3] or 0, 2),
                    "slowest_analysis_seconds": round(performance[4] or 0, 2)
                },
                
                # Session information
                "session_statistics": {
                    "total_sessions": session_stats[0] or 0,
                    "total_threats_processed": session_stats[1] or 0,
                    "avg_session_time_seconds": round(session_stats[2] or 0, 1),
                    "successful_sessions": session_stats[3] or 0,
                    "session_success_rate": round((session_stats[3] / max(session_stats[0], 1)) * 100, 1)
                }
            }
            
        except Exception as e:
            logger.error(f"Failed to generate analysis summary: {e}")
            return {
                "error": str(e),
                "analysis_period_days": days,
                "summary_generated": datetime.now().isoformat()
            }
    
    def get_logistics_dashboard_data(self) -> Dict:
        """Get logistics-specific dashboard data"""
        try:
            cursor = self.conn.cursor()
            
            # Get high-impact logistics threats (last 30 days)
            cutoff_30_days = (datetime.now() - timedelta(days=30)).isoformat()
            
            cursor.execute('''
                SELECT 
                    threat_name, severity, logistics_impact_score, supply_chain_risk,
                    mitigation_priority, targeted_industries, geographic_focus,
                    confidence_score, analysis_timestamp
                FROM processed_threats 
                WHERE logistics_relevance_score >= 70 
                AND analysis_timestamp > ?
                ORDER BY logistics_impact_score DESC, confidence_score DESC
                LIMIT 20
            ''', (cutoff_30_days,))
            
            high_impact_threats = [
                {
                    "threat_name": row[0],
                    "severity": row[1],
                    "logistics_impact_score": row[2],
                    "supply_chain_risk": row[3],
                    "mitigation_priority": row[4],
                    "targeted_industries": json.loads(row[5]) if row[5] else [],
                    "geographic_focus": row[6],
                    "confidence_score": row[7],
                    "analysis_timestamp": row[8]
                }
                for row in cursor.fetchall()
            ]
            
            # Supply chain risk distribution
            cursor.execute('''
                SELECT supply_chain_risk, COUNT(*) as count
                FROM processed_threats 
                WHERE analysis_timestamp > ?
                GROUP BY supply_chain_risk
                ORDER BY 
                    CASE supply_chain_risk 
                        WHEN 'critical' THEN 1 
                        WHEN 'high' THEN 2 
                        WHEN 'medium' THEN 3 
                        WHEN 'low' THEN 4 
                        WHEN 'minimal' THEN 5 
                        ELSE 6 
                    END
            ''', (cutoff_30_days,))
            
            supply_chain_risk_distribution = dict(cursor.fetchall())
            
            # Mitigation priority breakdown
            cursor.execute('''
                SELECT mitigation_priority, COUNT(*) as count
                FROM processed_threats 
                WHERE analysis_timestamp > ?
                GROUP BY mitigation_priority
                ORDER BY 
                    CASE mitigation_priority 
                        WHEN 'immediate' THEN 1 
                        WHEN 'high' THEN 2 
                        WHEN 'medium' THEN 3 
                        WHEN 'low' THEN 4 
                        ELSE 5 
                    END
            ''', (cutoff_30_days,))
            
            mitigation_priority_breakdown = dict(cursor.fetchall())
            
            # Geographic threat hotspots
            cursor.execute('''
                SELECT latitude, longitude, threat_name, severity, logistics_impact_score
                FROM processed_threats 
                WHERE analysis_timestamp > ?
                AND logistics_relevance_score >= 60
                AND latitude IS NOT NULL 
                AND longitude IS NOT NULL
                ORDER BY logistics_impact_score DESC
                LIMIT 50
            ''', (cutoff_30_days,))
            
            threat_hotspots = [
                {
                    "lat": row[0],
                    "lng": row[1],
                    "threat_name": row[2],
                    "severity": row[3],
                    "logistics_impact_score": row[4],
                    "marker_size": min(row[4] * 2, 20),  # Scale marker size
                    "color": {
                        "critical": "#ff0000",
                        "high": "#ff6600", 
                        "medium": "#ffaa00",
                        "low": "#99cc00"
                    }.get(row[3], "#666666")
                }
                for row in cursor.fetchall()
            ]
            
            return {
                "dashboard_generated": datetime.now().isoformat(),
                "data_period_days": 30,
                "high_impact_logistics_threats": high_impact_threats,
                "supply_chain_risk_distribution": supply_chain_risk_distribution,
                "mitigation_priority_breakdown": mitigation_priority_breakdown,
                "geographic_threat_hotspots": threat_hotspots,
                "summary_stats": {
                    "total_logistics_relevant_threats": len(high_impact_threats),
                    "critical_supply_chain_risks": supply_chain_risk_distribution.get('critical', 0),
                    "immediate_action_required": mitigation_priority_breakdown.get('immediate', 0),
                    "geographic_coverage": len(threat_hotspots)
                }
            }
            
        except Exception as e:
            logger.error(f"Failed to generate logistics dashboard data: {e}")
            return {
                "error": str(e),
                "dashboard_generated": datetime.now().isoformat()
            }
    
    def close_connection(self):
        """Close database connection"""
        try:
            if self.conn:
                self.conn.close()
                logger.info("Database connection closed")
        except Exception as e:
            logger.error(f"Error closing database connection: {e}")

# Main execution and testing
if __name__ == "__main__":
    import asyncio
    
    async def test_analyzer():
        """Test the AI analyzer"""
        print("🤖 Testing Vertex AI Threat Analyzer...")
        
        try:
            # Initialize analyzer
            analyzer = ThreatAIAnalyzer()
            
            # Test threat data
            test_threat = {
                "title": "APT29 Targets Maritime Supply Chain Infrastructure",
                "content": "Russian state-sponsored group APT29 launching sophisticated attacks against global maritime logistics companies. Campaign focuses on port management systems, cargo tracking platforms, and supply chain coordination software.",
                "source": "test_intelligence"
            }
            
            print(f"\n🔍 Analyzing test threat: {test_threat['title']}")
            
            # Analyze the threat
            analysis = await analyzer.analyze_threat(test_threat)
            
            print(f"\n📊 Analysis Results:")
            print(f"   Threat Name: {analysis['threat_name']}")
            print(f"   Threat Type: {analysis['threat_type']}")
            print(f"   Severity: {analysis['severity']}")
            print(f"   Confidence: {analysis['confidence_score']}%")
            print(f"   Logistics Impact: {analysis['logistics_impact']}/10")
            print(f"   Supply Chain Risk: {analysis['supply_chain_risk']}")
            
            # Test batch processing
            print(f"\n🔄 Testing batch processing...")
            batch_result = await analyzer.process_unprocessed_threats(limit=3)
            print(f"   Session: {batch_result['session_id']}")
            print(f"   Processed: {batch_result['threats_processed']} threats")
            print(f"   Time: {batch_result['session_time']}s")
            
            # Test summary
            print(f"\n📈 Testing analysis summary...")
            summary = analyzer.get_analysis_summary(days=7)
            print(f"   Total analyzed: {summary['threat_statistics']['total_threats_analyzed']}")
            print(f"   Avg confidence: {summary['threat_statistics']['avg_confidence_score']}%")
            
            print(f"\n✅ All tests completed successfully!")
            
        except Exception as e:
            print(f"\n❌ Test failed: {e}")
            import traceback
            traceback.print_exc()
        
        finally:
            if 'analyzer' in locals():
                analyzer.close_connection()
    
    # Run the test
    asyncio.run(test_analyzer())
