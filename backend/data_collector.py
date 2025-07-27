"""
AI-Enhanced Cyber Threat Intelligence Data Collector - Part 1
Core Infrastructure & Initialization
Designed for Global Logistics Company Security Team
"""

import asyncio
import aiohttp
import feedparser
import requests
import sqlite3
import json
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import logging
import hashlib
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
import random

# Configure enterprise logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class CollectionMode(Enum):
    """Collection strategies for different operational scenarios"""
    DEMO_ONLY = "demo_only"           # For demonstrations
    LIVE_ONLY = "live_only"           # Pure live collection
    HYBRID = "hybrid"                 # Demo + Live (recommended)
    LOGISTICS_FOCUSED = "logistics"   # Supply chain specialized

class SourcePriority(Enum):
    """AI-determined source priority levels"""
    CRITICAL = 1      # Government alerts, CISA
    HIGH = 2          # Major security vendors, maritime security
    MEDIUM = 3        # Industry publications
    LOW = 4           # General tech news
    EXPERIMENTAL = 5  # New sources being tested

@dataclass
class CollectionStats:
    """Enterprise collection statistics"""
    start_time: datetime
    end_time: Optional[datetime] = None
    sources_attempted: int = 0
    sources_successful: int = 0
    total_articles: int = 0
    security_articles: int = 0
    logistics_relevant: int = 0
    errors: List[str] = None
    source_results: Dict[str, Dict] = None
    
    def __post_init__(self):
        if self.errors is None:
            self.errors = []
        if self.source_results is None:
            self.source_results = {}

class ThreatDataCollector:
    """
    Enterprise-grade threat intelligence collector
    Focused on global logistics company security needs
    """
    
    def __init__(self, collection_mode: CollectionMode = CollectionMode.HYBRID):
        self.collection_mode = collection_mode
        self.session_stats = CollectionStats(start_time=datetime.now())
        
        # Initialize core systems
        self._init_logistics_sources()
        self._init_enterprise_db()
        self._init_demo_manager()
        
        logger.info(f"ThreatDataCollector initialized in {collection_mode.value} mode")
        logger.info(f"Configured {len(self.logistics_priority_sources)} priority sources")

    def _init_demo_manager(self):
        """Initialize demo data manager"""
        try:
            # Use the existing LogisticsDemoDataManager from the same file
            self.demo_manager = LogisticsDemoDataManager(self.conn)
            logger.info("✅ Demo manager initialized")
        except Exception as e:
            logger.error(f"❌ Demo manager initialization failed: {e}")
            # Create a fallback demo manager
            self.demo_manager = self._create_fallback_demo_manager()

    def _create_fallback_demo_manager(self):
        """Create a simple fallback demo manager"""
        class FallbackDemoManager:
            def __init__(self, conn):
                self.conn = conn
            
            def add_demo_data_to_database(self):
                logger.info("Using fallback demo manager")
                return 5  # Return fake count
            
            def get_recent_threats(self, limit=20, demo_only=False):
                return []
        
        return FallbackDemoManager(self.conn)

    def _init_logistics_sources(self):
        """Initialize logistics-focused threat intelligence sources"""
        
        # CRITICAL PRIORITY - Government & Infrastructure
        self.logistics_priority_sources = {
            "us_cisa_alerts": {
                "url": "https://us-cert.cisa.gov/ncas/alerts.xml",
                "priority": SourcePriority.CRITICAL,
                "focus": "government_alerts",
                "logistics_relevance": 95,
                "description": "CISA Critical Infrastructure Alerts"
            },
            
            # HIGH PRIORITY - Maritime & Supply Chain Specific
            "krebs_security": {
                "url": "https://krebsonsecurity.com/feed/",
                "priority": SourcePriority.HIGH,
                "focus": "investigative_security",
                "logistics_relevance": 80,
                "description": "Brian Krebs Security Investigations"
            },
            "bleeping_computer": {
                "url": "https://www.bleepingcomputer.com/feed/",
                "priority": SourcePriority.HIGH,
                "focus": "technical_threats",
                "logistics_relevance": 75,
                "description": "Technical Cybersecurity News"
            },
            "security_week": {
                "url": "https://feeds.feedburner.com/Securityweek",
                "priority": SourcePriority.HIGH,
                "focus": "enterprise_security",
                "logistics_relevance": 80,
                "description": "Enterprise Security News"
            },
            
            # MEDIUM PRIORITY - Industry & Regional
            "the_hacker_news": {
                "url": "https://feeds.feedburner.com/TheHackersNews",
                "priority": SourcePriority.MEDIUM,
                "focus": "breaking_news",
                "logistics_relevance": 65,
                "description": "Cybersecurity Breaking News"
            },
            "security_affairs": {
                "url": "https://securityaffairs.com/feed",
                "priority": SourcePriority.MEDIUM,
                "focus": "global_threats",
                "logistics_relevance": 70,
                "description": "Global Security Affairs"
            },
            "cyber_scoop": {
                "url": "https://www.cyberscoop.com/feed/",
                "priority": SourcePriority.MEDIUM,
                "focus": "policy_security",
                "logistics_relevance": 60,
                "description": "Cybersecurity Policy & Government"
            }
        }
        
        # Backup sources for redundancy
        self.backup_sources = {
            "malwarebytes": {
                "url": "https://www.malwarebytes.com/blog/feed/index.xml",
                "priority": SourcePriority.MEDIUM,
                "focus": "malware_analysis",
                "logistics_relevance": 55
            },
            "threatpost": {
                "url": "https://threatpost.com/feed/",
                "priority": SourcePriority.MEDIUM,
                "focus": "vulnerability_news",
                "logistics_relevance": 60
            }
        }

    def _init_enterprise_db(self):
        """Initialize enterprise-grade database schema"""
        try:
            self.conn = sqlite3.connect('../data/threats.db', check_same_thread=False)
            cursor = self.conn.cursor()
            
            # Enhanced raw threats table for logistics company
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS raw_threats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    content TEXT,
                    source TEXT NOT NULL,
                    url TEXT UNIQUE,
                    published_date TEXT,
                    collected_at TEXT NOT NULL,
                    processed BOOLEAN DEFAULT FALSE,
                    is_demo BOOLEAN DEFAULT FALSE,
                    logistics_relevance INTEGER DEFAULT 0,
                    threat_severity TEXT DEFAULT 'unknown',
                    source_priority INTEGER DEFAULT 3,
                    content_hash TEXT,
                    feed_status TEXT DEFAULT 'active'
                )
            ''')
            
            # Source performance tracking for enterprise monitoring
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS source_intelligence (
                    source_name TEXT PRIMARY KEY,
                    source_url TEXT,
                    priority_level INTEGER,
                    logistics_relevance INTEGER,
                    total_attempts INTEGER DEFAULT 0,
                    successful_collections INTEGER DEFAULT 0,
                    last_success TEXT,
                    last_error TEXT,
                    reliability_score REAL DEFAULT 1.0,
                    collection_frequency TEXT DEFAULT 'daily',
                    is_active BOOLEAN DEFAULT TRUE,
                    performance_notes TEXT
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS collection_sessions (
                    session_id TEXT PRIMARY KEY,
                    start_time TEXT NOT NULL,
                    end_time TEXT,
                    collection_mode TEXT,
                    sources_attempted INTEGER DEFAULT 0,
                    sources_successful INTEGER DEFAULT 0,
                    threats_collected INTEGER DEFAULT 0,
                    avg_logistics_relevance REAL DEFAULT 0,
                    session_status TEXT DEFAULT 'running'
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS processed_threats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    raw_threat_id INTEGER,
                    threat_name TEXT NOT NULL,
                    threat_type TEXT DEFAULT 'cyber_attack',
                    severity TEXT DEFAULT 'medium',
                    targeted_countries TEXT,
                    targeted_industries TEXT,
                    threat_actors TEXT,
                    attack_vectors TEXT,
                    confidence_score REAL DEFAULT 75.0,
                    latitude REAL,
                    longitude REAL,
                    analysis_timestamp TEXT NOT NULL,
                    FOREIGN KEY (raw_threat_id) REFERENCES raw_threats (id)
                )
            ''')
            
            # Create index for performance
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_processed_coordinates ON processed_threats(latitude, longitude)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_processed_severity ON processed_threats(severity)')

            
            # Create performance indexes
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_collected_at ON raw_threats(collected_at)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_source_priority ON raw_threats(source, source_priority)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_logistics_relevance ON raw_threats(logistics_relevance)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_session_time ON collection_sessions(start_time)')
            
            self.conn.commit()
            logger.info("✅ Enterprise database schema initialized")
            
        except Exception as e:
            logger.error(f"❌ Database initialization failed: {e}")
            raise

    def get_collection_strategy(self) -> Dict:
        """
        Determine optimal collection strategy based on mode and current conditions
        """
        strategy = {
            "mode": self.collection_mode.value,
            "max_sources": 8,  # Reasonable limit for demo
            "timeout_per_source": 10,
            "priority_filter": [SourcePriority.CRITICAL, SourcePriority.HIGH, SourcePriority.MEDIUM],
            "logistics_threshold": 50,  # Minimum logistics relevance score
            "concurrent_limit": 5,
            "demo_data_enabled": self.collection_mode in [CollectionMode.DEMO_ONLY, CollectionMode.HYBRID]
        }
        
        # Adjust strategy based on collection mode
        if self.collection_mode == CollectionMode.DEMO_ONLY:
            strategy.update({
                "max_sources": 0,
                "demo_data_enabled": True,
                "live_collection": False
            })
        elif self.collection_mode == CollectionMode.LIVE_ONLY:
            strategy.update({
                "max_sources": 12,
                "demo_data_enabled": False,
                "live_collection": True
            })
        elif self.collection_mode == CollectionMode.LOGISTICS_FOCUSED:
            strategy.update({
                "logistics_threshold": 70,  # Higher threshold for specialized mode
                "priority_filter": [SourcePriority.CRITICAL, SourcePriority.HIGH]
            })
        
        logger.info(f"📋 Collection strategy: {strategy['mode']} mode, {strategy['max_sources']} sources")
        return strategy

    def get_prioritized_sources(self, max_sources: int = 8) -> Dict[str, Dict]:
        """
        Get prioritized source list based on logistics relevance and reliability
        """
        all_sources = self.logistics_priority_sources.copy()
        
        # Sort by priority level and logistics relevance
        prioritized = sorted(
            all_sources.items(),
            key=lambda x: (x[1]['priority'].value, -x[1]['logistics_relevance'])
        )
        
        # Select top sources up to limit
        selected_sources = dict(prioritized[:max_sources])
        
        logger.info(f"📊 Selected {len(selected_sources)} priority sources for collection")
        for name, config in selected_sources.items():
            logger.info(f"   • {name}: {config['description']} (Priority: {config['priority'].name})")
        
        return selected_sources
    
    # Part 4B: Main Collection Engine - Add to existing file

    async def collect_all_threats(self, mode: CollectionMode = None) -> Dict:
        """
        Main collection method - enterprise-grade threat intelligence gathering
        """
        collection_mode = mode or CollectionMode.HYBRID
        session_id = f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        logger.info(f"🚀 Starting threat intelligence collection (Mode: {collection_mode.value})")
        
        # Initialize collection session tracking
        session_stats = self._initialize_collection_session(session_id, collection_mode)
        
        try:
            if collection_mode == CollectionMode.DEMO_ONLY:
                result = await self._collect_demo_only(session_stats)
            elif collection_mode == CollectionMode.LIVE_ONLY:
                result = await self._collect_live_only(session_stats)
            elif collection_mode == CollectionMode.HYBRID:
                result = await self._collect_hybrid_mode(session_stats)
            else:  # EMERGENCY
                result = await self._collect_emergency_mode(session_stats)
            
            # Finalize session
            self._finalize_collection_session(session_id, result)
            
            logger.info(f"✅ Collection complete: {result['total_threats']} threats collected")
            return result
            
        except Exception as e:
            logger.error(f"❌ Collection failed: {str(e)}")
            self._finalize_collection_session(session_id, {
                "status": "error",
                "error": str(e),
                "total_threats": 0
            })
            return self._create_error_response(str(e))

    async def _collect_hybrid_mode(self, session_stats: Dict) -> Dict:
        """
        Hybrid collection: Professional demo data + live RSS feeds
        """
        logger.info("📋 Phase 1: Loading professional demo dataset...")
        
        # PHASE 1: Ensure quality demo data exists
        demo_count = self.demo_manager.add_demo_data_to_database()
        demo_threats = self.demo_manager.get_recent_threats(limit=demo_count, demo_only=True)
        
        session_stats["demo_threats"] = len(demo_threats)
        logger.info(f"✅ {len(demo_threats)} professional demo threats loaded")
        
        # PHASE 2: Process demo threats with geography
        logger.info("🌍 Phase 2: Processing geographic data...")
        processed_demo = self._process_threats_with_geography(demo_threats)
        
        # PHASE 3: Attempt live RSS collection
        logger.info("🌐 Phase 3: Attempting live RSS collection...")
        
        live_threats = []
        if not hasattr(self, 'rss_collector') or self.rss_collector is None:
            stats = CollectionStats(start_time=datetime.now())
            self.rss_collector = LiveRSSCollector(self.conn, stats)
        
        try:
            prioritized_sources = self.get_prioritized_sources(8)
            live_threats = await self.rss_collector.collect_from_prioritized_sources(
                prioritized_sources,
                timeout=10,
                concurrent_limit=5
            )
            
            # Process live threats with geography too
            if live_threats:
                processed_live = self._process_threats_with_geography(live_threats)
                live_threats = processed_live
            
            session_stats["live_threats"] = len(live_threats)
            session_stats["sources_attempted"] = len(prioritized_sources)
            session_stats["sources_successful"] = self.rss_collector.stats.sources_successful
            
            if live_threats:
                logger.info(f"✅ Bonus: {len(live_threats)} live threats collected and processed")
            else:
                logger.info("ℹ️ No live threats collected - using demo dataset for presentation")
                
        except Exception as e:
            logger.warning(f"Live collection failed: {str(e)[:50]}... - using demo data")
            session_stats["collection_errors"] = [str(e)]
        
        # PHASE 4: Combine and validate results
        all_threats = processed_demo + live_threats
        
        # Apply quality filters
        filtered_threats = self._apply_quality_filters(all_threats)
        
        return {
            "status": "success",
            "collection_mode": CollectionMode.HYBRID.value,
            "total_threats": len(filtered_threats),
            "demo_threats": len(processed_demo),
            "live_threats": len(live_threats),
            "filtered_threats": len(all_threats) - len(filtered_threats),
            "sources_attempted": session_stats.get("sources_attempted", 0),
            "sources_successful": session_stats.get("sources_successful", 0),
            "avg_logistics_relevance": self._calculate_avg_relevance(filtered_threats),
            "collection_time": (datetime.now() - session_stats["start_time"]).total_seconds(),
            "threats": filtered_threats[:20],
            "session_id": session_stats["session_id"],
            "geographic_data_generated": True
        }


    async def _collect_demo_only(self, session_stats: Dict) -> Dict:
        """
        Demo-only collection for presentations and testing
        """
        logger.info("🎭 Demo-only mode: Loading professional demonstration dataset...")
        
        demo_count = self.demo_manager.add_demo_data_to_database()
        demo_threats = self.demo_manager.get_recent_threats(limit=20, demo_only=True)
        
        session_stats["demo_threats"] = len(demo_threats)
        
        return {
            "status": "success",
            "collection_mode": CollectionMode.DEMO_ONLY.value,
            "total_threats": len(demo_threats),
            "demo_threats": len(demo_threats),
            "live_threats": 0,
            "avg_logistics_relevance": self._calculate_avg_relevance(demo_threats),
            "collection_time": (datetime.now() - session_stats["start_time"]).total_seconds(),
            "threats": demo_threats,
            "session_id": session_stats["session_id"]
        }

    async def _collect_live_only(self, session_stats: Dict) -> Dict:
        """
        Live-only collection from RSS feeds
        """
        logger.info("🌐 Live-only mode: Collecting from RSS feeds...")
        
        if not hasattr(self, 'rss_collector') or self.rss_collector is None:
            stats = CollectionStats(start_time=datetime.now())
            self.rss_collector = LiveRSSCollector(self.conn, stats)
        
        prioritized_sources = self.get_prioritized_sources(12)  # More sources for live-only
        live_threats = await self.rss_collector.collect_from_prioritized_sources(
            prioritized_sources,
            timeout=10,
            concurrent_limit=5
        )
        
        session_stats["live_threats"] = len(live_threats)
        session_stats["sources_attempted"] = len(prioritized_sources)
        session_stats["sources_successful"] = self.rss_collector.stats.sources_successful
        
        # If live collection fails completely, fall back to emergency demo
        if not live_threats:
            logger.warning("⚠️ Live collection failed - falling back to emergency demo data")
            return await self._collect_emergency_mode(session_stats)
        
        return {
            "status": "success",
            "collection_mode": CollectionMode.LIVE_ONLY.value,
            "total_threats": len(live_threats),
            "demo_threats": 0,
            "live_threats": len(live_threats),
            "sources_attempted": session_stats["sources_attempted"],
            "sources_successful": session_stats["sources_successful"],
            "avg_logistics_relevance": self._calculate_avg_relevance(live_threats),
            "collection_time": (datetime.now() - session_stats["start_time"]).total_seconds(),
            "threats": live_threats[:20],
            "session_id": session_stats["session_id"]
        }
    
    # Part 4C: Session Management & Utilities - Add to existing file

    def _initialize_collection_session(self, session_id: str, mode: CollectionMode) -> Dict:
        """
        Initialize collection session tracking
        """
        session_stats = {
            "session_id": session_id,
            "start_time": datetime.now(),
            "collection_mode": mode.value,
            "demo_threats": 0,
            "live_threats": 0,
            "sources_attempted": 0,
            "sources_successful": 0,
            "collection_errors": []
        }
        
        # Save to database
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT INTO collection_sessions 
                (session_id, start_time, collection_mode)
                VALUES (?, ?, ?)
            ''', (session_id, session_stats["start_time"].isoformat(), mode.value))
            self.conn.commit()
        except Exception as e:
            logger.warning(f"Failed to save session to database: {e}")
        
        return session_stats

    def _finalize_collection_session(self, session_id: str, result: Dict):
        """
        Finalize collection session with results
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                UPDATE collection_sessions 
                SET end_time = ?, 
                    sources_attempted = ?,
                    sources_successful = ?,
                    threats_collected = ?,
                    avg_logistics_relevance = ?,
                    session_status = ?
                WHERE session_id = ?
            ''', (
                datetime.now().isoformat(),
                result.get("sources_attempted", 0),
                result.get("sources_successful", 0),
                result.get("total_threats", 0),
                result.get("avg_logistics_relevance", 0),
                result.get("status", "completed"),
                session_id
            ))
            self.conn.commit()
        except Exception as e:
            logger.warning(f"Failed to finalize session in database: {e}")

    async def _collect_emergency_mode(self, session_stats: Dict) -> Dict:
        """
        Emergency fallback mode - minimal demo data for system availability
        """
        logger.warning("🚨 Emergency mode: Loading minimal threat intelligence dataset...")
        
        # Ensure at least some demo data exists
        demo_count = self.demo_manager.add_demo_data_to_database()
        if demo_count == 0:
            # Generate emergency threats if none exist
            emergency_threats = self._generate_emergency_threats()
            demo_count = len(emergency_threats)
        
        demo_threats = self.demo_manager.get_recent_threats(limit=10, demo_only=True)
        session_stats["demo_threats"] = len(demo_threats)
        
        return {
            "status": "emergency",
            "collection_mode": CollectionMode.EMERGENCY.value,
            "total_threats": len(demo_threats),
            "demo_threats": len(demo_threats),
            "live_threats": 0,
            "message": "System operating in emergency mode with minimal dataset",
            "avg_logistics_relevance": self._calculate_avg_relevance(demo_threats),
            "collection_time": (datetime.now() - session_stats["start_time"]).total_seconds(),
            "threats": demo_threats,
            "session_id": session_stats["session_id"]
        }

    def _apply_quality_filters(self, threats: List[Dict]) -> List[Dict]:
        """
        Apply quality filters to threat collection
        """
        filtered_threats = []
        
        for threat in threats:
            # Skip threats with very low logistics relevance
            if threat.get('logistics_relevance', 0) < 30:
                continue
            
            # Skip duplicate content (basic check)
            if len(threat.get('title', '')) < 10:
                continue
            
            # Skip threats with insufficient content
            if len(threat.get('content', '')) < 50:
                continue
            
            filtered_threats.append(threat)
        
        # Sort by logistics relevance and recency
        filtered_threats.sort(
            key=lambda x: (x.get('logistics_relevance', 0), x.get('collected_at', '')),
            reverse=True
        )
        
        return filtered_threats

    def _calculate_avg_relevance(self, threats: List[Dict]) -> float:
        """
        Calculate average logistics relevance score
        """
        if not threats:
            return 0.0
        
        relevance_scores = [threat.get('logistics_relevance', 0) for threat in threats]
        return round(sum(relevance_scores) / len(relevance_scores), 1)

    def _create_error_response(self, error_msg: str) -> Dict:
        """
        Create standardized error response
        """
        return {
            "status": "error",
            "error": error_msg,
            "total_threats": 0,
            "demo_threats": 0,
            "live_threats": 0,
            "collection_time": 0,
            "threats": [],
            "message": "Collection failed - please check system logs"
        }

    def _generate_emergency_threats(self) -> List[Dict]:
        """
        Generate minimal emergency threat data if all else fails
        """
        emergency_threats = [
            {
                "title": "System Operating in Emergency Mode - Limited Threat Intelligence Available",
                "content": "Cyber threat intelligence collection system is currently operating in emergency mode. Live RSS feeds are unavailable and demo dataset is being used for minimal functionality. Please check network connectivity and RSS feed availability.",
                "source": "system_emergency",
                "collected_at": datetime.now().isoformat(),
                "published_date": datetime.now().isoformat(),
                "is_demo": True,
                "logistics_relevance": 50,
                "threat_severity": "medium",
                "url": "https://threat-intel.local/emergency/1"
            }
        ]
        
        # Save emergency threats to database
        for threat in emergency_threats:
            self.demo_manager._save_demo_threat_to_db(threat)
        
        return emergency_threats
    
    # Part 4D: Enterprise Monitoring & Health Checks - Add to ThreatDataCollector class

    def get_enterprise_health_report(self) -> Dict:
        """
        Comprehensive enterprise health monitoring for logistics company
        """
        try:
            cursor = self.conn.cursor()
            
            # Collection performance metrics
            cursor.execute('''
                SELECT 
                    COUNT(*) as total_sessions,
                    COUNT(CASE WHEN session_status = 'completed' THEN 1 END) as completed_sessions,
                    AVG(threats_collected) as avg_threats_per_session,
                    AVG(avg_logistics_relevance) as overall_logistics_relevance,
                    MAX(end_time) as last_collection
                FROM collection_sessions 
                WHERE start_time > datetime('now', '-24 hours')
            ''')
            performance_data = cursor.fetchone()
            
            # Source reliability analysis
            cursor.execute('''
                SELECT 
                    COUNT(*) as total_sources,
                    COUNT(CASE WHEN reliability_score > 0.8 THEN 1 END) as excellent_sources,
                    COUNT(CASE WHEN reliability_score > 0.5 THEN 1 END) as good_sources,
                    AVG(reliability_score) as avg_reliability,
                    COUNT(CASE WHEN is_active = 1 THEN 1 END) as active_sources
                FROM source_intelligence
            ''')
            source_data = cursor.fetchone()
            
            # Data freshness and quality
            cursor.execute('''
                SELECT 
                    COUNT(*) as total_threats_24h,
                    COUNT(CASE WHEN logistics_relevance >= 70 THEN 1 END) as high_relevance_threats,
                    AVG(logistics_relevance) as avg_relevance_24h,
                    COUNT(CASE WHEN is_demo = 0 THEN 1 END) as live_threats_24h,
                    MAX(collected_at) as latest_threat
                FROM raw_threats 
                WHERE collected_at > datetime('now', '-24 hours')
            ''')
            data_quality = cursor.fetchone()
            
            # Calculate health scores
            collection_health = self._calculate_collection_health_score(performance_data)
            source_health = self._calculate_source_health_score(source_data)
            data_health = self._calculate_data_health_score(data_quality)
            
            # Overall enterprise health score
            overall_health = (collection_health + source_health + data_health) / 3
            
            # Determine status and recommendations
            status_info = self._determine_health_status(overall_health)
            recommendations = self._generate_health_recommendations(
                collection_health, source_health, data_health
            )
            
            return {
                "overall_health": {
                    "score": round(overall_health, 1),
                    "status": status_info["status"],
                    "status_emoji": status_info["emoji"],
                    "grade": status_info["grade"]
                },
                "collection_performance": {
                    "score": round(collection_health, 1),
                    "total_sessions_24h": performance_data[0] or 0,
                    "success_rate": round((performance_data[1] or 0) / max(performance_data[0] or 1, 1) * 100, 1),
                    "avg_threats_per_session": round(performance_data[2] or 0, 1),
                    "avg_logistics_relevance": round(performance_data[3] or 0, 1),
                    "last_collection": performance_data[4]
                },
                "source_intelligence": {
                    "score": round(source_health, 1),
                    "total_sources": source_data[0] or 0,
                    "excellent_sources": source_data[1] or 0,
                    "good_sources": source_data[2] or 0,
                    "avg_reliability": round((source_data[3] or 0) * 100, 1),
                    "active_sources": source_data[4] or 0
                },
                "data_quality": {
                    "score": round(data_health, 1),
                    "threats_24h": data_quality[0] or 0,
                    "high_relevance_count": data_quality[1] or 0,
                    "avg_relevance": round(data_quality[2] or 0, 1),
                    "live_threats_24h": data_quality[3] or 0,
                    "latest_threat": data_quality[4]
                },
                "recommendations": recommendations,
                "monitoring_timestamp": datetime.now().isoformat(),
                "system_info": {
                    "database_size": self._get_database_size(),
                    "uptime_hours": self._calculate_system_uptime(),
                    "enterprise_mode": True,
                    "logistics_optimized": True
                }
            }
            
        except Exception as e:
            logger.error(f"Enterprise health report generation failed: {e}")
            return {
                "error": str(e),
                "overall_health": {"score": 0, "status": "🔴 System Error"},
                "monitoring_timestamp": datetime.now().isoformat()
            }

    def _calculate_collection_health_score(self, performance_data) -> float:
        """Calculate collection performance health score (0-100)"""
        total_sessions = performance_data[0] or 0
        completed_sessions = performance_data[1] or 0
        avg_threats = performance_data[2] or 0
        avg_relevance = performance_data[3] or 0
        
        if total_sessions == 0:
            return 50.0  # Neutral score for no data
        
        success_rate = completed_sessions / total_sessions
        threat_volume_score = min(avg_threats / 10, 1.0)  # Target: 10+ threats per session
        relevance_score = (avg_relevance or 0) / 100
        
        return (success_rate * 40 + threat_volume_score * 30 + relevance_score * 30) * 100

    def _calculate_source_health_score(self, source_data) -> float:
        """Calculate source reliability health score (0-100)"""
        total_sources = source_data[0] or 0
        excellent_sources = source_data[1] or 0
        good_sources = source_data[2] or 0
        avg_reliability = source_data[3] or 0
        active_sources = source_data[4] or 0
        
        if total_sources == 0:
            return 60.0  # Neutral score for no sources configured
        
        excellent_ratio = excellent_sources / total_sources
        good_ratio = good_sources / total_sources
        active_ratio = active_sources / total_sources
        
        return (excellent_ratio * 50 + good_ratio * 25 + active_ratio * 25) * 100

    def _calculate_data_health_score(self, data_quality) -> float:
        """Calculate data quality health score (0-100)"""
        total_threats = data_quality[0] or 0
        high_relevance = data_quality[1] or 0
        avg_relevance = data_quality[2] or 0
        live_threats = data_quality[3] or 0
        
        if total_threats == 0:
            return 40.0  # Low score for no recent data
        
        volume_score = min(total_threats / 20, 1.0)  # Target: 20+ threats per day
        relevance_ratio = high_relevance / total_threats if total_threats > 0 else 0
        quality_score = (avg_relevance or 0) / 100
        live_ratio = live_threats / total_threats if total_threats > 0 else 0
        
        return (volume_score * 30 + relevance_ratio * 30 + quality_score * 25 + live_ratio * 15) * 100

    def _determine_health_status(self, overall_health: float) -> Dict:
        """Determine system health status based on score"""
        if overall_health >= 90:
            return {"status": "Excellent", "emoji": "🟢", "grade": "A+"}
        elif overall_health >= 80:
            return {"status": "Good", "emoji": "🟢", "grade": "A"}
        elif overall_health >= 70:
            return {"status": "Satisfactory", "emoji": "🟡", "grade": "B"}
        elif overall_health >= 60:
            return {"status": "Fair", "emoji": "🟠", "grade": "C"}
        elif overall_health >= 40:
            return {"status": "Poor", "emoji": "🔴", "grade": "D"}
        else:
            return {"status": "Critical", "emoji": "🔴", "grade": "F"}

    def _generate_health_recommendations(self, collection_health: float, 
                                       source_health: float, data_health: float) -> List[str]:
        """Generate actionable recommendations based on health scores"""
        recommendations = []
        
        if collection_health < 70:
            recommendations.append("🔧 Optimize collection frequency and timeout settings")
            recommendations.append("📊 Review collection session logs for frequent failures")
        
        if source_health < 70:
            recommendations.append("🌐 Check RSS feed availability and update source configurations")
            recommendations.append("🔄 Add more reliable cybersecurity news sources")
        
        if data_health < 60:
            recommendations.append("📈 Increase collection frequency to improve data freshness")
            recommendations.append("🎯 Fine-tune logistics relevance scoring algorithms")
        
        if collection_health > 85 and source_health > 85 and data_health > 85:
            recommendations.append("✅ System performing excellently - consider expanding source coverage")
            recommendations.append("🚀 Ready for advanced threat analytics and AI processing")
        
        return recommendations

    def get_logistics_security_dashboard(self) -> Dict:
        """
        Generate executive dashboard data focused on logistics security
        """
        try:
            cursor = self.conn.cursor()
            
            # Critical logistics threats (last 7 days)
            cursor.execute('''
                SELECT title, threat_severity, logistics_relevance, collected_at, source
                FROM raw_threats 
                WHERE logistics_relevance >= 80 
                AND collected_at > datetime('now', '-7 days')
                ORDER BY logistics_relevance DESC, collected_at DESC
                LIMIT 10
            ''')
            critical_threats = cursor.fetchall()
            
            # Threat trend analysis (last 30 days)
            cursor.execute('''
                SELECT 
                    DATE(collected_at) as date,
                    COUNT(*) as total_threats,
                    COUNT(CASE WHEN threat_severity = 'critical' THEN 1 END) as critical_count,
                    COUNT(CASE WHEN threat_severity = 'high' THEN 1 END) as high_count,
                    AVG(logistics_relevance) as avg_relevance
                FROM raw_threats 
                WHERE collected_at > datetime('now', '-30 days')
                GROUP BY DATE(collected_at)
                ORDER BY date DESC
                LIMIT 30
            ''')
            trend_data = cursor.fetchall()
            
            # Source performance for logistics threats
            cursor.execute('''
                SELECT 
                    source,
                    COUNT(*) as threat_count,
                    AVG(logistics_relevance) as avg_relevance,
                    COUNT(CASE WHEN threat_severity IN ('critical', 'high') THEN 1 END) as high_severity_count
                FROM raw_threats 
                WHERE collected_at > datetime('now', '-7 days')
                AND logistics_relevance >= 50
                GROUP BY source
                ORDER BY avg_relevance DESC, threat_count DESC
                LIMIT 10
            ''')
            source_performance = cursor.fetchall()
            
            return {
                "executive_summary": {
                    "total_critical_threats": len([t for t in critical_threats if t[1] == 'critical']),
                    "high_logistics_relevance": len(critical_threats),
                    "trending_direction": self._analyze_threat_trend(trend_data),
                    "top_threat_category": self._identify_top_threat_category(),
                    "last_updated": datetime.now().isoformat()
                },
                "critical_logistics_threats": [
                    {
                        "title": t[0][:80] + "..." if len(t[0]) > 80 else t[0],
                        "severity": t[1],
                        "logistics_relevance": t[2],
                        "date": t[3],
                        "source": t[4]
                    }
                    for t in critical_threats
                ],
                "threat_trends": [
                    {
                        "date": t[0],
                        "total": t[1],
                        "critical": t[2],
                        "high": t[3],
                        "avg_relevance": round(t[4] or 0, 1)
                    }
                    for t in trend_data
                ],
                "source_intelligence": [
                    {
                        "source": s[0],
                        "threat_count": s[1],
                        "avg_relevance": round(s[2] or 0, 1),
                        "high_severity_count": s[3],
                        "quality_rating": "⭐⭐⭐" if s[2] > 80 else "⭐⭐" if s[2] > 60 else "⭐"
                    }
                    for s in source_performance
                ],
                "logistics_focus_areas": self._get_logistics_focus_areas(),
                "dashboard_timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Logistics dashboard generation failed: {e}")
            return {
                "error": str(e),
                "executive_summary": {},
                "dashboard_timestamp": datetime.now().isoformat()
            }
        
    # Part 4E: Supporting Utility Methods - Add to ThreatDataCollector class

    def _analyze_threat_trend(self, trend_data) -> str:
        """Analyze threat trend direction over time"""
        if len(trend_data) < 3:
            return "📊 Insufficient data"
        
        recent_avg = sum(t[1] for t in trend_data[:7]) / min(7, len(trend_data))
        earlier_avg = sum(t[1] for t in trend_data[-7:]) / min(7, len(trend_data))
        
        if recent_avg > earlier_avg * 1.2:
            return "📈 Increasing threat activity"
        elif recent_avg < earlier_avg * 0.8:
            return "📉 Decreasing threat activity"
        else:
            return "➡️ Stable threat levels"

    def _identify_top_threat_category(self) -> str:
        """Identify the most prevalent threat category"""
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                SELECT source, COUNT(*) as count
                FROM raw_threats 
                WHERE collected_at > datetime('now', '-7 days')
                AND logistics_relevance >= 60
                GROUP BY source
                ORDER BY count DESC
                LIMIT 1
            ''')
            result = cursor.fetchone()
            return result[0] if result else "General cybersecurity"
        except Exception:
            return "Mixed threat categories"

    def _get_logistics_focus_areas(self) -> List[Dict]:
        """Get logistics-specific focus areas with threat counts"""
        focus_areas = [
            {
                "area": "🚢 Maritime & Ports",
                "keywords": ["maritime", "port", "shipping", "vessel", "cargo"],
                "priority": "Critical",
                "threat_count": 0
            },
            {
                "area": "🚛 Supply Chain",
                "keywords": ["supply chain", "logistics", "warehouse", "distribution"],
                "priority": "Critical", 
                "threat_count": 0
            },
            {
                "area": "🏭 Manufacturing",
                "keywords": ["manufacturing", "industrial", "production", "factory"],
                "priority": "High",
                "threat_count": 0
            },
            {
                "area": "⚡ Energy & Utilities",
                "keywords": ["energy", "power", "utility", "grid", "oil", "gas"],
                "priority": "High",
                "threat_count": 0
            },
            {
                "area": "💰 Financial Systems",
                "keywords": ["banking", "financial", "payment", "transaction"],
                "priority": "Medium",
                "threat_count": 0
            }
        ]
        
        # Count threats for each focus area
        try:
            cursor = self.conn.cursor()
            for area in focus_areas:
                keyword_conditions = " OR ".join([f"LOWER(content) LIKE '%{kw}%'" for kw in area["keywords"]])
                cursor.execute(f'''
                    SELECT COUNT(*) FROM raw_threats 
                    WHERE collected_at > datetime('now', '-7 days')
                    AND ({keyword_conditions})
                ''')
                count = cursor.fetchone()[0]
                area["threat_count"] = count
        except Exception as e:
            logger.warning(f"Failed to count threats by focus area: {e}")
        
        return focus_areas

    def _get_database_size(self) -> str:
        """Get human-readable database size"""
        try:
            import os
            size_bytes = os.path.getsize(self.db_path)
            if size_bytes < 1024:
                return f"{size_bytes} B"
            elif size_bytes < 1024**2:
                return f"{size_bytes/1024:.1f} KB"
            elif size_bytes < 1024**3:
                return f"{size_bytes/(1024**2):.1f} MB"
            else:
                return f"{size_bytes/(1024**3):.1f} GB"
        except Exception:
            return "Unknown"

    def _calculate_system_uptime(self) -> float:
        """Calculate system uptime in hours"""
        try:
            cursor = self.conn.cursor()
            cursor.execute('SELECT MIN(start_time) FROM collection_sessions')
            first_session = cursor.fetchone()[0]
            
            if first_session:
                first_dt = datetime.fromisoformat(first_session)
                uptime = (datetime.now() - first_dt).total_seconds() / 3600
                return round(uptime, 1)
            else:
                return 0.0
        except Exception:
            return 0.0

    def get_source_diagnostic_report(self) -> Dict:
        """
        Detailed diagnostic report for source troubleshooting
        """
        try:
            cursor = self.conn.cursor()
            
            # Source status overview
            cursor.execute('''
                SELECT 
                    source_name,
                    total_attempts,
                    successful_collections,
                    reliability_score,
                    last_success,
                    last_error,
                    is_active
                FROM source_intelligence
                ORDER BY reliability_score DESC, successful_collections DESC
            ''')
            source_details = cursor.fetchall()
            
            # Recent collection attempts
            cursor.execute('''
                SELECT 
                    session_id,
                    start_time,
                    end_time,
                    collection_mode,
                    sources_attempted,
                    sources_successful,
                    threats_collected,
                    session_status
                FROM collection_sessions
                ORDER BY start_time DESC
                LIMIT 10
            ''')
            recent_sessions = cursor.fetchall()
            
            # Problem source identification
            problematic_sources = [
                source for source in source_details 
                if source[3] < 0.5  # reliability_score < 50%
            ]
            
            return {
                "source_analysis": [
                    {
                        "source_name": s[0],
                        "total_attempts": s[1],
                        "successful_collections": s[2],
                        "success_rate": f"{s[3]*100:.1f}%" if s[3] else "0%",
                        "last_success": s[4],
                        "last_error": s[5],
                        "status": "🟢 Active" if s[6] else "🔴 Inactive",
                        "health": (
                            "🟢 Excellent" if s[3] > 0.8 else
                            "🟡 Good" if s[3] > 0.5 else
                            "🔴 Poor"
                        )
                    }
                    for s in source_details
                ],
                "recent_sessions": [
                    {
                        "session_id": r[0],
                        "start_time": r[1],
                        "duration": self._calculate_session_duration(r[1], r[2]),
                        "mode": r[3],
                        "success_rate": f"{(r[5]/max(r[4],1))*100:.1f}%" if r[4] > 0 else "0%",
                        "threats_collected": r[6],
                        "status": r[7]
                    }
                    for r in recent_sessions
                ],
                "diagnostics": {
                    "total_sources_configured": len(source_details),
                    "active_sources": len([s for s in source_details if s[6]]),
                    "problematic_sources": len(problematic_sources),
                    "avg_source_reliability": round(sum(s[3] for s in source_details) / max(len(source_details), 1) * 100, 1),
                    "recommendations": self._generate_source_recommendations(source_details)
                },
                "troubleshooting_steps": [
                    "1. Check network connectivity to RSS feed URLs",
                    "2. Verify RSS feed formats are valid XML",
                    "3. Test individual source URLs manually",
                    "4. Review timeout and concurrent limit settings",
                    "5. Check for rate limiting or IP blocking",
                    "6. Validate User-Agent headers and request headers"
                ],
                "diagnostic_timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Source diagnostic report failed: {e}")
            return {
                "error": str(e),
                "diagnostic_timestamp": datetime.now().isoformat()
            }

    def _calculate_session_duration(self, start_time: str, end_time: str) -> str:
        """Calculate human-readable session duration"""
        try:
            if not end_time:
                return "In Progress"
            
            start_dt = datetime.fromisoformat(start_time)
            end_dt = datetime.fromisoformat(end_time)
            duration = (end_dt - start_dt).total_seconds()
            
            if duration < 60:
                return f"{duration:.1f}s"
            elif duration < 3600:
                return f"{duration/60:.1f}m"
            else:
                return f"{duration/3600:.1f}h"
        except Exception:
            return "Unknown"

    def _generate_source_recommendations(self, source_details) -> List[str]:
        """Generate actionable recommendations for source improvement"""
        recommendations = []
        
        total_sources = len(source_details)
        active_sources = len([s for s in source_details if s[6]])
        reliable_sources = len([s for s in source_details if s[3] > 0.7])
        
        if active_sources < total_sources * 0.8:
            recommendations.append("🔧 Reactivate disabled sources or remove defunct ones")
        
        if reliable_sources < total_sources * 0.6:
            recommendations.append("🌐 Review RSS feed URLs and update broken sources")
        
        if total_sources < 10:
            recommendations.append("📈 Add more cybersecurity and logistics news sources")
        
        recent_failures = len([s for s in source_details if s[4] is None])
        if recent_failures > total_sources * 0.3:
            recommendations.append("⚠️ Investigate network connectivity or firewall issues")
        
        if not recommendations:
            recommendations.append("✅ Source configuration is healthy")
        
        return recommendations

    def cleanup_database(self, days_to_keep: int = 30) -> Dict:
        """
        Clean up old data and optimize database performance
        """
        try:
            cursor = self.conn.cursor()
            cutoff_date = (datetime.now() - timedelta(days=days_to_keep)).isoformat()
            
            # Count what will be cleaned
            cursor.execute('SELECT COUNT(*) FROM raw_threats WHERE collected_at < ?', (cutoff_date,))
            old_threats_count = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM collection_sessions WHERE start_time < ?', (cutoff_date,))
            old_sessions_count = cursor.fetchone()[0]
            
            # Perform cleanup
            cursor.execute('DELETE FROM raw_threats WHERE collected_at < ?', (cutoff_date,))
            threats_deleted = cursor.rowcount
            
            cursor.execute('DELETE FROM collection_sessions WHERE start_time < ?', (cutoff_date,))
            sessions_deleted = cursor.rowcount
            
            # Optimize database
            cursor.execute('VACUUM')
            
            self.conn.commit()
            
            logger.info(f"🧹 Database cleanup complete: {threats_deleted} old threats removed")
            
            return {
                "cleanup_successful": True,
                "threats_deleted": threats_deleted,
                "sessions_deleted": sessions_deleted,
                "days_kept": days_to_keep,
                "database_optimized": True,
                "cleanup_timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Database cleanup failed: {e}")
            return {
                "cleanup_successful": False,
                "error": str(e),
                "cleanup_timestamp": datetime.now().isoformat()
            }

    def export_threat_intelligence(self, format_type: str = "json", days: int = 7) -> Dict:
        """
        Export threat intelligence data for external systems
        """
        try:
            cursor = self.conn.cursor()
            cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()
            
            cursor.execute('''
                SELECT 
                    id, title, content, source, url, published_date, 
                    collected_at, logistics_relevance, threat_severity,
                    threat_id, is_demo
                FROM raw_threats 
                WHERE collected_at > ?
                ORDER BY logistics_relevance DESC, collected_at DESC
            ''', (cutoff_date,))
            
            threats = cursor.fetchall()
            
            export_data = [
                {
                    "threat_id": t[9] or f"T-{t[0]}",
                    "title": t[1],
                    "content": t[2],
                    "source": t[3],
                    "url": t[4],
                    "published_date": t[5],
                    "collected_at": t[6],
                    "logistics_relevance": t[7],
                    "threat_severity": t[8],
                    "is_demo": bool(t[10])
                }
                for t in threats
            ]
            
            return {
                "export_successful": True,
                "format": format_type,
                "threat_count": len(export_data),
                "date_range_days": days,
                "data": export_data,
                "export_timestamp": datetime.now().isoformat(),
                "metadata": {
                    "avg_logistics_relevance": round(sum(t[7] for t in threats) / max(len(threats), 1), 1),
                    "critical_threats": len([t for t in threats if t[8] == 'critical']),
                    "high_threats": len([t for t in threats if t[8] == 'high']),
                    "demo_threats": len([t for t in threats if t[10]])
                }
            }
            
        except Exception as e:
            logger.error(f"Threat intelligence export failed: {e}")
            return {
                "export_successful": False,
                "error": str(e),
                "export_timestamp": datetime.now().isoformat()
            }
        
    def _process_threats_with_geography(self, threats):
        """Process threats and add geographic data"""
        geo_extractor = SimpleGeoExtractor()
        processed_threats = []
        
        for threat in threats:
            try:
                # Add geographic analysis
                geo_data = geo_extractor.analyze_threat_geography(threat)
                
                # Enhance threat with geographic data
                enhanced_threat = {
                    **threat,
                    'targeted_countries': geo_data['targeted_countries'],
                    'latitude': geo_data['latitude'],
                    'longitude': geo_data['longitude'],
                    'threat_actors': geo_data['threat_actors'],
                    'confidence_score': geo_data['confidence_score']
                }
                
                # Save to processed_threats table
                self._save_processed_threat(enhanced_threat)
                processed_threats.append(enhanced_threat)
                
            except Exception as e:
                logger.warning(f"Failed to process geography for threat: {e}")
                processed_threats.append(threat)
        
        return processed_threats

    def _save_processed_threat(self, threat_data):
        """Save processed threat with geographic data to database"""
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO processed_threats (
                    raw_threat_id, threat_name, threat_type, severity,
                    targeted_countries, targeted_industries, threat_actors, attack_vectors,
                    confidence_score, latitude, longitude, analysis_timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                threat_data.get('id'),
                threat_data['title'][:100],
                'cyber_attack',
                threat_data.get('threat_severity', 'medium'),
                json.dumps(threat_data.get('targeted_countries', [])),
                json.dumps(threat_data.get('targeted_industries', [])),
                json.dumps(threat_data.get('threat_actors', [])),
                json.dumps([]),  # attack_vectors
                threat_data.get('confidence_score', 75.0),
                threat_data.get('latitude'),
                threat_data.get('longitude'),
                datetime.now().isoformat()
            ))
            self.conn.commit()
            
        except Exception as e:
            logger.warning(f"Failed to save processed threat: {e}")








class LogisticsContentFilter:
    """
    AI-enhanced content filtering for logistics company threat intelligence
    """

    def __init__(self):
        # Logistics-specific threat keywords
        self.logistics_keywords = {
            # Supply Chain & Logistics
            'supply_chain': ['supply chain', 'logistics', 'shipping', 'cargo', 'freight', 'warehouse'],
            'maritime': ['port', 'maritime', 'vessel', 'shipping', 'container', 'dock', 'harbor'],
            'transportation': ['transportation', 'trucking', 'rail', 'aviation', 'delivery', 'fleet'],
            'infrastructure': ['infrastructure', 'critical systems', 'operational technology', 'scada', 'ics'],

            # Threat Types Relevant to Logistics
            'cyber_threats': ['ransomware', 'malware', 'phishing', 'ddos', 'breach', 'attack'],
            'apt_groups': ['apt', 'state sponsored', 'nation state', 'advanced persistent'],
            'vulnerabilities': ['zero-day', 'vulnerability', 'exploit', 'cve-', 'patch'],

            # Geographic/Industry Focus
            'regions': ['global', 'international', 'asia pacific', 'europe', 'americas'],
            'industries': ['manufacturing', 'automotive', 'energy', 'retail', 'government']
        }

        # Negative keywords (less relevant for logistics)
        self.exclusion_keywords = [
            'cryptocurrency', 'bitcoin', 'gaming', 'social media', 'entertainment',
            'consumer apps', 'mobile games', 'streaming'
        ]

    def calculate_logistics_relevance(self, title: str, content: str) -> int:
        """
        Calculate logistics relevance score (0-100) for threat intelligence
        """
        text = (title + " " + content).lower()
        relevance_score = 0

        # Base score for cybersecurity content
        base_security_keywords = ['cyber', 'security', 'threat', 'attack', 'breach', 'hack']
        if any(keyword in text for keyword in base_security_keywords):
            relevance_score += 30

        # Bonus points for logistics-specific content
        for category, keywords in self.logistics_keywords.items():
            matches = sum(1 for keyword in keywords if keyword in text)
            if category in ['supply_chain', 'maritime', 'transportation']:
                relevance_score += matches * 15  # High value categories
            elif category in ['infrastructure', 'cyber_threats']:
                relevance_score += matches * 10  # Medium value
            else:
                relevance_score += matches * 5   # Standard value

        # Penalty for exclusion keywords
        exclusion_matches = sum(1 for keyword in self.exclusion_keywords if keyword in text)
        relevance_score -= exclusion_matches * 10

        # Normalize to 0-100 range
        return max(0, min(100, relevance_score))

    def is_threat_relevant(self, title: str, content: str, threshold: int = 40) -> bool:
        """
        Determine if threat intelligence is relevant for logistics company
        """
        relevance_score = self.calculate_logistics_relevance(title, content)
        return relevance_score >= threshold

    def estimate_threat_severity(self, title: str, content: str) -> str:
        """
        Estimate threat severity based on keywords and context
        """
        text = (title + " " + content).lower()

        critical_indicators = ['zero-day', 'critical vulnerability', 'active exploitation', 
                        'ransomware', 'supply chain attack', 'critical infrastructure']
        high_indicators = ['vulnerability', 'breach', 'malware', 'apt', 'attack campaign']
        medium_indicators = ['security', 'threat', 'incident', 'compromise']

        if any(indicator in text for indicator in critical_indicators):
            return 'critical'
        elif any(indicator in text for indicator in high_indicators):
            return 'high'
        elif any(indicator in text for indicator in medium_indicators):
            return 'medium'
        else:
            return 'low'
        
    def _process_threats_with_geography(self, threats):
        """Process threats and add geographic data"""
        geo_extractor = SimpleGeoExtractor()
        processed_threats = []
        
        for threat in threats:
            try:
                # Add geographic analysis
                geo_data = geo_extractor.analyze_threat_geography(threat)
                
                # Enhance threat with geographic data
                enhanced_threat = {
                    **threat,
                    'targeted_countries': geo_data['targeted_countries'],
                    'latitude': geo_data['latitude'],
                    'longitude': geo_data['longitude'],
                    'threat_actors': geo_data['threat_actors'],
                    'confidence_score': geo_data['confidence_score']
                }
                
                # Save to processed_threats table
                self._save_processed_threat(enhanced_threat)
                processed_threats.append(enhanced_threat)
                
            except Exception as e:
                logger.warning(f"Failed to process geography for threat: {e}")
                processed_threats.append(threat)
        
        return processed_threats

    def _save_processed_threat(self, threat_data):
        """Save processed threat with geographic data to database"""
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO processed_threats (
                    raw_threat_id, threat_name, threat_type, severity,
                    targeted_countries, targeted_industries, threat_actors, attack_vectors,
                    confidence_score, latitude, longitude, analysis_timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                threat_data.get('id'),
                threat_data['title'][:100],
                'cyber_attack',
                threat_data.get('threat_severity', 'medium'),
                json.dumps(threat_data.get('targeted_countries', [])),
                json.dumps(threat_data.get('targeted_industries', [])),
                json.dumps(threat_data.get('threat_actors', [])),
                json.dumps([]),  # attack_vectors
                threat_data.get('confidence_score', 75.0),
                threat_data.get('latitude'),
                threat_data.get('longitude'),
                datetime.now().isoformat()
            ))
            self.conn.commit()
            
        except Exception as e:
            logger.warning(f"Failed to save processed threat: {e}")



class LiveRSSCollector:
    """
    Asynchronous RSS collection engine with enterprise-grade error handling
    """
    
    def __init__(self, db_connection, stats: CollectionStats):
        self.conn = db_connection
        self.stats = stats
        self.content_filter = LogisticsContentFilter()
        
        # HTTP session configuration for enterprise environments
        self.headers = {
            'User-Agent': 'LogisticsThreatIntel/1.0 (Enterprise Security Team)',
            'Accept': 'application/rss+xml, application/xml, text/xml, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Cache-Control': 'no-cache'
        }

    async def collect_from_prioritized_sources(self, sources: Dict[str, Dict], 
                                             timeout: int = 10, concurrent_limit: int = 5) -> List[Dict]:
        """
        Main collection method - async collection from prioritized sources
        """
        logger.info(f"🌐 Starting live RSS collection from {len(sources)} sources")
        self.stats.sources_attempted = len(sources)
        
        # Create semaphore to limit concurrent connections
        semaphore = asyncio.Semaphore(concurrent_limit)
        
        # Create collection tasks
        tasks = []
        for source_name, source_config in sources.items():
            task = self._collect_single_source(source_name, source_config, semaphore, timeout)
            tasks.append(task)
        
        # Execute all collection tasks with timeout protection
        try:
            results = await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=timeout * len(sources)  # Overall timeout
            )
            
            # Process results
            all_threats = []
            for i, result in enumerate(results):
                source_name = list(sources.keys())[i]
                
                if isinstance(result, Exception):
                    error_msg = f"{source_name}: {str(result)[:50]}"
                    self.stats.errors.append(error_msg)
                    self.stats.source_results[source_name] = {"status": "error", "articles": 0}
                    logger.warning(f"   ❌ {error_msg}")
                    
                elif isinstance(result, list):
                    all_threats.extend(result)
                    self.stats.sources_successful += 1
                    self.stats.source_results[source_name] = {
                        "status": "success", 
                        "articles": len(result),
                        "logistics_relevant": sum(1 for t in result if t.get('logistics_relevance', 0) > 50)
                    }
                    
                    if result:
                        relevant_count = sum(1 for t in result if t.get('logistics_relevance', 0) > 50)
                        logger.info(f"   ✅ {source_name}: {len(result)} articles ({relevant_count} logistics-relevant)")
                    else:
                        logger.info(f"   ⚪ {source_name}: no relevant content found")
            
            logger.info(f"📊 Collection complete: {len(all_threats)} total threats from {self.stats.sources_successful}/{self.stats.sources_attempted} sources")
            return all_threats
            
        except asyncio.TimeoutError:
            logger.error(f"⏰ Overall collection timeout after {timeout * len(sources)}s")
            self.stats.errors.append("Overall collection timeout")
            return []
            
        except Exception as e:
            logger.error(f"❌ Collection failed: {str(e)}")
            self.stats.errors.append(f"Collection failed: {str(e)}")
            return []

    async def _collect_single_source(self, source_name: str, source_config: Dict, 
                                   semaphore: asyncio.Semaphore, timeout: int) -> List[Dict]:
        """
        Collect from a single RSS source with comprehensive error handling
        """
        async with semaphore:
            try:
                url = source_config['url']
                priority = source_config['priority']
                
                logger.debug(f"🔍 Collecting from {source_name} ({url})")
                
                # Use aiohttp for async HTTP requests
                async with aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    headers=self.headers
                ) as session:
                    
                    async with session.get(url) as response:
                        if response.status != 200:
                            self._update_source_stats(source_name, False, f"HTTP {response.status}")
                            return []
                        
                        content = await response.read()
                        
                        # Parse RSS feed in thread pool (feedparser is blocking)
                        loop = asyncio.get_event_loop()
                        with ThreadPoolExecutor(max_workers=1) as executor:
                            feed = await loop.run_in_executor(
                                executor, feedparser.parse, content
                            )
                        
                        if not feed.entries:
                            self._update_source_stats(source_name, False, "No entries in feed")
                            return []
                        
                        # Process feed entries
                        threats = []
                        for entry in feed.entries[:5]:  # Limit per source for demo
                            try:
                                threat = self._process_feed_entry(entry, source_name, source_config)
                                if threat:
                                    threats.append(threat)
                                    
                            except Exception as e:
                                logger.debug(f"Entry processing error in {source_name}: {e}")
                                continue  # Skip problematic entries
                        
                        # Update source performance statistics
                        self._update_source_stats(source_name, True)
                        self.stats.total_articles += len(feed.entries)
                        self.stats.security_articles += len(threats)
                        
                        return threats
                        
            except asyncio.TimeoutError:
                self._update_source_stats(source_name, False, "Timeout")
                return []
            except Exception as e:
                error_msg = str(e)[:50]
                self._update_source_stats(source_name, False, error_msg)
                return []

    def _process_feed_entry(self, entry, source_name: str, source_config: Dict) -> Optional[Dict]:
        """
        Process individual RSS entry into structured threat intelligence
        """
        try:
            # Extract and clean content
            title = getattr(entry, 'title', '').strip()
            if not title:
                return None
            
            content = self._extract_clean_content(entry)
            url = getattr(entry, 'link', '')
            published_date = self._parse_published_date(entry)
            
            # Calculate logistics relevance using our filter
            logistics_relevance = self.content_filter.calculate_logistics_relevance(title, content)
            
            # Apply relevance threshold - only keep logistics-relevant content
            threshold = 40  # Configurable threshold
            if logistics_relevance < threshold:
                logger.debug(f"Filtered out low-relevance content: {title[:50]}... (score: {logistics_relevance})")
                return None
            
            # Estimate threat severity
            threat_severity = self.content_filter.estimate_threat_severity(title, content)
            
            # Create threat intelligence record
            threat = {
                "title": title[:200],  # Limit title length for database
                "content": content,
                "source": source_name,
                "url": url,
                "published_date": published_date,
                "collected_at": datetime.now().isoformat(),
                "is_demo": False,
                "logistics_relevance": logistics_relevance,
                "source_priority": source_config['priority'].value,
                "content_hash": self._generate_content_hash(title, content),
                "threat_severity": threat_severity
            }
            
            # Save to database
            self._save_threat_to_db(threat)
            
            logger.debug(f"✅ Processed: {title[:50]}... (relevance: {logistics_relevance}, severity: {threat_severity})")
            return threat
            
        except Exception as e:
            logger.debug(f"Entry processing error: {e}")
            return None

    def _update_source_stats(self, source_name: str, success: bool, error_msg: str = None):
        """Update source performance statistics in database"""
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO source_intelligence 
                (source_name, total_attempts, successful_collections, last_success, last_error, reliability_score)
                VALUES (?, 
                    COALESCE((SELECT total_attempts FROM source_intelligence WHERE source_name = ?), 0) + 1,
                    COALESCE((SELECT successful_collections FROM source_intelligence WHERE source_name = ?), 0) + ?,
                    ?, ?, 
                    CAST(COALESCE((SELECT successful_collections FROM source_intelligence WHERE source_name = ?), 0) + ? AS REAL) / 
                    (COALESCE((SELECT total_attempts FROM source_intelligence WHERE source_name = ?), 0) + 1)
                )
            ''', (
                source_name, source_name, source_name, 1 if success else 0,
                datetime.now().isoformat() if success else None,
                error_msg if not success else None,
                source_name, 1 if success else 0, source_name
            ))
            self.conn.commit()
        except Exception as e:
            logger.debug(f"Stats update error: {e}")

    # Part 2D: Content Processing Utilities - Add to existing file

    def _extract_clean_content(self, entry) -> str:
        """
        Extract and clean content from RSS entry with multiple fallbacks
        """
        content = ""
        
        # Try different content fields in order of preference
        if hasattr(entry, 'content') and entry.content:
            if isinstance(entry.content, list):
                content = entry.content[0].value
            else:
                content = entry.content
        elif hasattr(entry, 'summary') and entry.summary:
            content = entry.summary
        elif hasattr(entry, 'description') and entry.description:
            content = entry.description
        else:
            content = getattr(entry, 'title', '')
        
        # Clean HTML tags and normalize whitespace
        if content:
            try:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(content, 'html.parser')
                clean_content = soup.get_text(separator=' ', strip=True)
                # Remove extra whitespace and limit length
                clean_content = ' '.join(clean_content.split())
                return clean_content[:1500]  # Reasonable content limit
            except:
                # Fallback HTML cleaning
                import re
                clean_content = re.sub(r'<[^>]+>', ' ', content)
                clean_content = ' '.join(clean_content.split())
                return clean_content[:1500]
        
        return ""

    def _parse_published_date(self, entry) -> str:
        """
        Parse published date with multiple format support
        """
        try:
            if hasattr(entry, 'published_parsed') and entry.published_parsed:
                import time
                timestamp = time.mktime(entry.published_parsed)
                return datetime.fromtimestamp(timestamp).isoformat()
            elif hasattr(entry, 'published'):
                # Try to parse various date formats
                from email.utils import parsedate_to_datetime
                return parsedate_to_datetime(entry.published).isoformat()
        except:
            pass
        
        # Fallback to current time
        return datetime.now().isoformat()

    def _generate_content_hash(self, title: str, content: str) -> str:
        """
        Generate hash for duplicate detection
        """
        combined_content = title + content
        return hashlib.md5(combined_content.encode()).hexdigest()

    def _save_threat_to_db(self, threat: Dict):
        """
        Save threat intelligence to database with duplicate prevention
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT OR IGNORE INTO raw_threats 
                (title, content, source, url, published_date, collected_at, 
                 is_demo, logistics_relevance, source_priority, content_hash, threat_severity)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                threat['title'],
                threat['content'],
                threat['source'],
                threat['url'],
                threat['published_date'],
                threat['collected_at'],
                threat['is_demo'],
                threat['logistics_relevance'],
                threat['source_priority'],
                threat['content_hash'],
                threat['threat_severity']
            ))
            self.conn.commit()
            
        except Exception as e:
            logger.warning(f"Database save error: {str(e)[:50]}")

    def get_collection_health_report(self) -> Dict:
        """
        Generate health report for enterprise monitoring
        """
        try:
            cursor = self.conn.cursor()
            
            # Recent collection stats (last 24 hours)
            cutoff_24h = (datetime.now() - timedelta(hours=24)).isoformat()
            cursor.execute('''
                SELECT COUNT(*) FROM raw_threats 
                WHERE collected_at > ? AND is_demo = FALSE
            ''', (cutoff_24h,))
            live_threats_24h = cursor.fetchone()[0]
            
            # Logistics relevance breakdown
            cursor.execute('''
                SELECT 
                    AVG(logistics_relevance) as avg_relevance,
                    COUNT(CASE WHEN logistics_relevance >= 70 THEN 1 END) as high_relevance,
                    COUNT(CASE WHEN logistics_relevance >= 40 THEN 1 END) as medium_relevance
                FROM raw_threats 
                WHERE collected_at > ? AND is_demo = FALSE
            ''', (cutoff_24h,))
            relevance_stats = cursor.fetchone()
            
            # Source reliability
            cursor.execute('''
                SELECT 
                    COUNT(*) as total_sources,
                    AVG(reliability_score) as avg_reliability,
                    COUNT(CASE WHEN reliability_score > 0.8 THEN 1 END) as reliable_sources
                FROM source_intelligence 
                WHERE is_active = TRUE
            ''')
            source_stats = cursor.fetchone()
            
            return {
                "collection_health": {
                    "live_threats_24h": live_threats_24h,
                    "avg_logistics_relevance": round(relevance_stats[0] or 0, 1),
                    "high_relevance_threats": relevance_stats[1] or 0,
                    "medium_relevance_threats": relevance_stats[2] or 0
                },
                "source_health": {
                    "total_active_sources": source_stats[0] or 0,
                    "avg_reliability": round(source_stats[1] or 0, 2),
                    "reliable_sources": source_stats[2] or 0
                },
                "system_status": "healthy" if live_threats_24h > 10 else "warning",
                "last_updated": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Health report generation failed: {e}")
            return {"error": str(e), "system_status": "error"}


class LogisticsDemoDataManager:
    """
    Professional demo data manager for logistics company presentations
    Creates realistic threat intelligence scenarios specific to supply chain security
    """
    
    def __init__(self, db_connection):
        self.conn = db_connection
        self.demo_threats_generated = False
        logger.info("📋 Demo data manager initialized for logistics company")
        
    def _generate_realistic_timestamps(self, count: int) -> List[str]:
        """
        Generate realistic timestamps spread over recent days with clustering for campaigns
        """
        
        
        base_time = datetime.now()
        timestamps = []
        
        # Create some clustering to simulate real threat campaigns
        campaign_days = [0, 0, 1, 1, 2, 3]  # More threats on recent days
        
        for i in range(count):
            if i < len(campaign_days):
                days_ago = campaign_days[i]
            else:
                days_ago = random.choice([3, 4, 5, 6, 7])
            
            hours_ago = random.randint(0, 23)
            minutes_ago = random.randint(0, 59)
            
            timestamp = base_time - timedelta(
                days=days_ago,
                hours=hours_ago,
                minutes=minutes_ago
            )
            timestamps.append(timestamp.isoformat())
        
        return timestamps

    def _determine_source_priority(self, source_name: str) -> int:
        """
        Determine source priority based on source type for logistics relevance
        """
        priority_mapping = {
            "maritime_threat_intel": SourcePriority.CRITICAL.value,
            "manufacturing_security_intel": SourcePriority.HIGH.value,
            "supply_chain_intel": SourcePriority.CRITICAL.value,
            "financial_threat_intel": SourcePriority.HIGH.value,
            "vehicle_security_intel": SourcePriority.HIGH.value,
            "energy_logistics_intel": SourcePriority.HIGH.value
        }
        return priority_mapping.get(source_name, SourcePriority.MEDIUM.value)

    def _generate_content_hash(self, title: str, content: str) -> str:
        """Generate unique hash for demo content"""
        combined = f"DEMO-{title}-{content}"
        return hashlib.md5(combined.encode()).hexdigest()

    def _save_demo_threat_to_db(self, threat: Dict):
        """
        Save demo threat to database with all metadata
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO raw_threats 
                (title, content, source, url, published_date, collected_at, 
                 is_demo, logistics_relevance, source_priority, content_hash, threat_severity)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                threat['title'],
                threat['content'],
                threat['source'],
                threat['url'],
                threat['published_date'],
                threat['collected_at'],
                threat['is_demo'],
                threat['logistics_relevance'],
                threat['source_priority'],
                threat['content_hash'],
                threat['threat_severity']
            ))
            self.conn.commit()
            
        except Exception as e:
            logger.error(f"Demo threat save error: {e}")
            raise

    def get_maritime_supply_chain_threats(self) -> List[Dict]:
        """
        Generate maritime and supply chain focused demo threats
        """
        return [
            {
                "title": "APT40 Maritime Logistics Espionage Campaign 'DeepWater' Targets Global Ports",
                "content": "Chinese state-sponsored APT40 conducting sophisticated espionage campaign against global maritime logistics companies and port authorities. Campaign 'DeepWater' targets shipping manifests, cargo tracking systems, and port operational technology networks. Custom malware 'PortStorm' provides persistent access to container management systems and vessel traffic control. Attacks correlate with Chinese Belt and Road Initiative shipping routes and strategic port acquisitions. Over 15 major ports across US, Europe, and Asia-Pacific compromised. Industrial control systems for automated cranes and cargo handling equipment showing unauthorized access patterns.",
                "source": "maritime_threat_intel",
                "severity": "critical",
                "countries": ["US", "SG", "NL", "AE", "GR", "DE", "AU"],
                "industries": ["maritime", "logistics", "shipping", "ports", "supply_chain"],
                "threat_actors": ["APT40", "Leviathan", "Kryptonite Panda"],
                "attack_vectors": ["watering_hole", "supply_chain", "ot_compromise", "credential_harvesting"],
                "iocs": ["portstorm.dll", "cargo-tracker.maritime.com", "crane_control_backdoor"],
                "coordinates": {"lat": 1.3521, "lng": 103.8198},  # Singapore Port
                "logistics_relevance": 98,
                "threat_severity": "critical"
            },
            {
                "title": "Supply Chain Compromise: SolarWinds-Style Attack Affects Logistics Software Vendors",
                "content": "Coordinated supply chain attack compromising software build systems of multiple logistics and transportation management software vendors. Malicious code injected into legitimate software updates affecting fleet management, warehouse management, and cargo tracking systems used by thousands of logistics companies globally. Attack attributed to state-sponsored actors targeting transportation infrastructure. Compromised packages include popular TMS (Transportation Management System) and WMS (Warehouse Management System) solutions with over 5 million combined installations.",
                "source": "supply_chain_intel",
                "severity": "critical",
                "countries": ["US", "CA", "GB", "DE", "FR", "AU"],
                "industries": ["logistics", "transportation", "software", "supply_chain", "warehousing"],
                "threat_actors": ["Supply Chain Attackers", "State Sponsored", "Advanced Persistent Threat"],
                "attack_vectors": ["supply_chain", "software_compromise", "build_system_intrusion", "update_mechanism"],
                "iocs": ["malicious_tms_update.tar.gz", "build_inject.sh", "logistics_backdoor.dll"],
                "coordinates": {"lat": 37.7749, "lng": -122.4194},  # San Francisco Tech Hub
                "logistics_relevance": 100,
                "threat_severity": "critical"
            },
            {
                "title": "Zero-Day Vulnerability Chain in Enterprise Fleet Management Software Under Active Exploitation",
                "content": "Critical zero-day vulnerability chain (CVE-2024-0001 through CVE-2024-0003) discovered in popular fleet management and vehicle tracking software used by major logistics companies worldwide. Vulnerabilities allow unauthenticated remote code execution with system privileges on fleet management servers. Active exploitation detected with custom exploit tools targeting GPS tracking data, route optimization systems, and driver management databases. Over 50,000 commercial vehicles across North America and Europe potentially affected. No patches currently available as vendors work on emergency updates.",
                "source": "vehicle_security_intel",
                "severity": "critical",
                "countries": ["US", "CA", "GB", "DE", "FR", "NL", "SE"],
                "industries": ["logistics", "transportation", "fleet_management", "trucking", "delivery"],
                "threat_actors": ["Unknown APT", "Fleet Exploitation Group", "Vehicle System Hackers"],
                "attack_vectors": ["zero_day_exploit", "remote_code_execution", "fleet_system_compromise", "gps_manipulation"],
                "iocs": ["fleet_exploit.py", "gps_tracker_backdoor.bin", "route_hijack.dll"],
                "coordinates": {"lat": 39.8283, "lng": -98.5795},  # US Transportation Hub
                "logistics_relevance": 92,
                "threat_severity": "critical"
            }
        ]

    def get_manufacturing_energy_threats(self) -> List[Dict]:
        """
        Generate manufacturing and energy sector demo threats
        """
        return [
            {
                "title": "Conti Ransomware Successor 'BlackBasta' Targets Critical Manufacturing Supply Chains",
                "content": "BlackBasta ransomware group, formed from former Conti operators, launching coordinated attacks against automotive and aerospace manufacturing facilities worldwide. New 'ManufacturingLock' variant specifically designed to halt production lines, corrupt quality control systems, and steal proprietary manufacturing processes. Attacks leverage compromised industrial IoT devices and unsecured HMI interfaces to gain initial access. Group demands ransoms exceeding $10M and threatens to leak sensitive manufacturing data. Recent victims include major automotive suppliers in Germany, aerospace manufacturers in Washington state, and semiconductor facilities in Taiwan.",
                "source": "manufacturing_security_intel",
                "severity": "high",
                "countries": ["US", "DE", "JP", "TW", "MX", "TH"],
                "industries": ["automotive", "aerospace", "semiconductor", "manufacturing", "industrial"],
                "threat_actors": ["BlackBasta", "Conti Successors", "ManufacturingLock Group"],
                "attack_vectors": ["iot_compromise", "hmi_exploitation", "ransomware", "supply_chain_disruption"],
                "iocs": ["manufacturinglock.exe", "production_halt.dll", "iot_backdoor.bin"],
                "coordinates": {"lat": 42.3314, "lng": -83.0458},  # Detroit Manufacturing Hub
                "logistics_relevance": 95,
                "threat_severity": "high"
            },
            {
                "title": "Iranian APT35 'Charming Kitten' Targets Energy Sector Supply Chain with OT-Focused Malware",
                "content": "Iranian state-sponsored APT35 launching targeted attacks against energy sector organizations and their logistics partners with new operational technology (OT) focused malware suite called 'PowerGrid'. Campaign specifically targets SCADA systems controlling oil and gas pipeline infrastructure, energy transportation networks, and fuel distribution systems. Attacks begin with social engineering against logistics coordinators and operations managers using LinkedIn and professional networking. Custom malware can manipulate pipeline flow controls, fuel transportation schedules, and distribution logistics systems.",
                "source": "energy_logistics_intel",
                "severity": "high",
                "countries": ["US", "NO", "SA", "AE", "KW", "QA", "CA"],
                "industries": ["energy", "oil_gas", "pipeline", "fuel_distribution", "logistics"],
                "threat_actors": ["APT35", "Charming Kitten", "PowerGrid Operators", "Phosphorus"],
                "attack_vectors": ["social_engineering", "ot_malware", "scada_manipulation", "pipeline_systems"],
                "iocs": ["powergrid_controller.exe", "pipeline_backdoor.dll", "fuel_logistics_trojan.py"],
                "coordinates": {"lat": 29.7604, "lng": -95.3698},  # Houston Energy Hub
                "logistics_relevance": 88,
                "threat_severity": "high"
            },
            {
                "title": "Lazarus Group Cryptocurrency Exchange Supply Chain Attack Targets Logistics Payment Systems",
                "content": "North Korean state-sponsored Lazarus Group executing sophisticated attacks against cryptocurrency exchanges and payment systems used by logistics companies for international transactions. Campaign uses trojanized trading software updates and compromised payment processing APIs. New macOS and Windows implants feature blockchain analysis tools and direct wallet manipulation capabilities. Financial impact estimated at $150M+ across 12 exchanges and payment processors. Group specifically targeting logistics companies using cryptocurrency for cross-border payments and freight settlements.",
                "source": "financial_threat_intel",
                "severity": "high",
                "countries": ["KR", "JP", "SG", "HK", "US", "CA"],
                "industries": ["logistics", "fintech", "cryptocurrency", "international_trade", "freight"],
                "threat_actors": ["Lazarus Group", "Hidden Cobra", "APT38"],
                "attack_vectors": ["supply_chain", "trojanized_software", "payment_system_compromise", "cryptocurrency_theft"],
                "iocs": ["logistics_payment_trojan.dmg", "blockchain_analyzer.exe", "freight_payment_backdoor"],
                "coordinates": {"lat": 37.5665, "lng": 126.9780},  # Seoul Financial District
                "logistics_relevance": 85,
                "threat_severity": "high"
            }
        ]

    def get_professional_demo_threats(self) -> List[Dict]:
        """
        Combine all demo threat categories for comprehensive dataset
        """
        all_threats = []
        all_threats.extend(self.get_maritime_supply_chain_threats())
        all_threats.extend(self.get_manufacturing_energy_threats())
        
        logger.info(f"Generated {len(all_threats)} professional demo threats for logistics company")
        return all_threats

    def add_demo_data_to_database(self) -> int:
        """
        Add professional demo threats to database with realistic metadata
        """
        if self.demo_threats_generated:
            logger.info("Demo data already exists, skipping generation")
            return 0
            
        logger.info("🎭 Generating professional logistics demo dataset...")
        
        demo_threats = self.get_professional_demo_threats()
        timestamps = self._generate_realistic_timestamps(len(demo_threats))
        
        count = 0
        for i, threat in enumerate(demo_threats):
            try:
                # Enrich with realistic metadata
                enriched_threat = {
                    **threat,
                    "collected_at": timestamps[i],
                    "published_date": timestamps[i],
                    "url": f"https://threat-intel.enterprise.local/{threat['source']}/{i+1}",
                    "is_demo": True,
                    "content_hash": self._generate_content_hash(threat['title'], threat['content']),
                    "source_priority": self._determine_source_priority(threat['source']),
                    "threat_id": f"DEMO-{datetime.now().strftime('%Y')}-{1000 + i}"
                }
                
                self._save_demo_threat_to_db(enriched_threat)
                count += 1
                
            except Exception as e:
                logger.warning(f"Failed to save demo threat {i}: {e}")
                continue
        
        self.demo_threats_generated = True
        logger.info(f"✅ {count} professional demo threats added to database")
        return count

    def get_demo_statistics(self) -> Dict:
        """
        Generate comprehensive statistics for demo data presentation
        """
        try:
            cursor = self.conn.cursor()
            
            # Demo data overview
            cursor.execute('''
                SELECT 
                    COUNT(*) as total_demo_threats,
                    COUNT(CASE WHEN threat_severity = 'critical' THEN 1 END) as critical_threats,
                    COUNT(CASE WHEN threat_severity = 'high' THEN 1 END) as high_threats,
                    AVG(logistics_relevance) as avg_logistics_relevance,
                    COUNT(DISTINCT source) as unique_sources
                FROM raw_threats 
                WHERE is_demo = TRUE
            ''')
            overview = cursor.fetchone()
            
            # Source distribution
            cursor.execute('''
                SELECT source, COUNT(*) as threat_count 
                FROM raw_threats 
                WHERE is_demo = TRUE 
                GROUP BY source 
                ORDER BY threat_count DESC
            ''')
            source_distribution = dict(cursor.fetchall())
            
            # Severity breakdown
            cursor.execute('''
                SELECT threat_severity, COUNT(*) as count
                FROM raw_threats 
                WHERE is_demo = TRUE 
                GROUP BY threat_severity
            ''')
            severity_breakdown = dict(cursor.fetchall())
            
            # Recent demo activity timeline
            cursor.execute('''
                SELECT 
                    DATE(collected_at) as date,
                    COUNT(*) as threats_per_day,
                    COUNT(CASE WHEN threat_severity = 'critical' THEN 1 END) as critical_per_day
                FROM raw_threats 
                WHERE is_demo = TRUE 
                GROUP BY DATE(collected_at) 
                ORDER BY date DESC 
                LIMIT 7
            ''')
            timeline_data = cursor.fetchall()
            timeline = {row[0]: {"total": row[1], "critical": row[2]} for row in timeline_data}
            
            return {
                "overview": {
                    "total_threats": overview[0] or 0,
                    "critical_threats": overview[1] or 0,
                    "high_threats": overview[2] or 0,
                    "avg_logistics_relevance": round(overview[3] or 0, 1),
                    "unique_sources": overview[4] or 0
                },
                "source_distribution": source_distribution,
                "severity_breakdown": severity_breakdown,
                "timeline": timeline,
                "data_quality": {
                    "professional_grade": True,
                    "logistics_focused": True,
                    "realistic_scenarios": True,
                    "enterprise_ready": True
                },
                "last_updated": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Demo statistics generation failed: {e}")
            return {
                "error": str(e),
                "overview": {},
                "source_distribution": {},
                "severity_breakdown": {},
                "timeline": {}
            }

    def validate_demo_data_quality(self) -> Dict:
        """
        Validate demo data quality for enterprise presentation
        """
        try:
            cursor = self.conn.cursor()
            
            # Content quality checks
            cursor.execute('''
                SELECT 
                    AVG(LENGTH(content)) as avg_content_length,
                    MIN(LENGTH(content)) as min_content_length,
                    MAX(LENGTH(content)) as max_content_length,
                    COUNT(CASE WHEN LENGTH(content) > 200 THEN 1 END) as detailed_threats
                FROM raw_threats 
                WHERE is_demo = TRUE
            ''')
            content_quality = cursor.fetchone()
            
            # Logistics relevance validation
            cursor.execute('''
                SELECT 
                    COUNT(CASE WHEN logistics_relevance >= 80 THEN 1 END) as high_relevance,
                    COUNT(CASE WHEN logistics_relevance >= 60 THEN 1 END) as medium_relevance,
                    COUNT(CASE WHEN logistics_relevance < 60 THEN 1 END) as low_relevance,
                    AVG(logistics_relevance) as avg_relevance
                FROM raw_threats 
                WHERE is_demo = TRUE
            ''')
            relevance_quality = cursor.fetchone()
            
            # Data completeness check
            cursor.execute('''
                SELECT 
                    COUNT(CASE WHEN title IS NOT NULL AND LENGTH(title) > 10 THEN 1 END) as valid_titles,
                    COUNT(CASE WHEN content IS NOT NULL AND LENGTH(content) > 100 THEN 1 END) as valid_content,
                    COUNT(CASE WHEN source IS NOT NULL THEN 1 END) as valid_sources,
                    COUNT(*) as total_records
                FROM raw_threats 
                WHERE is_demo = TRUE
            ''')
            completeness = cursor.fetchone()
            
            # Calculate quality scores
            content_score = 100 if content_quality[0] > 300 else 85
            relevance_score = 100 if relevance_quality[3] > 80 else 90
            completeness_score = (completeness[0] + completeness[1] + completeness[2]) / (completeness[3] * 3) * 100
            
            overall_quality = (content_score + relevance_score + completeness_score) / 3
            
            return {
                "overall_quality_score": round(overall_quality, 1),
                "content_quality": {
                    "avg_length": round(content_quality[0] or 0, 0),
                    "min_length": content_quality[1] or 0,
                    "max_length": content_quality[2] or 0,
                    "detailed_count": content_quality[3] or 0,
                    "score": content_score
                },
                "logistics_relevance": {
                    "high_relevance_count": relevance_quality[0] or 0,
                    "medium_relevance_count": relevance_quality[1] or 0,
                    "low_relevance_count": relevance_quality[2] or 0,
                    "avg_relevance": round(relevance_quality[3] or 0, 1),
                    "score": relevance_score
                },
                "data_completeness": {
                    "valid_titles": completeness[0] or 0,
                    "valid_content": completeness[1] or 0,
                    "valid_sources": completeness[2] or 0,
                    "total_records": completeness[3] or 0,
                    "score": round(completeness_score, 1)
                },
                "quality_status": "Excellent" if overall_quality > 90 else "Good" if overall_quality > 80 else "Fair",
                "validation_timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Demo data validation failed: {e}")
            return {
                "error": str(e),
                "overall_quality_score": 0,
                "quality_status": "Error"
            }

    def get_recent_threats(self, limit: int = 20, demo_only: bool = False) -> List[Dict]:
        """
        Retrieve recent threats with option to filter demo data
        """
        try:
            cursor = self.conn.cursor()
            
            where_clause = "WHERE is_demo = TRUE" if demo_only else ""
            
            cursor.execute(f'''
                SELECT 
                    id, title, content, source, url, published_date, 
                    collected_at, logistics_relevance, threat_severity,
                    source_priority, is_demo
                FROM raw_threats 
                {where_clause}
                ORDER BY collected_at DESC 
                LIMIT ?
            ''', (limit,))
            
            threats = cursor.fetchall()
            return [
                {
                    'id': t[0], 'title': t[1], 'content': t[2][:500] + "..." if len(t[2]) > 500 else t[2],
                    'source': t[3], 'url': t[4], 'published_date': t[5], 
                    'collected_at': t[6], 'logistics_relevance': t[7], 'threat_severity': t[8],
                    'source_priority': t[9], 'is_demo': bool(t[10])
                } 
                for t in threats
            ]
            
        except Exception as e:
            logger.error(f"Failed to retrieve recent threats: {e}")
            return []

    def get_logistics_relevant_threats(self, min_relevance: int = 70, limit: int = 10) -> List[Dict]:
        """
        Get threats with high logistics relevance for executive dashboard
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                SELECT 
                    id, title, content, source, threat_severity,
                    logistics_relevance, collected_at, is_demo
                FROM raw_threats 
                WHERE logistics_relevance >= ?
                ORDER BY logistics_relevance DESC, collected_at DESC
                LIMIT ?
            ''', (min_relevance, limit))
            
            threats = cursor.fetchall()
            return [
                {
                    'id': t[0], 'title': t[1], 'content': t[2][:300] + "..." if len(t[2]) > 300 else t[2],
                    'source': t[3], 'threat_severity': t[4], 'logistics_relevance': t[5],
                    'collected_at': t[6], 'is_demo': bool(t[7])
                }
                for t in threats
            ]
            
        except Exception as e:
            logger.error(f"Failed to retrieve logistics relevant threats: {e}")
            return []

    def cleanup_old_demo_data(self, days_old: int = 30) -> int:
        """
        Clean up old demo data to keep database fresh
        """
        try:
            cutoff_date = (datetime.now() - timedelta(days=days_old)).isoformat()
            cursor = self.conn.cursor()
            
            cursor.execute('''
                DELETE FROM raw_threats 
                WHERE is_demo = TRUE AND collected_at < ?
            ''', (cutoff_date,))
            
            deleted_count = cursor.rowcount
            self.conn.commit()
            
            if deleted_count > 0:
                logger.info(f"🧹 Cleaned up {deleted_count} old demo threats (older than {days_old} days)")
                self.demo_threats_generated = False  # Allow regeneration
            
            return deleted_count
            
        except Exception as e:
            logger.error(f"Failed to cleanup old demo data: {e}")
            return 0
        

class SimpleGeoExtractor:
    """
    Geographic data extractor for threat intelligence
    Extracts country/location information from threat text
    """
    
    def __init__(self):
        # Country mapping with coordinates
        self.country_coords = {
            'US': {'lat': 39.8283, 'lng': -98.5795, 'name': 'United States'},
            'CN': {'lat': 35.8617, 'lng': 104.1954, 'name': 'China'},
            'RU': {'lat': 61.5240, 'lng': 105.3188, 'name': 'Russia'},
            'DE': {'lat': 51.1657, 'lng': 10.4515, 'name': 'Germany'},
            'FR': {'lat': 46.6034, 'lng': 1.8883, 'name': 'France'},
            'GB': {'lat': 55.3781, 'lng': -3.4360, 'name': 'United Kingdom'},
            'JP': {'lat': 36.2048, 'lng': 138.2529, 'name': 'Japan'},
            'KR': {'lat': 35.9078, 'lng': 127.7669, 'name': 'South Korea'},
            'IN': {'lat': 20.5937, 'lng': 78.9629, 'name': 'India'},
            'BR': {'lat': -14.2350, 'lng': -51.9253, 'name': 'Brazil'},
            'CA': {'lat': 56.1304, 'lng': -106.3468, 'name': 'Canada'},
            'AU': {'lat': -25.2744, 'lng': 133.7751, 'name': 'Australia'},
            'NL': {'lat': 52.1326, 'lng': 5.2913, 'name': 'Netherlands'},
            'IT': {'lat': 41.8719, 'lng': 12.5674, 'name': 'Italy'},
            'ES': {'lat': 40.4637, 'lng': -3.7492, 'name': 'Spain'},
            'SG': {'lat': 1.3521, 'lng': 103.8198, 'name': 'Singapore'},
            'AE': {'lat': 23.4241, 'lng': 53.8478, 'name': 'UAE'},
            'MX': {'lat': 23.6345, 'lng': -102.5528, 'name': 'Mexico'},
            'TH': {'lat': 15.8700, 'lng': 100.9925, 'name': 'Thailand'},
            'TW': {'lat': 23.6978, 'lng': 120.9605, 'name': 'Taiwan'},
        }
        
        # Location keywords for detection
        self.location_patterns = {
            'US': ['US', 'USA', 'United States', 'America', 'American'],
            'CN': ['CN', 'China', 'Chinese', 'Beijing'],
            'RU': ['RU', 'Russia', 'Russian', 'Moscow'],
            'DE': ['DE', 'Germany', 'German', 'Berlin'],
            'FR': ['FR', 'France', 'French', 'Paris'],
            'GB': ['GB', 'UK', 'Britain', 'British', 'England', 'London'],
            'JP': ['JP', 'Japan', 'Japanese', 'Tokyo'],
            'KR': ['KR', 'Korea', 'Korean', 'Seoul'],
            'IN': ['IN', 'India', 'Indian', 'Mumbai', 'Delhi'],
            'BR': ['BR', 'Brazil', 'Brazilian'],
            'CA': ['CA', 'Canada', 'Canadian'],
            'AU': ['AU', 'Australia', 'Australian'],
            'NL': ['NL', 'Netherlands', 'Dutch', 'Amsterdam'],
            'IT': ['IT', 'Italy', 'Italian', 'Rome'],
            'ES': ['ES', 'Spain', 'Spanish', 'Madrid'],
            'SG': ['SG', 'Singapore'],
            'AE': ['AE', 'UAE', 'Dubai', 'Emirates'],
            'MX': ['MX', 'Mexico', 'Mexican'],
            'TH': ['TH', 'Thailand', 'Thai'],
            'TW': ['TW', 'Taiwan', 'Taiwanese'],
        }

    def extract_countries(self, text):
        """Extract countries mentioned in threat text"""
        found_countries = []
        text_upper = text.upper()
        
        for country_code, patterns in self.location_patterns.items():
            for pattern in patterns:
                if pattern.upper() in text_upper:
                    if country_code not in found_countries:
                        found_countries.append(country_code)
                    break
        
        return found_countries

    def get_primary_coordinates(self, countries):
        """Get primary coordinates from detected countries"""
        if not countries:
            return None, None
        
        # Use first detected country as primary location
        primary_country = countries[0]
        if primary_country in self.country_coords:
            coords = self.country_coords[primary_country]
            return coords['lat'], coords['lng']
        
        return None, None

    def analyze_threat_geography(self, threat_data):
        """Analyze threat for geographic and logistics relevance"""
        text = f"{threat_data['title']} {threat_data.get('content', '')}"
        
        # Extract countries
        countries = self.extract_countries(text)
        
        # Get primary coordinates
        lat, lng = self.get_primary_coordinates(countries)
        
        # Determine threat actors based on text analysis
        threat_actors = []
        actor_keywords = {
            'APT40': ['apt40', 'leviathan', 'kryptonite panda'],
            'APT35': ['apt35', 'charming kitten', 'phosphorus'],
            'Lazarus': ['lazarus', 'hidden cobra', 'apt38'],
            'BlackBasta': ['blackbasta', 'black basta'],
            'Conti': ['conti', 'ryuk'],
        }
        
        text_lower = text.lower()
        for actor, keywords in actor_keywords.items():
            if any(keyword in text_lower for keyword in keywords):
                threat_actors.append(actor)
        
        return {
            'targeted_countries': countries,
            'latitude': lat,
            'longitude': lng,
            'threat_actors': threat_actors,
            'confidence_score': 80.0 if lat and lng else 60.0
        }
