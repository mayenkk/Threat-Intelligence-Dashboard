import sqlite3
import os
from datetime import datetime

def create_database():
    """
    Create the complete threat intelligence database with all required tables
    """
    # Ensure data directory exists
    os.makedirs('../data', exist_ok=True)
    
    # Connect to database (creates file if doesn't exist)
    conn = sqlite3.connect('../data/threats.db')
    cursor = conn.cursor()
    
    print("🗄️ Creating threat intelligence database...")
    
    # 1. Raw threats table (from data collector)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS raw_threats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT,
            source TEXT,
            url TEXT UNIQUE,
            published_date TEXT,
            collected_at TEXT,
            processed BOOLEAN DEFAULT FALSE,
            is_demo BOOLEAN DEFAULT FALSE,
            feed_status TEXT DEFAULT 'active',
            threat_severity TEXT DEFAULT 'medium',
            logistics_relevance INTEGER DEFAULT 50,
            threat_id TEXT
        )
    ''')
    
    # 2. Source reliability tracking
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS source_stats (
            source_name TEXT PRIMARY KEY,
            total_attempts INTEGER DEFAULT 0,
            successful_collections INTEGER DEFAULT 0,
            last_success TEXT,
            last_error TEXT,
            reliability_score REAL DEFAULT 1.0
        )
    ''')
    
    # 3. Collection sessions (from Part 4)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS collection_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT UNIQUE,
            start_time TEXT,
            end_time TEXT,
            collection_mode TEXT,
            sources_attempted INTEGER DEFAULT 0,
            sources_successful INTEGER DEFAULT 0,
            threats_collected INTEGER DEFAULT 0,
            avg_logistics_relevance REAL DEFAULT 0,
            session_status TEXT DEFAULT 'in_progress',
            error_messages TEXT
        )
    ''')
    
    # 4. Source intelligence (enhanced tracking)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS source_intelligence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_name TEXT UNIQUE,
            url TEXT,
            category TEXT,
            priority_level TEXT DEFAULT 'medium',
            is_active BOOLEAN DEFAULT TRUE,
            total_attempts INTEGER DEFAULT 0,
            successful_collections INTEGER DEFAULT 0,
            reliability_score REAL DEFAULT 1.0,
            last_success TEXT,
            last_error TEXT,
            avg_threats_per_collection REAL DEFAULT 0,
            created_at TEXT,
            updated_at TEXT
        )
    ''')
    
    # 5. AI analysis results (for future Vertex AI integration)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ai_threat_analysis (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            raw_threat_id INTEGER,
            threat_name TEXT,
            threat_type TEXT,
            severity TEXT,
            logistics_relevance_score INTEGER,
            business_impact_assessment TEXT,
            targeted_countries TEXT,
            targeted_industries TEXT,
            threat_actors TEXT,
            attack_vectors TEXT,
            iocs TEXT,
            maritime_specific_risk INTEGER,
            supply_chain_risk INTEGER,
            operational_impact TEXT,
            recommended_actions TEXT,
            executive_summary TEXT,
            confidence_score REAL,
            ai_model_version TEXT,
            analysis_timestamp TEXT,
            FOREIGN KEY (raw_threat_id) REFERENCES raw_threats (id)
        )
    ''')
    
    # Create indexes for better performance
    print("📊 Creating database indexes...")
    
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_threats_collected_at ON raw_threats(collected_at)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_threats_source ON raw_threats(source)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_threats_severity ON raw_threats(threat_severity)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_threats_logistics_relevance ON raw_threats(logistics_relevance)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_start_time ON collection_sessions(start_time)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_ai_analysis_relevance ON ai_threat_analysis(logistics_relevance_score)')
    
    # Insert initial source configurations
    print("🌐 Configuring initial threat intelligence sources...")
    
    initial_sources = [
        ("the_hacker_news", "https://feeds.feedburner.com/TheHackersNews", "cybersecurity_news", "high"),
        ("krebs_security", "https://krebsonsecurity.com/feed/", "cybersecurity_news", "high"),
        ("bleeping_computer", "https://www.bleepingcomputer.com/feed/", "cybersecurity_news", "high"),
        ("security_week", "https://feeds.feedburner.com/Securityweek", "cybersecurity_news", "high"),
        ("schneier", "https://www.schneier.com/feed/", "security_blog", "medium"),
        ("sans_isc", "https://isc.sans.edu/rssfeed.xml", "security_research", "high"),
        ("malwarebytes", "https://www.malwarebytes.com/blog/feed/index.xml", "malware_research", "medium"),
        ("exploit_db", "https://www.exploit-db.com/rss.xml", "vulnerability", "medium"),
        ("packet_storm", "https://rss.packetstormsecurity.com/news/", "vulnerability", "medium"),
        ("us_cert_alerts", "https://us-cert.cisa.gov/ncas/alerts.xml", "government", "high"),
        ("cyber_scoop", "https://www.cyberscoop.com/feed/", "cybersecurity_news", "medium"),
        ("infosec_magazine", "https://www.infosecurity-magazine.com/rss/news/", "cybersecurity_news", "medium")
    ]
    
    current_time = datetime.now().isoformat()
    
    for source_name, url, category, priority in initial_sources:
        cursor.execute('''
            INSERT OR REPLACE INTO source_intelligence 
            (source_name, url, category, priority_level, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (source_name, url, category, priority, current_time, current_time))
    
    conn.commit()
    
    print("✅ Database created successfully!")
    print(f"📍 Database location: {os.path.abspath('../data/threats.db')}")
    
    # Verify database creation
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = cursor.fetchall()
    print(f"📋 Created tables: {[table[0] for table in tables]}")
    
    cursor.execute("SELECT COUNT(*) FROM source_intelligence")
    source_count = cursor.fetchone()[0]
    print(f"🌐 Configured {source_count} threat intelligence sources")
    
    conn.close()
    return True

def check_database_health():
    """
    Check database health and show status
    """
    try:
        conn = sqlite3.connect('../data/threats.db')
        cursor = conn.cursor()
        
        print("\n🔍 Database Health Check")
        print("=" * 40)
        
        # Check each table
        tables_to_check = [
            'raw_threats', 'source_stats', 'collection_sessions', 
            'source_intelligence', 'ai_threat_analysis'
        ]
        
        for table in tables_to_check:
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            count = cursor.fetchone()[0]
            print(f"📊 {table}: {count} records")
        
        # Check recent activity
        cursor.execute("SELECT MAX(collected_at) FROM raw_threats")
        latest_threat = cursor.fetchone()[0]
        print(f"🕒 Latest threat: {latest_threat or 'None'}")
        
        # Check source status
        cursor.execute("SELECT COUNT(*) FROM source_intelligence WHERE is_active = 1")
        active_sources = cursor.fetchone()[0]
        print(f"🌐 Active sources: {active_sources}")
        
        conn.close()
        print("✅ Database is healthy!")
        return True
        
    except Exception as e:
        print(f"❌ Database health check failed: {e}")
        return False

if __name__ == "__main__":
    print("🚀 Setting up Threat Intelligence Database...")
    
    # Create database
    if create_database():
        # Check health
        check_database_health()
        print("\n🎉 Database setup complete! Ready for threat collection.")
    else:
        print("❌ Database setup failed!")
