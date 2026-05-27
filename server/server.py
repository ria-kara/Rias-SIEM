"""
Ria's SIEM - Server Component
Receives logs from agents, stores them in SQLite, and serves the web interface.

Author: Ria
Licence: MIT
"""

import os
import json
import sqlite3
from datetime import datetime
from flask import Flask, request, jsonify, render_template, g

app = Flask(__name__, template_folder='../web/templates')

# Configuration
DATABASE_PATH = os.environ.get('SIEM_DB_PATH', 'logs.db')
HOST = os.environ.get('SIEM_HOST', '0.0.0.0')
PORT = int(os.environ.get('SIEM_PORT', 5000))


def get_db():
    """Get database connection for current request."""
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception):
    """Close database connection after request."""
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    """Initialise database with required tables and indexes."""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_host TEXT NOT NULL,
            source_ip TEXT,
            timestamp TEXT NOT NULL,
            received_at TEXT NOT NULL,
            event_id INTEGER,
            log_type TEXT,
            severity TEXT,
            message TEXT,
            raw_data TEXT
        )
    ''')
    
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_source_host ON logs(source_host)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_event_id ON logs(event_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_log_type ON logs(log_type)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON logs(timestamp)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_severity ON logs(severity)')
    
    conn.commit()
    conn.close()
    print(f"[+] Database initialised at: {DATABASE_PATH}")


@app.route('/api/logs', methods=['POST'])
def receive_logs():
    """Receive and store logs from agents."""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        source_host = data.get('host', 'Unknown')
        source_ip = request.remote_addr
        logs = data.get('logs', [])
        
        if not logs:
            return jsonify({'error': 'No logs in payload'}), 400
        
        received_at = datetime.utcnow().isoformat()
        
        db = get_db()
        cursor = db.cursor()
        stored_count = 0
        
        for log_entry in logs:
            cursor.execute('''
                INSERT INTO logs (source_host, source_ip, timestamp, received_at, 
                                  event_id, log_type, severity, message, raw_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                source_host,
                source_ip,
                log_entry.get('timestamp', ''),
                received_at,
                log_entry.get('event_id'),
                log_entry.get('log_type', ''),
                log_entry.get('severity', ''),
                log_entry.get('message', ''),
                json.dumps(log_entry)
            ))
            stored_count += 1
        
        db.commit()
        
        print(f"[+] Received {stored_count} logs from {source_host} ({source_ip})")
        
        return jsonify({
            'status': 'success',
            'message': f'Stored {stored_count} log entries',
            'host': source_host
        }), 201
        
    except Exception as e:
        print(f"[-] Error receiving logs: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/logs', methods=['GET'])
def query_logs():
    """Query logs with filters (source_host, event_id, log_type, severity, time range, keyword)."""
    try:
        query = "SELECT * FROM logs WHERE 1=1"
        params = []
        
        if request.args.get('source_host'):
            query += " AND source_host LIKE ?"
            params.append(f"%{request.args.get('source_host')}%")
        
        if request.args.get('event_id'):
            query += " AND event_id = ?"
            params.append(int(request.args.get('event_id')))
        
        if request.args.get('log_type'):
            query += " AND log_type = ?"
            params.append(request.args.get('log_type'))
        
        if request.args.get('severity'):
            query += " AND severity = ?"
            params.append(request.args.get('severity'))
        
        if request.args.get('start_time'):
            query += " AND timestamp >= ?"
            params.append(request.args.get('start_time'))
        
        if request.args.get('end_time'):
            query += " AND timestamp <= ?"
            params.append(request.args.get('end_time'))
        
        if request.args.get('keyword'):
            query += " AND message LIKE ?"
            params.append(f"%{request.args.get('keyword')}%")
        
        query += " ORDER BY timestamp DESC"
        
        limit = int(request.args.get('limit', 100))
        offset = int(request.args.get('offset', 0))
        query += f" LIMIT {limit} OFFSET {offset}"
        
        db = get_db()
        cursor = db.cursor()
        cursor.execute(query, params)
        
        logs = []
        for row in cursor.fetchall():
            logs.append({
                'id': row['id'],
                'source_host': row['source_host'],
                'source_ip': row['source_ip'],
                'timestamp': row['timestamp'],
                'received_at': row['received_at'],
                'event_id': row['event_id'],
                'log_type': row['log_type'],
                'severity': row['severity'],
                'message': row['message']
            })
        
        return jsonify({
            'status': 'success',
            'count': len(logs),
            'logs': logs
        })
        
    except Exception as e:
        print(f"[-] Error querying logs: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get dashboard statistics."""
    try:
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM logs")
        total_logs = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(DISTINCT source_host) FROM logs")
        total_hosts = cursor.fetchone()[0]
        
        cursor.execute("""
            SELECT log_type, COUNT(*) as count 
            FROM logs 
            GROUP BY log_type
        """)
        logs_by_type = {row[0]: row[1] for row in cursor.fetchall()}
        
        cursor.execute("""
            SELECT severity, COUNT(*) as count 
            FROM logs 
            GROUP BY severity
        """)
        logs_by_severity = {row[0]: row[1] for row in cursor.fetchall()}
        
        cursor.execute("""
            SELECT event_id, COUNT(*) as count 
            FROM logs 
            WHERE event_id IS NOT NULL
            GROUP BY event_id 
            ORDER BY count DESC 
            LIMIT 10
        """)
        top_event_ids = [{'event_id': row[0], 'count': row[1]} for row in cursor.fetchall()]
        
        cursor.execute("""
            SELECT COUNT(*) FROM logs 
            WHERE datetime(received_at) > datetime('now', '-1 day')
        """)
        recent_activity = cursor.fetchone()[0]
        
        return jsonify({
            'status': 'success',
            'stats': {
                'total_logs': total_logs,
                'total_hosts': total_hosts,
                'logs_by_type': logs_by_type,
                'logs_by_severity': logs_by_severity,
                'top_event_ids': top_event_ids,
                'recent_activity': recent_activity
            }
        })
        
    except Exception as e:
        print(f"[-] Error getting stats: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/hosts', methods=['GET'])
def get_hosts():
    """Get list of registered hosts."""
    try:
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("""
            SELECT 
                source_host,
                source_ip,
                MAX(received_at) as last_seen,
                COUNT(*) as log_count
            FROM logs
            GROUP BY source_host
            ORDER BY last_seen DESC
        """)
        
        hosts = []
        for row in cursor.fetchall():
            hosts.append({
                'hostname': row[0],
                'ip_address': row[1],
                'last_seen': row[2],
                'log_count': row[3]
            })
        
        return jsonify({
            'status': 'success',
            'hosts': hosts
        })
        
    except Exception as e:
        print(f"[-] Error getting hosts: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/')
def index():
    """Serve the web interface."""
    return render_template('index.html')


if __name__ == '__main__':
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║                    🛡️  Ria's SIEM Server  🛡️                  ║
    ║                       Basic SIEM POC                          ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)
    
    init_db()
    
    print(f"[+] Starting server on {HOST}:{PORT}")
    print(f"[+] Web interface: http://{HOST}:{PORT}")
    print(f"[+] API endpoint: http://{HOST}:{PORT}/api/logs")
    print("[+] Press Ctrl+C to stop\n")
    
    app.run(host=HOST, port=PORT, debug=True)
