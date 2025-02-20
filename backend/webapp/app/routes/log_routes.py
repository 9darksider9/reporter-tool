from flask import Blueprint, jsonify, request, current_app
from flask_login import login_required
from ..decorators import admin_required
import os
import json
from datetime import datetime, timedelta, timezone

bp = Blueprint('logs', __name__, url_prefix='/api/logs')

def parse_date(date_str):
    """Parse date string and return UTC datetime object"""
    try:
        if not date_str:
            return None
        # Parse ISO format date and convert to naive UTC
        dt = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    except Exception as e:
        print(f"[ERROR] Failed to parse date {date_str}: {str(e)}")
        return None

def read_log_entries(log_file, start_time=None, end_time=None):
    entries = []
    try:
        print(f"[DEBUG] Reading log file: {log_file}")
        if not os.path.exists(log_file):
            print(f"[ERROR] Log file not found: {log_file}")
            return entries
            
        # Convert start_time and end_time to naive UTC if they're timezone-aware
        if start_time and start_time.tzinfo:
            start_time = start_time.replace(tzinfo=None)
        if end_time and end_time.tzinfo:
            end_time = end_time.replace(tzinfo=None)
            
        print(f"[DEBUG] Using time range: {start_time} to {end_time}")
            
        with open(log_file, 'r') as f:
            lines = f.readlines()
            print(f"[DEBUG] Found {len(lines)} lines in log file")
            
            for line_num, line in enumerate(lines, 1):
                try:
                    line = line.strip()
                    if not line:
                        continue
                        
                    # Find the first JSON bracket
                    json_start = line.find('{')
                    if json_start == -1:
                        print(f"[WARNING] No JSON found in line {line_num}: {line}")
                        continue
                    
                    # Split into timestamp and JSON
                    timestamp_str = line[:json_start].strip()
                    json_str = line[json_start:]
                    
                    # Parse timestamp
                    try:
                        timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                        
                        # Apply time filter if specified
                        if start_time and timestamp < start_time:
                            print(f"[DEBUG] Skipping entry before start time: {timestamp}")
                            continue
                        if end_time and timestamp > end_time:
                            print(f"[DEBUG] Skipping entry after end time: {timestamp}")
                            continue
                        
                        # Parse JSON data
                        data = json.loads(json_str)
                        data['timestamp'] = timestamp.isoformat() + 'Z'  # Add UTC indicator
                        entries.append(data)
                        print(f"[DEBUG] Successfully parsed entry from {timestamp}")
                        
                    except ValueError as e:
                        print(f"[ERROR] Failed to parse timestamp in line {line_num}: {str(e)}")
                        continue
                    except json.JSONDecodeError as e:
                        print(f"[ERROR] Failed to parse JSON in line {line_num}: {str(e)}")
                        continue
                    
                except Exception as e:
                    print(f"[ERROR] Failed to process line {line_num}: {str(e)}")
                    print(f"[ERROR] Problematic line: {line}")
                    continue
                    
        # Sort entries by timestamp in reverse order (newest first)
        entries.sort(key=lambda x: x['timestamp'], reverse=True)
        print(f"[DEBUG] Successfully parsed and sorted {len(entries)} log entries")
        return entries
    except Exception as e:
        print(f"[ERROR] Failed to read log file: {str(e)}")
        return entries

@bp.route('/audit', methods=['GET'])
@login_required
@admin_required
def get_audit_logs():
    """Get audit logs with optional time range filter"""
    try:
        start_time = parse_date(request.args.get('start_time'))
        end_time = parse_date(request.args.get('end_time'))
        
        print(f"[DEBUG] Fetching audit logs. Start: {start_time}, End: {end_time}")
        
        log_file = os.path.join(current_app.root_path, 'logs', 'audit.log')
        print(f"[DEBUG] Reading from log file: {log_file}")
        
        entries = read_log_entries(log_file, start_time, end_time)
        print(f"[DEBUG] Found {len(entries)} entries")
        
        return jsonify({
            'logs': entries,
            'count': len(entries)
        })
    except Exception as e:
        print(f"[ERROR] Error fetching audit logs: {str(e)}")
        return jsonify({
            'error': str(e),
            'logs': [],
            'count': 0
        }), 500

@bp.route('/authentication', methods=['GET'])
@login_required
@admin_required
def get_auth_logs():
    """Get authentication logs with optional time range filter"""
    start_time = parse_date(request.args.get('start_time'))
    end_time = parse_date(request.args.get('end_time'))
    
    log_file = os.path.join(current_app.root_path, 'logs', 'authentication.log')
    entries = read_log_entries(log_file, start_time, end_time)
    
    return jsonify({
        'logs': entries,
        'count': len(entries)
    })

@bp.route('/usage', methods=['GET'])
@login_required
@admin_required
def get_usage_logs():
    """Get usage logs with optional time range filter"""
    start_time = parse_date(request.args.get('start_time'))
    end_time = parse_date(request.args.get('end_time'))
    
    log_file = os.path.join(current_app.root_path, 'logs', 'usage.log')
    entries = read_log_entries(log_file, start_time, end_time)
    
    return jsonify({
        'logs': entries,
        'count': len(entries)
    })

@bp.route('/all', methods=['GET'])
@login_required
@admin_required
def get_all_logs():
    """Get all logs with optional time range filter"""
    start_time = parse_date(request.args.get('start_time'))
    end_time = parse_date(request.args.get('end_time'))
    
    log_types = {
        'audit': os.path.join(current_app.root_path, 'logs', 'audit.log'),
        'authentication': os.path.join(current_app.root_path, 'logs', 'authentication.log'),
        'usage': os.path.join(current_app.root_path, 'logs', 'usage.log')
    }
    
    all_logs = {}
    total_count = 0
    
    for log_type, log_file in log_types.items():
        entries = read_log_entries(log_file, start_time, end_time)
        all_logs[log_type] = entries
        total_count += len(entries)
    
    return jsonify({
        'logs': all_logs,
        'total_count': total_count
    })

@bp.route('/stats', methods=['GET'])
@login_required
@admin_required
def get_log_stats():
    """Get statistics about logs for the dashboard"""
    try:
        log_dir = os.path.join(current_app.root_path, 'logs')
        print(f"[DEBUG] Accessing log stats endpoint. Log directory: {log_dir}")
        
        if not os.path.exists(log_dir):
            print(f"[ERROR] Log directory does not exist: {log_dir}")
            return jsonify({'error': 'Log directory not found'}), 500
        
        stats = {
            'audit': {'size': 0, 'last_modified': None, 'entry_count': 0},
            'authentication': {'size': 0, 'last_modified': None, 'entry_count': 0},
            'usage': {'size': 0, 'last_modified': None, 'entry_count': 0}
        }
        
        for log_type in stats:
            log_file = os.path.join(log_dir, f'{log_type}.log')
            print(f"[DEBUG] Checking log file: {log_file}")
            
            if os.path.exists(log_file):
                print(f"[DEBUG] Found {log_type} log file")
                file_size = os.path.getsize(log_file)
                stats[log_type]['size'] = file_size
                
                if file_size > 0:
                    stats[log_type]['last_modified'] = datetime.fromtimestamp(
                        os.path.getmtime(log_file)
                    ).isoformat()
                    with open(log_file, 'r') as f:
                        stats[log_type]['entry_count'] = sum(1 for line in f if line.strip())
                else:
                    print(f"[DEBUG] {log_type} log file is empty")
                    stats[log_type]['last_modified'] = datetime.utcnow().isoformat()
                    stats[log_type]['entry_count'] = 0
                
                print(f"[DEBUG] Stats for {log_type}: {stats[log_type]}")
            else:
                print(f"[WARNING] Log file not found: {log_file}")
        
        print(f"[DEBUG] Returning stats: {stats}")
        return jsonify(stats)
    except Exception as e:
        print(f"[ERROR] Error getting log stats: {str(e)}")
        return jsonify({'error': str(e)}), 500 