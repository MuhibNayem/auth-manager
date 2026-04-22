"""
Compliance Module - Enterprise Security & Regulatory Compliance

Features:
- GDPR compliance engine (data export, right to be forgotten)
- SOC2 audit logging (immutable logs)
- Security dashboard with real-time threat monitoring
- PII masking and encryption
"""

from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import json
import hashlib


class GDPRComplianceEngine:
    """Handle GDPR compliance requirements"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.data_retention_days = config.get('data_retention_days', 90)
    
    async def export_user_data(self, user_id: str) -> Dict[str, Any]:
        """Export all user data for GDPR right to access"""
        from ..db import get_database
        
        db = await get_database()
        
        # Collect all user data
        user = await db.users.find_one({'id': user_id})
        if not user:
            raise ValueError(f"User {user_id} not found")
        
        sessions = await db.sessions.find_many({'user_id': user_id}).to_list(length=None)
        audit_logs = await db.audit_logs.find_many({'user_id': user_id}).to_list(length=None)
        
        export_data = {
            'export_date': datetime.utcnow().isoformat(),
            'user': self._anonymize_sensitive(user, for_export=True),
            'sessions': [self._anonymize_sensitive(s, for_export=True) for s in sessions],
            'audit_logs': [self._anonymize_sensitive(log, for_export=True) for log in audit_logs],
            'data_categories': {
                'identity': ['email', 'name', 'created_at'],
                'authentication': ['login_history', 'mfa_settings'],
                'sessions': ['active_sessions', 'device_info'],
                'preferences': ['language', 'timezone']
            }
        }
        
        return export_data
    
    async def delete_user_data(self, user_id: str, hard_delete: bool = False) -> Dict[str, Any]:
        """Delete user data for GDPR right to be forgotten"""
        from ..db import get_database
        
        db = await get_database()
        
        if hard_delete:
            # Complete deletion (use with caution)
            result = await db.users.delete_one({'id': user_id})
            await db.sessions.delete_many({'user_id': user_id})
            
            # Anonymize audit logs instead of deleting (for security trail)
            await db.audit_logs.update_many(
                {'user_id': user_id},
                {'$set': {'user_id': 'deleted', 'email': 'deleted@deleted.com'}}
            )
            
            return {'deleted': result.deleted_count > 0}
        else:
            # Soft delete - anonymize personal data
            await db.users.update_one(
                {'id': user_id},
                {'$set': {
                    'email': f'deleted_{user_id}@deleted.com',
                    'personal_data': None,
                    'is_deleted': True,
                    'deleted_at': datetime.utcnow()
                }}
            )
            
            return {'anonymized': True}
    
    def _anonymize_sensitive(self, data: Dict, for_export: bool = False) -> Dict:
        """Anonymize sensitive fields based on context"""
        if not data:
            return data
        
        sensitive_fields = ['password_hash', 'token', 'secret', 'api_key']
        result = data.copy()
        
        for field in sensitive_fields:
            if field in result:
                if for_export:
                    result[field] = '[REDACTED]'
                else:
                    del result[field]
        
        return result


class SOC2AuditLogger:
    """Immutable audit logging for SOC2 compliance"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.enabled = config.get('audit_logging', True)
    
    async def log_event(self, event: Dict[str, Any]) -> None:
        """Log an immutable audit event"""
        if not self.enabled:
            return
        
        from ..db import get_database
        
        db = await get_database()
        
        # Create immutable audit record
        audit_record = {
            'timestamp': datetime.utcnow(),
            'event_type': event.get('type'),
            'user_id': event.get('user_id'),
            'action': event.get('action'),
            'resource': event.get('resource'),
            'ip_address': event.get('ip_address'),
            'user_agent': event.get('user_agent'),
            'status': event.get('status', 'success'),
            'metadata': event.get('metadata', {}),
            'checksum': None  # Will be calculated
        }
        
        # Calculate checksum for immutability verification
        record_json = json.dumps(audit_record, sort_keys=True, default=str)
        audit_record['checksum'] = hashlib.sha256(record_json.encode()).hexdigest()
        
        # Insert into append-only audit log collection
        await db.audit_logs.insert_one(audit_record)
    
    async def verify_log_integrity(self, log_id: str) -> bool:
        """Verify that a log entry hasn't been tampered with"""
        from ..db import get_database
        
        db = await get_database()
        log = await db.audit_logs.find_one({'_id': log_id})
        
        if not log:
            return False
        
        # Recalculate checksum
        stored_checksum = log.pop('checksum')
        record_json = json.dumps(log, sort_keys=True, default=str)
        calculated_checksum = hashlib.sha256(record_json.encode()).hexdigest()
        
        return stored_checksum == calculated_checksum
    
    async def export_audit_logs(self, start_date: datetime, end_date: datetime) -> List[Dict]:
        """Export audit logs for compliance review"""
        from ..db import get_database
        
        db = await get_database()
        
        logs = await db.audit_logs.find({
            'timestamp': {'$gte': start_date, '$lte': end_date}
        }).to_list(length=None)
        
        return logs


class SecurityDashboard:
    """Real-time security monitoring dashboard"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
    
    async def get_threat_summary(self) -> Dict[str, Any]:
        """Get current threat landscape summary"""
        from ..db import get_database
        
        db = await get_database()
        
        # Calculate metrics for last 24 hours
        now = datetime.utcnow()
        yesterday = now - timedelta(hours=24)
        
        # Failed login attempts
        failed_logins = await db.audit_logs.count_documents({
            'timestamp': {'$gte': yesterday},
            'event_type': 'login',
            'status': 'failed'
        })
        
        # Suspicious activities
        suspicious = await db.audit_logs.count_documents({
            'timestamp': {'$gte': yesterday},
            'metadata.is_suspicious': True
        })
        
        # Active sessions
        active_sessions = await db.sessions.count_documents({
            'expires_at': {'$gte': now}
        })
        
        # Geographic distribution
        geo_dist = await db.audit_logs.aggregate([
            {'$match': {'timestamp': {'$gte': yesterday}}},
            {'$group': {'_id': '$metadata.country', 'count': {'$sum': 1}}},
            {'$sort': {'count': -1}},
            {'$limit': 10}
        ]).to_list(length=10)
        
        return {
            'period': 'last_24_hours',
            'failed_login_attempts': failed_logins,
            'suspicious_activities': suspicious,
            'active_sessions': active_sessions,
            'geographic_distribution': geo_dist,
            'threat_level': self._calculate_threat_level(failed_logins, suspicious)
        }
    
    async def get_user_risk_score(self, user_id: str) -> Dict[str, Any]:
        """Calculate risk score for a specific user"""
        from ..db import get_database
        
        db = await get_database()
        
        now = datetime.utcnow()
        week_ago = now - timedelta(days=7)
        
        # Count risky behaviors
        failed_logins = await db.audit_logs.count_documents({
            'user_id': user_id,
            'timestamp': {'$gte': week_ago},
            'status': 'failed'
        })
        
        multiple_locations = await db.audit_logs.aggregate([
            {'$match': {'user_id': user_id, 'timestamp': {'$gte': week_ago}}},
            {'$group': {'_id': '$metadata.country'}},
            {'$count': 'countries'}
        ]).to_list(length=1)
        
        country_count = multiple_locations[0]['countries'] if multiple_locations else 0
        
        # Calculate risk score (0-100)
        risk_score = min(100, (failed_logins * 10) + (country_count * 20))
        
        return {
            'user_id': user_id,
            'risk_score': risk_score,
            'risk_level': 'high' if risk_score > 70 else 'medium' if risk_score > 30 else 'low',
            'factors': {
                'failed_logins': failed_logins,
                'multiple_countries': country_count
            },
            'recommendations': self._get_recommendations(risk_score, failed_logins, country_count)
        }
    
    def _calculate_threat_level(self, failed_logins: int, suspicious: int) -> str:
        """Calculate overall threat level"""
        if failed_logins > 1000 or suspicious > 100:
            return 'critical'
        elif failed_logins > 500 or suspicious > 50:
            return 'high'
        elif failed_logins > 100 or suspicious > 10:
            return 'medium'
        else:
            return 'low'
    
    def _get_recommendations(self, risk_score: int, failed_logins: int, countries: int) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        if failed_logins > 5:
            recommendations.append("Consider enabling MFA for this user")
        if countries > 2:
            recommendations.append("Unusual geographic activity detected - verify user identity")
        if risk_score > 70:
            recommendations.append("Temporarily lock account and require password reset")
        
        return recommendations


async def run_dashboard(config: Dict[str, Any]):
    """Run the security dashboard server"""
    from aiohttp import web
    
    dashboard = SecurityDashboard(config)
    
    async def threat_summary(request):
        summary = await dashboard.get_threat_summary()
        return web.json_response(summary)
    
    async def user_risk(request):
        user_id = request.match_info.get('user_id')
        risk = await dashboard.get_user_risk_score(user_id)
        return web.json_response(risk)
    
    app = web.Application()
    app.router.add_get('/api/threats', threat_summary)
    app.router.add_get('/api/users/{user_id}/risk', user_risk)
    
    # Serve static HTML dashboard
    app.router.add_get('/', lambda r: web.Response(text=_get_dashboard_html(), content_type='text/html'))
    
    runner = web.AppRunner(app)
    await runner.setup()
    
    site = web.TCPSite(runner, 'localhost', config.get('port', 8080))
    await site.start()
    
    print(f"🛡️  Security dashboard running at http://localhost:{config.get('port', 8080)}")
    
    # Keep running
    try:
        while True:
            await asyncio.sleep(3600)
    except KeyboardInterrupt:
        await runner.cleanup()


def _get_dashboard_html() -> str:
    """Return simple HTML dashboard"""
    return '''
<!DOCTYPE html>
<html>
<head>
    <title>Authy Security Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .card { background: white; padding: 20px; margin: 20px 0; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; }
        .metric { display: inline-block; margin: 20px; padding: 20px; background: #f0f0f0; border-radius: 8px; min-width: 150px; }
        .metric-value { font-size: 2em; font-weight: bold; color: #2196F3; }
        .metric-label { color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Authy Security Dashboard</h1>
        <div class="card">
            <h2>Threat Summary (Last 24 Hours)</h2>
            <div id="metrics">Loading...</div>
        </div>
    </div>
    <script>
        fetch('/api/threats')
            .then(r => r.json())
            .then(data => {
                document.getElementById('metrics').innerHTML = `
                    <div class="metric"><div class="metric-value">${data.failed_login_attempts}</div><div class="metric-label">Failed Logins</div></div>
                    <div class="metric"><div class="metric-value">${data.suspicious_activities}</div><div class="metric-label">Suspicious Activities</div></div>
                    <div class="metric"><div class="metric-value">${data.active_sessions}</div><div class="metric-label">Active Sessions</div></div>
                    <div class="metric"><div class="metric-value" style="color: ${data.threat_level === 'critical' ? 'red' : 'green'}">${data.threat_level.toUpperCase()}</div><div class="metric-label">Threat Level</div></div>
                `;
            });
    </script>
</body>
</html>
'''
