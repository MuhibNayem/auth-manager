"""
Authy Dev Command - Development Server with Hot Reload
FAANG-grade development environment with mock services and HTTPS support.
"""
import asyncio
import os
import signal
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


@click.command(name='dev')
@click.option('--host', '-h', default='127.0.0.1', show_default=True, help='Host to bind')
@click.option('--port', '-p', default=8000, type=int, help='Port to bind')
@click.option('--reload', is_flag=True, default=True, help='Enable auto-reload')
@click.option('--https', is_flag=True, help='Enable HTTPS with self-signed cert')
@click.option('--mock-services', is_flag=True, help='Use mock email/SMS services')
@click.option('--debug', is_flag=True, help='Enable debug mode')
def dev_cmd(host: str, port: int, reload: bool, https: bool, mock_services: bool, debug: bool):
    """
    Start development server with hot reload and debugging.
    
    Features:
    - Auto-reload on code changes
    - Mock email/SMS services for testing
    - Optional HTTPS with self-signed certificates
    - Interactive dashboard
    - Real-time logging
    """
    asyncio.run(_run_dev_server(host, port, reload, https, mock_services, debug))


async def _run_dev_server(host: str, port: int, reload: bool, https: bool, 
                          mock_services: bool, debug: bool):
    """Run development server."""
    
    # Show startup banner
    console.print(Panel.fit(
        "[bold blue]🛡️  Authy Development Server[/bold blue]\n\n"
        f"Host: [cyan]{host}[/cyan]\n"
        f"Port: [cyan]{port}[/cyan]\n"
        f"Reload: [green]{'Enabled' if reload else 'Disabled'}[/green]\n"
        f"HTTPS: [yellow]{'Enabled' if https else 'Disabled'}[/yellow]\n"
        f"Mock Services: [green]{'Enabled' if mock_services else 'Disabled'}[/green]\n"
        f"Debug: [green]{'Enabled' if debug else 'Disabled'}[/green]",
        title="🚀 Starting",
        border_style="blue"
    ))
    
    # Set environment variables
    os.environ['AUTHY_ENV'] = 'development'
    os.environ['AUTHY_DEBUG'] = '1' if debug else '0'
    
    if mock_services:
        os.environ['AUTHY_MOCK_EMAIL'] = '1'
        os.environ['AUTHY_MOCK_SMS'] = '1'
        console.print("[dim]✓ Mock email/SMS services enabled[/dim]")
    
    # Generate self-signed cert if HTTPS enabled
    if https:
        cert_dir = Path.cwd() / '.authy' / 'certs'
        cert_dir.mkdir(parents=True, exist_ok=True)
        
        cert_file = cert_dir / 'localhost.crt'
        key_file = cert_dir / 'localhost.key'
        
        if not cert_file.exists():
            console.print("[dim]Generating self-signed certificate...[/dim]")
            await _generate_cert(cert_file, key_file)
        
        os.environ['SSL_CERT_FILE'] = str(cert_file)
        os.environ['SSL_KEY_FILE'] = str(key_file)
    
    # Try to detect and run appropriate server
    framework = _detect_framework()
    
    if framework == 'fastapi':
        await _run_fastapi_dev(host, port, reload, https)
    elif framework == 'flask':
        await _run_flask_dev(host, port, reload)
    elif framework == 'django':
        await _run_django_dev(host, port, reload)
    else:
        await _run_generic_dev(host, port)
    
    console.print("\n[yellow]Server stopped[/yellow]")


async def _generate_cert(cert_file: Path, key_file: Path):
    """Generate self-signed certificate."""
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime
        
        # Generate private key
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        # Generate certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Authy Development"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ])
        
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("localhost")]),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        
        # Write files
        with open(key_file, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        
        with open(cert_file, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        console.print("[green]✓ Certificate generated[/green]")
        
    except ImportError:
        console.print("[yellow]⚠ cryptography not installed, HTTPS disabled[/yellow]")


def _detect_framework() -> Optional[str]:
    """Detect web framework."""
    if Path('manage.py').exists():
        return 'django'
    
    for py_file in Path.cwd().glob('*.py'):
        try:
            content = py_file.read_text()
            if 'FastAPI' in content or 'fastapi' in content:
                return 'fastapi'
            if 'Flask' in content or 'flask' in content:
                return 'flask'
        except:
            pass
    
    return None


async def _run_fastapi_dev(host: str, port: int, reload: bool, https: bool):
    """Run FastAPI development server."""
    try:
        import uvicorn
        
        config = uvicorn.Config(
            "src.main:app",
            host=host,
            port=port,
            reload=reload,
            ssl_certfile=os.environ.get('SSL_CERT_FILE'),
            ssl_keyfile=os.environ.get('SSL_KEY_FILE'),
            log_level="info",
        )
        
        server = uvicorn.Server(config)
        
        # Handle shutdown signals
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, lambda: asyncio.create_task(server.shutdown()))
        
        await server.serve()
        
    except ImportError:
        console.print("[red]Error: uvicorn not installed. Run: pip install uvicorn[/red]")
    except FileNotFoundError:
        console.print("[red]Error: src/main.py not found[/red]")


async def _run_flask_dev(host: str, port: int, reload: bool):
    """Run Flask development server."""
    try:
        from flask.cli import main as flask_main
        import sys
        
        sys.argv = ['flask', 'run', '--host', host, '--port', str(port)]
        if reload:
            sys.argv.append('--reload')
        
        flask_main()
        
    except ImportError:
        console.print("[red]Error: Flask not installed[/red]")
    except FileNotFoundError:
        console.print("[red]Error: src/app.py not found[/red]")


async def _run_django_dev(host: str, port: int, reload: bool):
    """Run Django development server."""
    try:
        import django
        from django.core.management import execute_from_command_line
        import sys
        
        os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'src.settings')
        
        sys.argv = ['manage.py', 'runserver', f'{host}:{port}']
        if not reload:
            sys.argv.append('--noreload')
        
        execute_from_command_line(sys.argv)
        
    except ImportError:
        console.print("[red]Error: Django not installed[/red]")
    except FileNotFoundError:
        console.print("[red]Error: manage.py not found[/red]")


async def _run_generic_dev(host: str, port: int):
    """Run generic static-file development server.

    The static fallback ALWAYS binds 127.0.0.1 (§9) — it is never exposed on
    other interfaces regardless of --host.
    """
    if host != "127.0.0.1":
        console.print(
            f"[yellow]⚠ Static fallback ignores --host={host}; binding 127.0.0.1 only[/yellow]"
        )
    host = "127.0.0.1"
    console.print(f"""
[yellow]⚠ No framework detected. Starting basic server...[/yellow]

You can access your application at:
  http://{host}:{port}

To enable framework-specific features, ensure your main app file exists:
  - FastAPI: src/main.py
  - Flask: src/app.py  
  - Django: manage.py
""")
    
    # Simple HTTP server for static files
    import http.server
    import socketserver
    
    class Handler(http.server.SimpleHTTPRequestHandler):
        def log_message(self, format, *args):
            console.print(f"[dim]{args[0]}[/dim]")
    
    with socketserver.TCPServer((host, port), Handler) as httpd:
        console.print(f"[green]✓ Serving at http://{host}:{port}[/green]")
        console.print("[dim]Press Ctrl+C to stop[/dim]")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
