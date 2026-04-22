"""
Authy Init Command - Interactive Project Scaffolding
FAANG-grade initialization with framework detection and best practices.
"""
import asyncio
import os
import shutil
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn

from ..utils import print_success, print_error, print_info, confirm_action

console = Console()


@click.command(name='init')
@click.option('--name', '-n', help='Project name')
@click.option('--framework', '-f', type=click.Choice(['fastapi', 'flask', 'django', 'none']), 
              help='Web framework')
@click.option('--database', '-d', type=click.Choice(['postgresql', 'mysql', 'sqlite', 'mongodb', 'dynamodb']),
              help='Database type')
@click.option('--features', multiple=True, 
              type=click.Choice(['saml', 'oidc', 'mfa', 'social', 'webhooks', 'audit', 'organizations']),
              help='Enable features')
@click.option('--force', is_flag=True, help='Overwrite existing files')
def init_cmd(name: Optional[str], framework: Optional[str], database: Optional[str], 
             features: tuple, force: bool):
    """
    Initialize a new Authy project with interactive scaffolding.
    
    Creates configuration files, directory structure, and boilerplate code.
    Detects existing frameworks and suggests best practices.
    """
    asyncio.run(_init_project(name, framework, database, features, force))


async def _init_project(name: Optional[str], framework: Optional[str], database: Optional[str],
                        features: tuple, force: bool):
    """Initialize project asynchronously."""
    
    # Get project name
    if not name:
        name = Prompt.ask("Project name", default=Path.cwd().name)
    
    # Check if directory exists
    project_dir = Path.cwd() / name if not Path.cwd().name == name else Path.cwd()
    
    if project_dir.exists() and any(project_dir.iterdir()):
        if not force:
            if not confirm_action(f"Directory {project_dir} is not empty. Continue?"):
                console.print("[yellow]Aborted[/yellow]")
                return
    
    project_dir.mkdir(parents=True, exist_ok=True)
    
    # Interactive prompts if not provided
    if not framework:
        framework = _detect_framework(project_dir) or Prompt.ask(
            "Select web framework",
            choices=['fastapi', 'flask', 'django', 'none'],
            default='fastapi'
        )
    
    if not database:
        database = Prompt.ask(
            "Select database",
            choices=['postgresql', 'mysql', 'sqlite', 'mongodb', 'dynamodb'],
            default='postgresql'
        )
    
    if not features:
        features = _prompt_features()
    
    # Show summary
    console.print(Panel.fit(
        f"[bold]Project Configuration[/bold]\n\n"
        f"Name: [cyan]{name}[/cyan]\n"
        f"Framework: [cyan]{framework}[/cyan]\n"
        f"Database: [cyan]{database}[/cyan]\n"
        f"Features: [cyan]{', '.join(features) if features else 'none'}[/cyan]",
        title="📋 Summary",
        border_style="blue"
    ))
    
    if not confirm_action("Continue with these settings?", default=True):
        console.print("[yellow]Aborted[/yellow]")
        return
    
    # Create project structure
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        
        task = progress.add_task("Creating project structure...", total=7)
        
        # 1. Create directories
        progress.update(task, description="Creating directories...")
        _create_directories(project_dir)
        
        # 2. Create configuration
        progress.update(task, description="Creating configuration...", advance=1)
        _create_config(project_dir, framework, database, features)
        
        # 3. Create main application file
        progress.update(task, description="Creating application boilerplate...", advance=2)
        _create_app_file(project_dir, framework, database, features)
        
        # 4. Create environment template
        progress.update(task, description="Creating .env template...", advance=3)
        _create_env_template(project_dir, database, features)
        
        # 5. Create requirements file
        progress.update(task, description="Creating requirements.txt...", advance=4)
        _create_requirements(project_dir, framework, database, features)
        
        # 6. Create README
        progress.update(task, description="Creating README.md...", advance=5)
        _create_readme(project_dir, name, framework, database, features)
        
        # 7. Create gitignore
        progress.update(task, description="Creating .gitignore...", advance=6)
        _create_gitignore(project_dir)
        
        progress.update(task, completed=7)
    
    print_success(f"Project '{name}' initialized successfully!")
    console.print(f"\nNext steps:")
    console.print(f"  1. [bold]cd {name}[/bold]")
    console.print(f"  2. [bold]cp .env.example .env[/bold] and configure secrets")
    console.print(f"  3. [bold]pip install -r requirements.txt[/bold]")
    console.print(f"  4. [bold]authy dev[/bold] to start development server")


def _detect_framework(project_dir: Path) -> Optional[str]:
    """Detect existing framework in directory."""
    if (project_dir / 'manage.py').exists():
        return 'django'
    if (project_dir / 'app.py').exists() or (project_dir / 'application.py').exists():
        content = ''
        for py_file in project_dir.glob('*.py'):
            try:
                content += py_file.read_text()
            except:
                pass
        if 'FastAPI' in content or 'fastapi' in content:
            return 'fastapi'
        if 'Flask' in content or 'flask' in content:
            return 'flask'
    return None


def _prompt_features() -> tuple:
    """Interactive feature selection."""
    features = []
    all_features = ['saml', 'oidc', 'mfa', 'social', 'webhooks', 'audit', 'organizations']
    
    console.print("\n[bold]Select Features:[/bold]")
    for feature in all_features:
        if Confirm.ask(f"  Enable {feature}?", default=True):
            features.append(feature)
    
    return tuple(features)


def _create_directories(project_dir: Path):
    """Create project directory structure."""
    dirs = [
        'src',
        'src/auth',
        'src/api',
        'src/models',
        'src/config',
        'migrations',
        'tests',
        'docs'
    ]
    for d in dirs:
        (project_dir / d).mkdir(parents=True, exist_ok=True)


def _create_config(project_dir: Path, framework: str, database: str, features: tuple):
    """Create configuration file."""
    config_content = f'''"""
Authy Configuration - {project_dir.name}
Auto-generated by Authy CLI
"""
from authy_package import AuthConfig
from authy_package.db import SQLDatabase, MongoDBDatabase, DynamoDBAdapter

# Database configuration
DATABASE_URL = "{{{{ get_env('DATABASE_URL') }}}}"

# Initialize database adapter
'''
    
    if database == 'mongodb':
        config_content += '''db = MongoDBDatabase(DATABASE_URL)
'''
    elif database == 'dynamodb':
        config_content += '''db = DynamoDBAdapter(
    table_prefix="authy_",
    # Uses IAM roles in production, no credentials needed
)
'''
    else:
        config_content += '''db = SQLDatabase(DATABASE_URL)
'''
    
    config_content += f'''
# Auth configuration
config = AuthConfig(
    app_name="{project_dir.name}",
    secret_key="{{{{ get_env('AUTHY_SECRET_KEY') }}}}",
    token_expiry_hours=24,
    refresh_token_expiry_days=7,
    session_limit=5,
    password_min_length=12,
    require_mfa={('mfa' in features)},
    enable_saml={('saml' in features)},
    enable_oidc={('oidc' in features)},
    enable_social_auth={('social' in features)},
    enable_webhooks={('webhooks' in features)},
    enable_audit_log={('audit' in features)},
    enable_organizations={('organizations' in features)},
)

# Initialize auth managers
auth = config.create_auth_manager(db)
'''
    
    (project_dir / 'src' / 'config' / 'auth_config.py').write_text(config_content)


def _create_app_file(project_dir: Path, framework: str, database: str, features: tuple):
    """Create main application file based on framework."""
    
    if framework == 'fastapi':
        app_content = '''"""
FastAPI Application with Authy Authentication
"""
from fastapi import FastAPI, Depends, HTTPException
from authy_package.fastapi_adapter import FastAPIAuth

from .config.auth_config import auth, db

app = FastAPI(title="Authy App")

# Initialize FastAPI adapter
fastapi_auth = FastAPIAuth(auth)

@app.get("/")
async def root():
    return {"message": "Welcome to Authy!"}

@app.get("/protected")
async def protected_route(user=Depends(fastapi_auth.require_auth())):
    """Protected route requiring authentication"""
    return {"user": user.email, "status": "authenticated"}

@app.get("/admin")
async def admin_route(user=Depends(fastapi_auth.require_role("admin"))):
    """Admin-only route"""
    return {"message": "Admin access granted"}

@app.post("/login")
async def login(credentials: dict, rate_limited=Depends(fastapi_auth.rate_limit(5, 300))):
    """Login endpoint with rate limiting"""
    # Implementation here
    pass

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
'''
        (project_dir / 'src' / 'main.py').write_text(app_content)
    
    elif framework == 'flask':
        app_content = '''"""
Flask Application with Authy Authentication
"""
from flask import Flask, request, jsonify
from functools import wraps
from authy_package.flask_adapter import FlaskAuth

from .config.auth_config import auth, db

app = Flask(__name__)
flask_auth = FlaskAuth(auth)

@app.route("/")
def root():
    return jsonify({"message": "Welcome to Authy!"})

@app.route("/protected")
@flask_auth.require_auth()
def protected_route():
    """Protected route requiring authentication"""
    return jsonify({"user": flask_auth.current_user.email, "status": "authenticated"})

@app.route("/admin")
@flask_auth.require_role("admin")
def admin_route():
    """Admin-only route"""
    return jsonify({"message": "Admin access granted"})

@app.route("/login", methods=["POST"])
@flask_auth.rate_limit(5, 300)
def login():
    """Login endpoint with rate limiting"""
    # Implementation here
    pass

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8000)
'''
        (project_dir / 'src' / 'app.py').write_text(app_content)
    
    elif framework == 'django':
        app_content = '''"""
Django Application with Authy Authentication
"""
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from authy_package.django_adapter import DjangoAuth

from .config.auth_config import auth, db

django_auth = DjangoAuth(auth)

@require_http_methods(["GET"])
def root(request):
    return JsonResponse({"message": "Welcome to Authy!"})

@require_http_methods(["GET"])
@django_auth.require_auth()
def protected_route(request):
    """Protected route requiring authentication"""
    return JsonResponse({"user": request.auth_user.email, "status": "authenticated"})

@require_http_methods(["GET"])
@django_auth.require_role("admin")
def admin_route(request):
    """Admin-only route"""
    return JsonResponse({"message": "Admin access granted"})

@require_http_methods(["POST"])
@csrf_exempt
@django_auth.rate_limit(5, 300)
def login(request):
    """Login endpoint with rate limiting"""
    # Implementation here
    pass
'''
        (project_dir / 'src' / 'views.py').write_text(app_content)
    
    else:
        # Generic example
        app_content = '''"""
Generic Python Application with Authy Authentication
"""
from authy_package import AuthConfig
from authy_package.db import SQLDatabase

# Initialize
db = SQLDatabase("postgresql://localhost/authy")
config = AuthConfig(
    app_name="my-app",
    secret_key="change-me-in-production",
)
auth = config.create_auth_manager(db)

async def main():
    # Example: Create user
    user = await auth.create_user(
        email="user@example.com",
        password="secure-password-123"
    )
    print(f"Created user: {user.email}")
    
    # Example: Authenticate
    session = await auth.authenticate("user@example.com", "secure-password-123")
    print(f"Authenticated: {session.access_token}")

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
'''
        (project_dir / 'src' / 'app.py').write_text(app_content)


def _create_env_template(project_dir: Path, database: str, features: tuple):
    """Create .env.example file."""
    env_content = f'''# Authy Environment Configuration
# Copy this file to .env and fill in your values

# Application
APP_NAME={project_dir.name}
AUTHY_SECRET_KEY=change-me-to-a-secure-random-string

# Database Configuration
'''
    
    if database == 'postgresql':
        env_content += '''DATABASE_URL=postgresql://user:password@localhost:5432/authy
'''
    elif database == 'mysql':
        env_content += '''DATABASE_URL=mysql://user:password@localhost:3306/authy
'''
    elif database == 'sqlite':
        env_content += '''DATABASE_URL=sqlite:///./authy.db
'''
    elif database == 'mongodb':
        env_content += '''DATABASE_URL=mongodb://localhost:27017/authy
'''
    elif database == 'dynamodb':
        env_content += '''# DynamoDB uses IAM roles in production
AWS_REGION=us-east-1
AUTHY_DYNAMODB_TABLE_PREFIX=authy_
'''
    
    if 'saml' in features:
        env_content += '''
# SAML Configuration
SAML_ENTITY_ID=https://your-app.com/saml/metadata
SAML_ACS_URL=https://your-app.com/saml/acs
SAML_IDP_METADATA_URL=https://your-idp.com/metadata
'''
    
    if 'oidc' in features:
        env_content += '''
# OIDC Configuration
OIDC_CLIENT_ID=your-client-id
OIDC_CLIENT_SECRET=your-client-secret
OIDC_ISSUER_URL=https://your-idp.com/.well-known/openid-configuration
'''
    
    if 'social' in features:
        env_content += '''
# Social Auth Configuration
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=
'''
    
    if 'webhooks' in features:
        env_content += '''
# Webhook Configuration
WEBHOOK_SECRET=generate-a-secure-secret-for-webhook-signatures
'''
    
    (project_dir / '.env.example').write_text(env_content)


def _create_requirements(project_dir: Path, framework: str, database: str, features: tuple):
    """Create requirements.txt file."""
    deps = [
        'authy-package>=2.0.0',
        'rich>=13.0.0',
        'click>=8.0.0',
        'python-dotenv>=1.0.0',
    ]
    
    if framework == 'fastapi':
        deps.extend(['fastapi>=0.100.0', 'uvicorn[standard]>=0.23.0', 'pydantic>=2.0.0'])
    elif framework == 'flask':
        deps.extend(['flask>=2.3.0', 'werkzeug>=2.3.0'])
    elif framework == 'django':
        deps.extend(['django>=4.2.0'])
    
    if database == 'postgresql':
        deps.append('asyncpg>=0.29.0')
    elif database == 'mysql':
        deps.append('aiomysql>=0.2.0')
    elif database == 'mongodb':
        deps.append('motor>=3.3.0')
    elif database == 'dynamodb':
        deps.append('aioboto3>=12.0.0')
    
    if 'saml' in features:
        deps.extend(['lxml>=4.9.0', 'xmlsec>=1.3.14', 'cryptography>=41.0.0'])
    
    if 'oidc' in features:
        deps.extend(['authlib>=1.2.0', 'httpx>=0.24.0'])
    
    (project_dir / 'requirements.txt').write_text('\n'.join(deps) + '\n')


def _create_readme(project_dir: Path, name: str, framework: str, database: str, features: tuple):
    """Create README.md file."""
    readme_content = f'''# {name}

Enterprise authentication application built with Authy.

## Features

'''
    
    feature_list = {
        'saml': '- ✅ SAML 2.0 SSO',
        'oidc': '- ✅ OpenID Connect',
        'mfa': '- ✅ Multi-Factor Authentication',
        'social': '- ✅ Social Login (Google, GitHub, etc.)',
        'webhooks': '- ✅ Webhook Events',
        'audit': '- ✅ Audit Logging',
        'organizations': '- ✅ Multi-Tenancy/Organizations'
    }
    
    for f in features:
        if f in feature_list:
            readme_content += feature_list[f] + '\n'
    
    readme_content += f'''
## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure Environment

```bash
cp .env.example .env
# Edit .env with your configuration
```

### 3. Run Migrations

```bash
authy migrate run
```

### 4. Start Development Server

```bash
authy dev
```

## Framework

Built with **{framework}** and **{database}**.

## Documentation

- [Authy Documentation](https://github.com/authy-package/docs)
- [API Reference](./docs/api.md)

## License

MIT
'''
    
    (project_dir / 'README.md').write_text(readme_content)


def _create_gitignore(project_dir: Path):
    """Create .gitignore file."""
    gitignore = '''# Byte-compiled / optimized / DLL files
__pycache__/
*.py[cod]
*$py.class

# C extensions
*.so

# Distribution / packaging
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg

# PyInstaller
*.manifest
*.spec

# Installer logs
pip-log.txt
pip-delete-this-directory.txt

# Unit test / coverage reports
htmlcov/
.tox/
.nox/
.coverage
.coverage.*
.cache
nosetests.xml
coverage.xml
*.cover
*.py,cover
.hypothesis/
.pytest_cache/

# Translations
*.mo
*.pot

# Environments
.env
.venv
env/
venv/
ENV/
env.bak/
venv.bak/

# IDE
.idea/
.vscode/
*.swp
*.swo
*~

# Authy
*.key
*.pem
secrets/
'''
    
    (project_dir / '.gitignore').write_text(gitignore)
