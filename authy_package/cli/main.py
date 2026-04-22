"""
Authy CLI - Enterprise Authentication Command Line Interface

Usage:
    authy init          # Initialize new project with zero-config
    authy dev           # Start local development environment
    authy deploy        # Deploy to production (AWS/Vercel/K8s)
    authy migrate       # Migrate users from other providers
    authy admin         # Launch security dashboard
"""

import asyncio
import click
import json
import os
from pathlib import Path
from typing import Optional

from .commands import (
    init_project,
    start_dev_environment,
    deploy_application,
    run_migration,
    launch_admin_dashboard
)


@click.group()
@click.version_option(version="1.0.0", prog_name="authy")
def cli():
    """🔐 Authy - Enterprise Authentication Platform CLI
    
    The fastest way to add secure authentication to any Python project.
    """
    pass


@cli.command()
@click.option('--framework', type=click.Choice(['fastapi', 'flask', 'django', 'none']), 
              default='fastapi', help='Web framework to integrate')
@click.option('--db', type=click.Choice(['postgres', 'mysql', 'mongodb', 'sqlite']), 
              default='postgres', help='Database backend')
@click.option('--ui', type=click.Choice(['react', 'vue', 'svelte', 'none']), 
              default='react', help='Frontend UI kit')
@click.option('--auth-providers', multiple=True, 
              type=click.Choice(['google', 'github', 'apple', 'microsoft', 'passwordless']),
              default=['google'], help='Social auth providers to enable')
@click.pass_context
def init(ctx, framework: str, db: str, ui: str, auth_providers: tuple):
    """🚀 Initialize a new Authy project with zero configuration
    
    Creates project structure, configuration files, and starter code.
    
    Examples:
        authy init --framework fastapi --db postgres --ui react
        authy init --framework django --db mysql --ui none
    """
    config = {
        'framework': framework,
        'database': db,
        'ui_kit': ui,
        'providers': list(auth_providers),
        'project_name': Path.cwd().name
    }
    
    click.echo(f"🔐 Initializing Authy project in {Path.cwd()}...")
    success = init_project(config)
    
    if success:
        click.echo(click.style("✅ Project initialized successfully!", fg="green"))
        click.echo("\nNext steps:")
        click.echo("  1. Review generated authy_config.json")
        click.echo("  2. Update .env with your secrets")
        click.echo("  3. Run 'authy dev' to start development server")
    else:
        click.echo(click.style("❌ Initialization failed", fg="red"))
        ctx.exit(1)


@cli.command()
@click.option('--port', default=8000, help='Development server port')
@click.option('--hot-reload', is_flag=True, default=True, help='Enable hot reloading')
@click.option('--mock-services', is_flag=True, default=True, help='Mock external services (email, SMS)')
@click.option('--hosted-pages', is_flag=True, default=True, help='Enable hosted login pages')
def dev(port: int, hot_reload: bool, mock_services: bool, hosted_pages: bool):
    """🛠️ Start local development environment
    
    Spins up database, cache, and auth server with hot reloading.
    Mocks external services for faster local development.
    
    Examples:
        authy dev
        authy dev --port 9000 --no-mock-services
    """
    click.echo(f"🚀 Starting Authy development environment on port {port}...")
    
    config = {
        'port': port,
        'hot_reload': hot_reload,
        'mock_services': mock_services,
        'hosted_pages': hosted_pages
    }
    
    try:
        asyncio.run(start_dev_environment(config))
    except KeyboardInterrupt:
        click.echo("\n👋 Development server stopped")


@cli.command()
@click.option('--target', type=click.Choice(['aws-lambda', 'vercel', 'docker', 'kubernetes']), 
              default='docker', help='Deployment target')
@click.option('--region', default='us-east-1', help='Cloud region')
@click.option('--dry-run', is_flag=True, help='Validate configuration without deploying')
def deploy(target: str, region: str, dry_run: bool):
    """🌍 Deploy authentication service to production
    
    Packages and deploys your auth service to cloud providers.
    Handles SSL, scaling, and security hardening automatically.
    
    Examples:
        authy deploy --target aws-lambda --region eu-west-1
        authy deploy --target kubernetes --dry-run
    """
    click.echo(f"📦 Preparing deployment to {target} in {region}...")
    
    if dry_run:
        click.echo("🔍 Running validation checks...")
    
    config = {
        'target': target,
        'region': region,
        'dry_run': dry_run
    }
    
    success = deploy_application(config)
    
    if success:
        if dry_run:
            click.echo(click.style("✅ Validation passed! Ready to deploy.", fg="green"))
        else:
            click.echo(click.style("✅ Deployment successful!", fg="green"))
    else:
        click.echo(click.style("❌ Deployment failed", fg="red"))


@cli.command()
@click.option('--from-provider', type=click.Choice(['firebase', 'auth0', 'django', 'cognito', 'supabase']), 
              required=True, help='Source authentication provider')
@click.option('--config-file', type=click.Path(exists=True), help='Provider configuration file')
@click.option('--strategy', type=click.Choice(['full', 'lazy-password-migration']), 
              default='lazy-password-migration', help='Password migration strategy')
@click.option('--dry-run', is_flag=True, help='Preview migration without applying')
def migrate(from_provider: str, config_file: Optional[str], strategy: str, dry_run: bool):
    """🔄 Migrate users from another authentication provider
    
    Seamlessly imports users while preserving password hashes.
    Supports lazy migration to avoid forcing password resets.
    
    Examples:
        authy migrate --from-provider firebase --config-file firebase-key.json
        authy migrate --from-provider auth0 --strategy full --dry-run
    """
    click.echo(f"🔄 Migrating from {from_provider} using {strategy} strategy...")
    
    if config_file:
        with open(config_file, 'r') as f:
            provider_config = json.load(f)
    else:
        provider_config = {}
    
    config = {
        'provider': from_provider,
        'provider_config': provider_config,
        'strategy': strategy,
        'dry_run': dry_run
    }
    
    result = run_migration(config)
    
    if result['success']:
        click.echo(click.style(f"✅ Migration completed: {result['users_migrated']} users imported", fg="green"))
        if result.get('warnings'):
            click.echo(f"⚠️  Warnings: {len(result['warnings'])}")
    else:
        click.echo(click.style(f"❌ Migration failed: {result['error']}", fg="red"))


@cli.command()
@click.option('--port', default=8080, help='Admin dashboard port')
@click.option('--read-only', is_flag=True, help='Open in read-only mode')
def admin(port: int, read_only: bool):
    """🛡️ Launch enterprise security dashboard
    
    View audit logs, manage users, monitor threats, and configure compliance.
    
    Examples:
        authy admin
        authy admin --read-only --port 9090
    """
    click.echo(f"🛡️  Launching security dashboard on port {port}...")
    
    config = {
        'port': port,
        'read_only': read_only
    }
    
    try:
        asyncio.run(launch_admin_dashboard(config))
    except KeyboardInterrupt:
        click.echo("\n👋 Dashboard closed")


def main():
    """Entry point for the authy CLI command"""
    cli()


if __name__ == '__main__':
    main()
