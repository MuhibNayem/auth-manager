"""``authy deploy`` tests — honest artifact generation, no fake deploys."""

from __future__ import annotations

import shutil

import yaml

from authy_package.cli import cli


def test_deploy_aws_generates_artifacts(runner, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(cli, ["deploy", "aws", "--env", "staging"])
    assert result.exit_code == 0, result.output

    # Says exactly what it did — artifact generation, not deployment.
    assert "Generated CloudFormation artifact" in result.output
    assert "No AWS resources were created" in result.output

    # No fabricated resource ids anywhere in the output.
    assert "sg-" not in result.output
    assert "arn:aws:" not in result.output

    artifact = tmp_path / "deploy-out" / "aws-stack.yaml"
    assert artifact.exists()
    template = yaml.safe_load(artifact.read_text(encoding="utf-8"))
    assert template["AWSTemplateFormatVersion"] == "2010-09-09"
    assert "AppSecurityGroup" in template["Resources"]
    assert template["Parameters"]["Env"]["Default"] == "staging"
    assert (tmp_path / "deploy-out" / "README.md").exists()


def test_deploy_kubernetes_generates_manifests(runner, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(cli, ["deploy", "kubernetes", "--namespace", "authy-test", "--replicas", "2"])
    assert result.exit_code == 0, result.output

    k8s = tmp_path / "deploy-out" / "k8s"
    deployment = yaml.safe_load((k8s / "deployment.yaml").read_text(encoding="utf-8"))
    assert deployment["spec"]["replicas"] == 2
    assert deployment["metadata"]["namespace"] == "authy-test"
    assert (k8s / "namespace.yaml").exists()
    assert (k8s / "service.yaml").exists()
    assert "No cluster resources were created" in result.output


def test_deploy_gcp_and_azure_generate_compose(runner, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(cli, ["deploy", "gcp", "--project-id", "my-proj"])
    assert result.exit_code == 0, result.output
    compose = yaml.safe_load((tmp_path / "deploy-out" / "gcp-compose.yaml").read_text())
    assert compose["x-gcp"]["project_id"] == "my-proj"
    assert "No GCP resources were created" in result.output

    result = runner.invoke(cli, ["deploy", "azure", "--resource-group", "rg-authy"])
    assert result.exit_code == 0, result.output
    compose = yaml.safe_load((tmp_path / "deploy-out" / "azure-compose.yaml").read_text())
    assert compose["x-azure"]["resource_group"] == "rg-authy"
    assert "No Azure resources were created" in result.output


def test_deploy_docker_without_docker_cli_fails_honestly(runner, monkeypatch, tmp_path):
    """Docker path is skipped (with an honest error) when the CLI is absent."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(shutil, "which", lambda name: None)

    result = runner.invoke(cli, ["deploy", "docker"])
    assert result.exit_code == 1
    assert "docker CLI not found" in result.output
    assert "nothing was built" in result.output


def test_aws_engine_health_check_is_honest():
    from authy_package.cli.deploy import AWSDeploymentEngine

    engine = AWSDeploymentEngine()
    assert engine.health_check() is False  # nothing built yet
    engine.build_template()
    assert engine.health_check() is True
    engine._template = {"AWSTemplateFormatVersion": "2010-09-09", "Resources": {}}
    assert engine.health_check() is False  # empty resources -> unhealthy
