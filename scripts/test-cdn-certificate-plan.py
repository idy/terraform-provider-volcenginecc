#!/usr/bin/env python3
"""Prove CDN certificate plans in disposable state. Never runs Terraform Apply."""

import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
ADDRESS = "registry.terraform.io/volcengine/volcenginecc"
VERSION = (ROOT / "version/VERSION").read_text().strip()
RESOURCE = "volcenginecc_cdn_domain.legacy"
DEFAULT_ORIGIN = [{"origin_action": {"origin_lines": [{
    "address": "origin.example.com", "origin_host": "origin.example.com", "origin_type": "primary",
    "instance_type": "domain", "http_port": "80", "https_port": "443", "weight": "1", "private_bucket_access": False,
}]}}]


def fixture(binding='"old-certificate"', tls='["tlsv1.2", "tlsv1.3"]', extra="", origin=None, ca=False):
    return '''terraform {
  required_providers {
    volcenginecc = { source = "volcengine/volcenginecc", version = "= PROVIDER_VERSION" }
  }
}
provider "volcenginecc" {
  access_key = "fixture-access"
  secret_key = "fixture-secret"
  region     = "cn-hongkong"
}
resource "volcenginecc_cdn_domain" "legacy" {
  domain         = "legacy.example.com"
  project        = "fixture"
  service_region = "chinese_mainland"
  service_type   = "download"
  origin = ORIGIN
  https = {
    switch = true
    cert_info = { cert_id = BINDING, source = "volc_cert_center" }
    http2 = true
    ocsp = true
    disable_http = false
    forced_redirect = { enable_forced_redirect = true, status_code = "301" }
    tls_version = TLS
    CA_CHECK
  }
  lifecycle { prevent_destroy = true }
}
'''.replace("PROVIDER_VERSION", VERSION).replace("BINDING", binding).replace("TLS", tls).replace("ORIGIN", json.dumps(DEFAULT_ORIGIN if origin is None else origin)).replace(
        "CA_CHECK", 'cert_check = { switch = true, cert_info_list = [{cert_id = "ca-certificate", source = "cdn_cert_hosting"}] }' if ca else ""
    ) + extra


def check_provider(binary, terraform, baseline=False):
    system = {"Darwin": "darwin", "Linux": "linux"}[platform.system()]
    arch = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "amd64"}[platform.machine()]
    with tempfile.TemporaryDirectory(prefix="cdn-certificate-plan-") as temporary:
        root = Path(temporary)
        package = root / "mirror" / ADDRESS / VERSION / f"{system}_{arch}"
        package.mkdir(parents=True)
        (package / f"terraform-provider-volcenginecc_v{VERSION}").symlink_to(binary)
        (root / "terraform.rc").write_text(
            'provider_installation { filesystem_mirror { path = ' + json.dumps(str(root / "mirror")) +
            ' include = ["' + ADDRESS + '"] } }\n'
        )
        env = {key: value for key, value in os.environ.items()
               if not key.startswith(("TF_", "VOLCENGINE_", "VOLC_", "AWS_"))}
        env.update(TF_CLI_CONFIG_FILE=str(root / "terraform.rc"), TF_IN_AUTOMATION="1", CHECKPOINT_DISABLE="1")

        def run(*arguments, allowed=(0,)):
            result = subprocess.run([terraform, "-chdir=" + str(root), *arguments], env=env,
                                    capture_output=True, text=True, timeout=120)
            if result.returncode not in allowed:
                raise AssertionError(f"Terraform {arguments[0]} failed:\n{result.stdout}\n{result.stderr}")
            return result

        def plan(config, allowed=(0,)):
            (root / "main.tf").write_text(config)
            return run("plan", "-refresh=false", "-input=false", "-no-color", "-out=" + str(root / "plan"), allowed=allowed)

        def change():
            data = json.loads(run("show", "-json", str(root / "plan")).stdout)
            return next(item["change"] for item in data["resource_changes"] if item["address"] == RESOURCE)

        (root / "main.tf").write_text(fixture())
        run("init", "-backend=false", "-input=false", "-no-color")
        plan(fixture())
        schemas = json.loads(run("providers", "schema", "-json").stdout)
        resource_schema = schemas["provider_schemas"][ADDRESS]["resource_schemas"]["volcenginecc_cdn_domain"]

        def synthetic_value(value, declaration):
            nested = declaration.get("nested_type")
            if nested:
                if nested["nesting_mode"] in {"list", "set"}:
                    return [] if value is None else [
                        {name: synthetic_value(item.get(name), child) for name, child in nested["attributes"].items()}
                        for item in value
                    ]
                value = value or {}
                return {name: synthetic_value(value.get(name), child) for name, child in nested["attributes"].items()}
            if value is not None:
                return value
            kind = declaration["type"]
            if isinstance(kind, str):
                return {"string": "", "bool": False, "number": 0}[kind]
            return {} if kind[0] == "map" else []

        # Construct a wholly synthetic, stable prior checkpoint from the schema.
        # Unconfigured computed fields have benign known fixture values; they are
        # not claims about any actual server configuration. No Apply is used.
        planned = change()["after"]
        values = {name: synthetic_value(planned.get(name), declaration)
                  for name, declaration in resource_schema["block"]["attributes"].items()}
        values.update(id="fixture-domain-id", cname="legacy.cdn.example.net", status="online", created_time=100, updated_time=200)
        values["https"]["cert_info"].update(cert_name="legacy.example.com", effective_time=100, expire_time=1000, encry_type="inter_cert")
        checkpoint = {
            "version": 4, "terraform_version": "1.15.8", "serial": 1,
            "lineage": "402977f6-5223-4b5a-8c5d-9cb2f8f8d27b", "outputs": {},
            "resources": [{"mode": "managed", "type": "volcenginecc_cdn_domain", "name": "legacy",
                           "provider": 'provider["' + ADDRESS + '"]',
                           "instances": [{"schema_version": 1, "attributes": values}]}],
        }
        # The resource schema owns its state version; query it rather than
        # assuming that its source-version number is a Terraform schema version.
        checkpoint["resources"][0]["instances"][0]["schema_version"] = resource_schema["version"]
        (root / "terraform.tfstate").write_text(json.dumps(checkpoint))

        if baseline:
            result = plan(fixture('"new-certificate"'), allowed=(1,))
            assert "Instance cannot be destroyed" in result.stderr, result.stderr
            print("baseline: certificate renewal requests domain replacement and prevent_destroy blocks it")
            return

        for label, config, unknown in [
            ("known certificate", fixture('"new-certificate"'), False),
            ("unknown renewed certificate", fixture("terraform_data.next_certificate.output", extra='\nresource "terraform_data" "next_certificate" { input = "new-certificate" }\n'), True),
        ]:
            plan(config)
            actual = change()
            assert actual["actions"] == ["update"], actual["actions"]
            assert not actual.get("replace_paths"), actual.get("replace_paths")
            assert actual["after"]["id"] == values["id"]
            assert actual["after"]["cname"] == values["cname"]
            assert bool(actual["after_unknown"].get("https", {}).get("cert_info", {}).get("cert_id", False)) == unknown
            assert actual["after_unknown"].get("updated_time") is True
            print(f"patched {label}: update in place, unchanged ID/CNAME, no replacement")
        nullable = json.loads(json.dumps(checkpoint))
        origin = nullable["resources"][0]["instances"][0]["attributes"]["origin"][0]
        origin["condition"] = None
        origin["origin_action"]["origin_lines"][0]["region"] = None
        (root / "terraform.tfstate").write_text(json.dumps(nullable))
        plan(fixture('"new-certificate"'))
        actual = change()
        assert actual["actions"] == ["update"] and not actual.get("replace_paths"), actual["actions"]
        assert actual["after"]["origin"] == nullable["resources"][0]["instances"][0]["attributes"]["origin"]
        print("patched nullable origin metadata: unchanged origin, certificate update only")

        multiple = json.loads(json.dumps(nullable))
        lines = multiple["resources"][0]["instances"][0]["attributes"]["origin"][0]["origin_action"]["origin_lines"]
        backup = json.loads(json.dumps(lines[0]))
        backup.update(address="backup.example.com", origin_host="backup.example.com", origin_type="backup")
        lines.append(backup)
        configured_origin = json.loads(json.dumps(DEFAULT_ORIGIN))
        configured_backup = json.loads(json.dumps(DEFAULT_ORIGIN[0]["origin_action"]["origin_lines"][0]))
        configured_backup.update(address="backup.example.com", origin_host="backup.example.com", origin_type="backup")
        configured_origin[0]["origin_action"]["origin_lines"].append(configured_backup)
        (root / "terraform.tfstate").write_text(json.dumps(multiple))
        plan(fixture('"new-certificate"', origin=configured_origin))
        assert change()["actions"] == ["update"]
        print("patched primary/backup origins: certificate update without replacement")

        mtls = json.loads(json.dumps(checkpoint))
        https_schema = resource_schema["block"]["attributes"]["https"]["nested_type"]["attributes"]
        ca_schema = https_schema["cert_check"]["nested_type"]["attributes"]["cert_info_list"]
        ca_value = synthetic_value([{"cert_id": "ca-certificate", "source": "cdn_cert_hosting"}], ca_schema)
        ca_value[0]["certificate"] = None
        check = mtls["resources"][0]["instances"][0]["attributes"]["https"]["cert_check"]
        check.update(switch=True, cert_info_list=ca_value)
        (root / "terraform.tfstate").write_text(json.dumps(mtls))
        plan(fixture('"new-certificate"', ca=True))
        actual = change()
        assert actual["actions"] == ["update"]
        assert actual["after"]["https"]["cert_check"] == check
        print("patched existing client-CA certificate set: known and unchanged during server certificate renewal")
        (root / "terraform.tfstate").write_text(json.dumps(checkpoint))
        result = plan(fixture('"new-certificate"', tls='["tlsv1.3"]'), allowed=(1,))
        assert "Instance cannot be destroyed" in result.stderr, result.stderr
        print("patched non-certificate HTTPS change: original replacement protection retained")
        result = plan(fixture('"new-certificate"').replace("origin.example.com", "changed.example.com"), allowed=(1,))
        assert "Instance cannot be destroyed" in result.stderr, result.stderr
        print("patched origin configuration change: original replacement protection retained")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider", type=Path)
    parser.add_argument("--baseline-provider", type=Path)
    parser.add_argument("--terraform", default=shutil.which("terraform"))
    arguments = parser.parse_args()
    if not arguments.terraform:
        parser.error("Terraform is required")
    if arguments.provider is None:
        arguments.provider = ROOT / "bin/terraform-provider-volcenginecc"
    for binary in [arguments.provider, arguments.baseline_provider]:
        if binary is not None and (not binary.is_file() or not os.access(binary, os.X_OK)):
            parser.error("provider must be an existing executable")
    check_provider(arguments.provider.resolve(), arguments.terraform)
    if arguments.baseline_provider:
        check_provider(arguments.baseline_provider.resolve(), arguments.terraform, baseline=True)


if __name__ == "__main__":
    main()
