# Alert Portal

Alert Portal is a self-service web application for creating and managing Prometheus alerting rules through a browser. It provides authenticated access, role-based permissions, validated alert expressions, and Mattermost notification destination management.

**Application version:** `0.1.20` (declared in `app/main.py`).

> Publication status: This repository is being prepared from a previously deployed application. The reusable Kubernetes deployment and installation instructions are not yet complete. Do not apply the legacy deployment or monitoring overlays to a cluster without review.

## How it works

1. A user signs in with a local account or, when enabled, an Active Directory account over LDAPS.
2. Authorized users create, update, or delete alert definitions in the portal.
3. The portal validates rule inputs and manages Kubernetes `PrometheusRule` resources.
4. Prometheus evaluates the rules; Alertmanager handles notifications.
5. The portal can forward Alertmanager events to approved Mattermost destinations.

Alert Portal is **not** a replacement for Prometheus, Prometheus Operator, or Alertmanager. It is an application that integrates with them. It is not currently part of the `kube-prometheus-stack` Helm chart.

## Features

- Local-user authentication and optional Active Directory LDAPS authentication.
- Administrator, editor, and viewer roles with server-side authorization checks.
- Rule ownership metadata, managed `PrometheusRule` resources, and PromQL validation/templates.
- Mattermost destination management and authenticated Alertmanager webhook forwarding.
- PostgreSQL persistence and application health endpoints.
- Automated Python regression tests.

## Technology stack

- Python 3.12, FastAPI, Uvicorn
- PostgreSQL
- Kubernetes and Prometheus Operator (`PrometheusRule` CRD)
- Prometheus and Alertmanager
- Mattermost API integration

## Repository layout

| Path | Purpose |
| --- | --- |
| `app/` | Application source, authentication, routes, and services |
| `tests/` | Unit, API, and security regression tests |
| `migrations/` | Database schema migrations; review before applying |
| `schema.sql` | Schema for a **new** database only |
| `scripts/` | Administrative setup helpers; some mutate Kubernetes resources |
| `Dockerfile` | Application container build |
| `requirements.txt` | Pinned Python runtime dependencies |

## Local development and tests

Use Python 3.12 and an isolated environment. The following commands are intended for a **development machine**, not a production server:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt pytest httpx
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -q -p no:cacheprovider tests/
```

The sanitized GitHub preparation copy passed **264 tests, 0 failures, and 8 dependency deprecation warnings** on 2026-11-10 using Python 3.12.3 and pytest 9.1.1. Re-run the suite after changes and before a release. The development-only `pytest` and `httpx` dependencies in the example above are not yet covered by a version-locked development requirements file.

## Configuration and secrets

Configure environment variables and Kubernetes Secret/ConfigMap references appropriate to your deployment. Relevant variable names include:

| Area | Variables |
| --- | --- |
| Database | `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASSWORD` |
| Prometheus | `PROMETHEUS_URL`, `PROMETHEUS_RULE_NAMESPACE`, `PROMETHEUS_RELEASE_LABEL_VALUE` |
| LDAP (optional) | `LDAP_ENABLED`, `LDAP_HOST`, `LDAP_PORT`, `LDAP_BASE_DN`, `LDAP_GROUP_DN`, `LDAP_NETBIOS_DOMAIN`, `LDAP_CA_CERT_FILE`, `LDAP_TIMEOUT`, `LDAP_LEGACY_TLS_COMPAT` |
| Mattermost | `MATTERMOST_BASE_URL`, `MATTERMOST_ALLOWED_HOSTS`, `MATTERMOST_BOT_TOKEN` |
| Alertmanager | `ALERTMANAGER_WEBHOOK_TOKEN` |
| Session security | `COOKIE_SECURE`, `SESSION_HOURS` |

Never commit live `.env` files, API tokens, database credentials, private keys, Kubernetes Secrets, or production webhook URLs. `LDAP_ENABLED` is disabled by default. LDAPS must validate certificates and server hostnames. Do not enable `LDAP_LEGACY_TLS_COMPAT` unless a security review explicitly approves a temporary exception. `LDAP_TIMEOUT` defaults to 10 seconds and accepts 1–30 seconds.

**Set `COOKIE_SECURE=true` whenever users access the portal over HTTPS.** The current application code defaults this variable to `false`, which is unsuitable for a TLS-terminated production deployment unless explicitly overridden. `SESSION_HOURS` defaults to 8. Configure `PROMETHEUS_URL` for the target environment; its application default points to a Kubernetes Service DNS name and is not a generic remote-Prometheus address.

The historical `mattermost_destinations` table contains an encrypted webhook column, but the active v0.1.20 Mattermost Bot flow reads `MATTERMOST_BOT_TOKEN` from the environment and does not read `MATTERMOST_ENCRYPTION_KEY`. Keep historical schema and migration files for backward compatibility; do not infer that the old webhook flow remains an active integration.

## Deployment prerequisites

- Kubernetes cluster with Prometheus Operator and the `PrometheusRule` CRD installed.
- A Prometheus instance configured to discover the portal-managed rule namespace and labels.
- PostgreSQL database and reviewed schema/migration plan.
- Least-privilege Kubernetes permissions for the portal service account.
- Alertmanager routing and Mattermost configuration where notifications are required.
- Kubernetes Secrets for credentials and encryption material.

**No generic, tested deployment manifest or standalone Helm chart is included yet.** The production-specific Helm overlays and rollout patch are deliberately excluded from the initial GitHub commit. Do not use `schema.sql` to modify an existing database. Review and back up a database before applying any migration.

## Health and security

The application exposes `/health/live` and `/health/ready` for Kubernetes probes. Protect access with ingress TLS, configure least-privilege service accounts, keep an active local administrator before enabling LDAP, and review authentication/authorization boundaries before exposing the service to users.

The existing ownership annotation namespace is retained for backward compatibility with already-managed rules. Do not rename it without a migration plan.

## Compatibility and planned work

| Capability | v0.1.20 status |
| --- | --- |
| Alert Portal in Kubernetes with Prometheus Operator | Implemented; production deployment has been verified separately |
| Standalone reusable Helm chart | Not yet included or tested |
| Alert Portal deployment through Docker Compose | Planned; not included |
| Rule management for Prometheus running in Docker or as a systemd service | Planned; file-based rule backend not implemented |
| Mattermost Bot notifications | Implemented |
| Slack, Microsoft Teams, Email, and generic webhook destinations | Planned; not implemented |
| Multiple notification destinations per alert through notification policies | Planned; not implemented |

The planned design retains the existing Kubernetes `PrometheusRule` backend and Mattermost destinations, while adding a separate file-based rule backend and pluggable notification providers. These are **future changes requiring new code, migrations, security review, integration tests, and a new application version**. Do not attempt to enable them by changing v0.1.20 environment variables alone.

## Project status

This independently developed project is being prepared for an initial GitHub repository. Repository visibility and licensing must be confirmed before publishing. Installation guides, deployment templates, a reproducible dependency/build process, and a final secret scan must be completed before broader distribution. No upstream `kube-prometheus-stack` integration is claimed.
