# Authy RBAC — Status Report (2.0 remediation)

Status document. Supersedes earlier versions of this report, which mixed
an accurate description of the RBAC engine with unverifiable performance
figures, vendor comparisons, and a TODO checklist contradicting other
reports. Authoritative spec: [`docs/CONTRACTS.md`](docs/CONTRACTS.md)
(§4 db persistence for roles/assignments, §5 authorization checks).

## Components

| Component | Location | Status |
|---|---|---|
| Core RBAC engine | `authy_package/admin/rbac_manager.py` | Delivered (rebuilt) |
| REST endpoints | `authy_package/admin/rbac_api.py` | Delivered (rebuilt) |
| React role manager UI | `authy_package/ui_kits/react/admin-dashboard/src/components/RBACManager.tsx` | Delivered (rebuilt) |
| Persistence | db contract: `save_role`, `get_role`, `list_roles`, `delete_role`, `save_role_assignment`, `query_role_assignments`, `delete_role_assignment` (CONTRACTS.md §4) | Delivered |

## Core concepts

- **Permissions** — granular `resource:action` names
  (e.g. `user:create`, `audit:export`), grouped by category
  (users, org, audit, billing, settings, sessions).
- **Roles** — named permission sets with single-parent inheritance;
  circular inheritance is rejected. System roles (`is_system=True`)
  cannot be deleted or modified.
- **Assignments** — bind a user to a role with a scope:
  `global`, `organization`, `team`, or `resource`; optional `expires_at`
  for time-limited access; `granted_by` recorded for audit.
- **Evaluation** — default-deny; effective permissions = role permissions
  ∪ inherited permissions, filtered by scope.

## API endpoints (`/admin/v2/rbac/*`)

| Method | Endpoint | Purpose |
|---|---|---|
| POST/GET | `/rbac/permissions` | Create/list permissions (filter by category) |
| POST/GET | `/rbac/roles` | Create/list roles (optionally per org) |
| PUT/DELETE | `/rbac/roles/{id}` | Update/delete custom roles |
| POST | `/rbac/assignments` | Assign role to user (scoped, expiring) |
| DELETE | `/rbac/assignments/{id}` | Revoke assignment |
| GET | `/rbac/users/{user_id}/roles` | User's role assignments |
| POST | `/rbac/check-permission` | Evaluate one permission |
| GET | `/rbac/users/{user_id}/permissions` | Effective permissions |

All endpoints sit behind the CONTRACTS.md §5 authorization model
(bearer-only JWT or hashed admin API key; admin role or `admin:*` RBAC
grant; org-admin enforcement on org-scoped routes).

## Default permission catalog

`user:read/create/update/delete/impersonate`,
`org:read/create/update/delete/manage-members`,
`audit:read/export/delete`,
`billing:read/update/manage`,
`role:manage`, `config:update`, `webhook:manage`,
`session:read/revoke/revoke-all`.

## Usage

```python
from authy_package.admin.rbac_manager import RBACManager, PermissionScope

rbac = RBACManager(db=db)

role = await rbac.create_role(
    name="Compliance Officer",
    description="Can view and export audit logs",
    permissions=["audit:read", "audit:export"],
    organization_id=org_id,
)

await rbac.assign_role(
    user_id=user_id,
    role_id=role["id"],
    scope_type=PermissionScope.ORGANIZATION,
    scope_id=org_id,
    granted_by=admin_id,
)

allowed = await rbac.has_permission(
    user_id=user_id,
    permission_name="audit:export",
    scope_type=PermissionScope.ORGANIZATION,
    scope_id=org_id,
)
```

## Verification

RBAC behavior (role CRUD, inheritance, scoping, expiry, system-role
protection) is covered by the remediation test suite using the in-memory
fakes per CONTRACTS.md §0 rule 10 and §12 — the previous report's
"unit tests: recommended next step" TODO is resolved by that suite.

Claims removed from the previous report as unverifiable:
permission-check latency/throughput figures, cache hit rates, and the
Auth0/Okta/AWS IAM comparison table.

---

*Changed in the 2.0 remediation — see
`docs/REMEDIATION_STATUS_packaging.md` for the documentation changelog.*
