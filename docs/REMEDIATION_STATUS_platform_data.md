# Remediation Status — platform-data (database adapters)

Workstream: **platform-data** (`authy_package/db/*` adapters + `tests/platform_data`).
Contract: `docs/CONTRACTS.md` §4 (unified async `AbstractDatabase`).
Branch state verified against frozen foundation files (`db/__init__.py`,
`db/abstract_db.py`, `db/memory.py`, `db/enterprise_utils.py` — untouched).

## Changes delivered

### Deleted (contract decision: fake stubs removed)

- `authy_package/db/redis_adapter.py` — was a `pass`-body stub importing a
  non-existent `enterprise_abstract` module. Removed; `get_database()`
  raises `ConfigError` for `db_type="redis"`.
- `authy_package/db/cassandra_adapter.py` — same. Removed; `ConfigError`
  for `db_type="cassandra"`.

### Rewritten: `authy_package/db/sql.py` → `SQLDatabase(AbstractDatabase)`

Full §4 surface on SQLAlchemy 2.x async (declarative `Mapped` models;
asyncpg/aiomysql usable via URL, aiosqlite for tests/dev):

- Tables: `users`, `sessions`, `organizations`, `org_members`,
  `invitations`, `audit_events`, `webhook_endpoints`,
  `webhook_deliveries`, `roles`, `role_assignments`, `api_keys`,
  `settings`, `saml_requests`, `saml_response_ids`,
  `saml_user_mappings`, `oidc_providers`. Typed columns for the stable
  contract keys + JSON `extra` columns for provider-specific extras.
- Everything parameterized (no string-interpolated SQL; LIKE wildcards
  escaped).
- Case-insensitive identifier lookups via `LOWER()` comparisons; unique
  expression indexes `lower(email)` / `lower(username)` (+ exact phone)
  backstop the pre-checks.
- `list_users`/`list_organizations`/`search_audit_events`: LIMIT/OFFSET
  with `COUNT(...)` totals; `(rows, total)` tuples.
- Audit: `checksum` = sha256 over canonical JSON (`sort_keys`, compact
  separators, `default=str`) of the event WITHOUT db-assigned
  `id`/`sequence`/`checksum`, with `previous_checksum` included in the
  checksummed payload — byte-for-byte the `memory.py` semantics. Appends
  serialized under an asyncio lock; bulk saves are one transaction.
- `revoke_session` / `revoke_all_user_sessions`: single atomic
  `UPDATE ... WHERE status='active'` (rowcount decides).
- SAML consume: `DELETE ... RETURNING` on non-SQLite dialects;
  select+delete in one transaction (lock-guarded) on SQLite.
- SAML response-id ledger: `check_and_record` is select+insert in one
  transaction (expired TTL entries stop blocking; persistent entries
  block forever).
- `update_oidc_provider`: whitelisted columns only (`memory.py`'s
  `OIDC_UPDATABLE_FIELDS`); unknown keys → `ValueError`; issuer/slug
  reindex with uniqueness checks.
- Engine `echo` driven by config flag (`echo`/`echo_sql`) default False.
- `connect()` = engine + `create_all`; `health_check()` = `SELECT 1`;
  `close()` = `engine.dispose()`.
- Ids: `uuid.uuid4().hex`; timestamps: ISO-8601 UTC strings
  (microsecond-normalized so lexicographic == chronological).
- In-memory SQLite URLs use `StaticPool` (single shared connection).

### Rewritten: `authy_package/db/mongodb.py` → `MongoDB(AbstractDatabase)`

Full §4 surface on motor:

- `_id` = contract string id; one collection per entity (same 16).
- `connect()` creates the client and ensures indexes: unique sparse
  indexes on `email_lowercase` / `username_lowercase` / `phone`
  (lowercase-normalized fields stored at write time), unique `slug`,
  `token`, `roles.name`, `api_keys.key_hash`, `oidc_providers.issuer`
  + `slug`, unique `audit_events.sequence`, TTL indexes
  (`expireAfterSeconds=0`) on `saml_requests` / `saml_response_ids`
  (persistent response-id entries carry no `expires_at` and are never
  TTL-collected).
- Update paths whitelist `$set` keys per collection
  (`USER_UPDATABLE_FIELDS`, `ORG_UPDATABLE_FIELDS`,
  `MEMBER_UPDATABLE_FIELDS`, `WEBHOOK_ENDPOINT_UPDATABLE_FIELDS`,
  `OIDC_UPDATABLE_FIELDS`); `$`-operator keys and unknown keys are
  rejected with `ValueError` before any collection access.
- Atomic consumes: `find_one_and_delete` for SAML requests;
  unique-`_id` insert (DuplicateKeyError ⇒ replay) for response ids;
  conditional `update_one({"status": "active"})` for session revoke.
- Audit chain: exact `memory.py` checksum/hash-chain semantics
  (lock-serialized appends, sequence unique-indexed).
- Pagination: `skip`/`limit` + `count_documents` totals.
- Lazy client (constructor is import-safe/param-free of I/O); guarded
  `MOTOR_AVAILABLE` import with informative `ImportError`.

### Fixed/re-based: `authy_package/db/dynamodb_adapter.py` → `DynamoDBAdapter(AbstractDatabase)`

Now implements the FULL §4 contract (was: legacy
`EnterpriseDatabaseAdapter` surface importing a module that no longer
exists — unimportable). Kept the existing per-entity PK/SK key design
and the `CircuitBreaker` / `ObservabilityMixin` / retry wiring from
`enterprise_utils`. Specific fixes mandated by the contract review:

- **bool before int** in `_serialize_item`/`_serialize_value`
  (`True` → `{"BOOL": True}`, not `{"N": "1"}`); lists of bools
  serialize as `L` of `BOOL`, not `NS`.
- **Missing `time` import added** (health-check latency, TTL epochs).
- **Audit PK includes the event id** (`AUDIT#{event_id}`): no
  same-second collisions; `get_audit_event` is a direct-key get.
- **`query_audit_logs` GSI alignment**: actor searches query
  `GSI1Index` (`GSI1PK=ACTOR#...`), single-type searches query
  `GSI2Index` (`GSI2PK=EVENT#...`) with ISO-timestamp range on the GSI
  sort key; everything else falls back to scan (documented).
- **Atomic consumes via conditional expressions**: `consume_saml_request`
  = one `delete_item` with `ConditionExpression=attribute_exists(PK) AND
  expires_at > :now`, `ReturnValues=ALL_OLD` (exactly one winner);
  `check_and_record_saml_response_id` = one conditional `put_item`
  (`attribute_not_exists(PK) OR expires_at < :now`).
- **`get_active_sessions` filters `status == "active"`**.
- **`get_user_by_identifier(*, username, email, phone)`** keyword-only
  contract signature (email via GSI1 query; username/phone via scan).
- **Unused imports removed**; legacy non-contract methods (MFA secrets,
  login attempts, old SAML/OIDC provider tables, migration stub) removed.
- All updates are parameterized through
  `ExpressionAttributeNames`/`ExpressionAttributeValues` placeholders;
  caller input is never interpolated into expression strings.
- Timestamps are ISO-8601 UTC; `health_check()` returns `bool`.

#### Honest list: DynamoDB contract methods served by scan-based fallbacks

The key design cannot serve these directly; each is a documented scan
fallback (also exported as `SCAN_FALLBACK_OPERATIONS` in the module):

| Operation | Reason |
| --- | --- |
| `list_users`, `count_users` | No list GSI on the users table |
| `get_user_by_identifier` (username/phone paths) | GSI1 projects email only |
| identifier-uniqueness checks for username/phone | same |
| `get_invitation_by_token` | No GSI on token |
| `get_pending_invitations` | No GSI on org/status |
| `list_organizations` | No list GSI |
| `delete_organization` invitation cascade | invitations not keyed by org |
| `list_webhook_endpoints` | No list GSI |
| `list_roles`, role-name uniqueness check | No GSI on role name |
| `query_role_assignments`, `delete_role` assignment check | assignments not keyed by role/scope |
| `list_api_keys` | No list GSI (hash lookup itself uses GSI1) |
| audit chain-last lookup (`save_audit_event`) | No global-sequence key in the design |
| `search_audit_events` (multi-type / target-only / unfiltered) | GSIs cover actor and single type only |
| `get_audit_statistics`, `get_audit_time_series`, `delete_audit_events_before` | aggregation over the whole ledger |
| OIDC slug lookup / slug-uniqueness (save/update paths) | PK is issuer-keyed |

Everything else is served by direct keys or GSI queries.

## Tests (`tests/platform_data`, own `conftest.py`)

- **Parametrized conformance suite** — the SAME cases run against
  `InMemoryDatabase` and `SQLDatabase` (SQLite + aiosqlite, file-backed
  per test): users CRUD + case-insensitive lookups + pagination/search/
  filters; sessions incl. `asyncio.gather` revoke race (single winner);
  orgs/members/invitations incl. cascades; audit chain integrity +
  independent checksum recomputation + tamper detection (store-level
  mutation per backend) + statistics + time series; webhooks CRUD +
  delivery ordering; RBAC roles/assignments; API keys (hash-only);
  settings kv; SAML consume atomicity (3-way race, single winner) +
  response-id replay + TTL expiry; OIDC whitelist rejection + issuer/
  slug reindex.
- **MongoDB unit tests** — mocked motor layer (no live server): index
  creation (unique/sparse/TTL specs), `$set` whitelist + operator-key
  enforcement on every update path, lowercase-field storage/stripping,
  atomic consumes, conditional session revoke, audit chain.
- **DynamoDB unit tests** — stubbed boto3-style client honoring
  conditional expressions: bool-before-int serialization, audit PK
  uniqueness for same-second events + chain links, active-session
  filtering, single-winner conditional consumes, replay blocking,
  keyword-only identifier signature, breaker/observability wiring.
- **Removed adapters** — files absent, modules non-importable, factory
  `ConfigError` for `redis`/`cassandra`.

## Verification

- `./.venv/bin/python -m pytest tests/platform_data tests/foundation -q`
  — **green: 365 passed** (140 platform_data cases — 82 test functions
  expanded by the memory/sql-sqlite parametrization and the removed-db_type
  parametrization — plus the 225 foundation tests), exit code 0.
- `./.venv/bin/python -m compileall authy_package` — clean (exit 0).
- Adapters additionally smoke-verified: SQLDatabase end-to-end on
  sqlite+aiosqlite (users/sessions races/audit chain/SAML races/OIDC
  whitelist); DynamoDBAdapter concrete (no remaining abstract methods)
  and constructible from `DatabaseConfig` via the `get_database()`
  factory; MongoDB constructible with lazy client.

## Risks / notes

- `core/auth_manager.py` previously used the legacy
  `SQLDatabase(url, orm_model)` constructor; the contract constructor is
  `SQLDatabase(DatabaseConfig | url-str)` (factory-compatible). The
  core-auth workstream owns that call site.
- DynamoDB scan fallbacks are O(table size); acceptable per the contract
  decision, but production tables should add GSIs before heavy use of
  the listed operations.
- Multi-process audit-chain appends rely on per-process locks plus the
  unique `sequence` index (SQL) / conditional puts (DynamoDB) to detect
  contention; single-writer deployments are recommended for the ledger.
