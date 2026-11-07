# Security boundary

Agent Pool is a local resident service. It stores pool state and queued effects
in a private SQLite database and accepts connections through a private Unix
socket. The native host launches a separate MCP frontend; it forwards protected
call metadata to Agent Bridge rather than trusting caller-supplied identities.

Pool reads and mutations require a current Bridge assertion and are authorized
against the pool leader or the caller's current membership. Mutations can change
local state, request agent starts from Agent Run, and send messages through
Agent Bridge. Removing a member revokes Pool access but does not stop its agent.
The credential-free `get_status` tool does not access the resident.

The optional owner observer uses a separate private credential and supports only
read-only state inspection; it does not grant a native participant identity.
Provision socket directories and credential files with the ownership and access
restrictions described in `docs/architecture.md` and `config.example.toml`.

Do not publish secrets or raw user content in logs, snapshots or evidence.
Use GitHub's private vulnerability reporting when available. If it is not
enabled, open an issue requesting a private contact without disclosing the
vulnerability or sensitive details in public.
