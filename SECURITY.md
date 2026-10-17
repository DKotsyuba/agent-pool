# Security boundary

<!-- Replace this section with the product's actual boundary before
implementing mutations: authorized roots/tenants, subjects, side effects and a
real reporting channel. -->

The product exposes one read-only identity tool. It performs no filesystem
mutation, external SaaS access, daemon, or credential handling. Describe the
actual authorized roots, subjects and side effects before implementing
mutations. Tool annotations and caller-supplied actor labels are not
authentication.

Do not publish secrets or raw user content in logs, snapshots or evidence.
Report security concerns privately to the repository owner; establish a real
reporting channel before public distribution.
