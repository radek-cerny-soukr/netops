# Admin engine

This directory contains an internal engine of the single NetOps application. It is not a separately installable or separately released package. Product version and dependencies are declared only in the root pyproject.toml and requirements.lock.

Use the [NetOps quickstart](../../docs/quickstart-1.0.md), [architecture](../../docs/architecture-1.0.md), [support boundaries](../../docs/verified-support.md) and [qualification procedure](../../docs/testing-1.0.md). Engine sources are in src; regression tests and their non-production support fixtures are in tests.

The Admin operations of each platform (profile tables, operational clears, saves, port bounces and PoE cycles, profile batches and encrypted backups), their protections, reason codes and the versions they were verified on are described in the [Admin configuration](../../docs/admin-configuration.md). A firmware outside the tested versions of a profile is reported as `firmware_support` with status `untested`, not refused; the FortiOS schema-transaction workflow still requires its exact build, and identity, account rights, device capabilities and safeguards are still checked.
