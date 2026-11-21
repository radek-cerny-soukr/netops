# Auditor engine

This directory contains an internal engine of the single NetOps application. It is not a separately installable or separately released package. Product version and dependencies are declared only in the root pyproject.toml and requirements.lock.

Use the [NetOps quickstart](../../docs/quickstart-1.0.md), [architecture](../../docs/architecture-1.0.md), [support boundaries](../../docs/verified-support.md) and [qualification procedure](../../docs/testing-1.0.md). Engine sources are in src; regression tests and their non-production support fixtures are in tests.

The Auditor store (`/var/lib/netops/auditor/store.sqlite`) uses the SQLite write-ahead log (WAL): the files `store.sqlite-wal` and `store.sqlite-shm` beside it, when present, belong to the store and are part of every copy or backup of it; the store must stay on a local file system (the default named volume). The stopped-instance backup of the whole state volume in the [quickstart](../../docs/quickstart-1.0.md#back-up-state) already includes them.

The Auditor evaluates FortiOS, ExtremeXOS and FortiADC snapshots. FortiOS and ExtremeXOS also support collection. FortiADC audits use exported text and its identity metadata. The MCP tools query the configured catalogue and stored findings. See [Auditor tools](docs/tools.md), [configuration](docs/configuration.md) and [collection channels](docs/channels.md).
