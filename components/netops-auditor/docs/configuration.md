# Auditor configuration inside NetOps

Configure the stopped instance with `netops configure auditor`. JSON requires `tenant` and `catalog` (`fortios` or `exos`); `inventory` and `vault` are an optional pair. The adapter owns the private store and role environment. Selecting another tenant/catalog preserves imported data.

Use the [current operator workflow](../../../docs/quickstart-1.0.md#auditor-operator-workflows), [inventory](inventory.md), [shared vault schema](../../netops-core/docs/vault.md) and [collector boundaries](channels.md). MCP exposes read-only store/catalog queries, described with their accepted argument values in [Auditor tools](tools.md); it does not collect configurations or contact devices. An invalid tool argument, such as an unknown `severity` or `group_by` value, is refused with the generic `Role operation failed; no automatic retry` without naming the argument. No standalone MCP process or separate package is installed in NetOps 1.0.
