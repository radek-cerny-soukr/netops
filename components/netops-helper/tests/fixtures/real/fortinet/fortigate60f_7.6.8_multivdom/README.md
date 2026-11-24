# FortiGate-60F 7.6.8 build 3744 in multi-VDOM mode (measurement verification, 2026-11-14)

Interactive SSH transcripts of the lab FortiGate-60F while it was temporarily in `vdom-mode multi-vdom`
with the VDOMs `root` (index 0) and `nops172-vd1` (index 3). The file name is the capture number of the
measurement, the account and the VDOM context:

- `A` super_admin (prompt `#`), `G` super_admin_readonly (prompt `$`);
- `noctx` right after the login, `root` / `vd1` inside `config vdom` / `edit <vdom>`.

`transcripts.json` maps each capture name to its transcript (one JSON file, so that the transcripts are not
taken for single-command captures by the classification baseline and are still covered by the fixture
privacy check). Each transcript starts with `[login]`; every prompt line carries the command sent after it,
followed by the device answer. `514-A-root-intfshow` and `523-A-vd1-intfshow` were filtered on the device side to the
`edit "<name>"` and `set vdom "<vdom>"` lines of `show system interface` (no other configuration was kept).
`94-A-extra` holds the routing database, the session filter `vd <index>`, `diagnose sys session stat` and
`get system interface` read inside `nops172-vd1` and `root`.

Preparation from the measurement evidence (`evidence-1.0.9/109-11/mereni-172/60f-cli/*.out`):

1. carriage returns removed (`tr -d '\r'`, the PTY `\r\r\n` line ends; the Helper drops every `\r` too);
2. `tests/support/anonymize_fixture.py --check --serial <serial>` (IPv4 to RFC 5737, MAC to RFC 7042, host
   name, serial); the mapping was not stored;
3. the anonymiser widened the gap after an IPv4 address that became shorter (`ip: 203.0.113.251   255.255.255.0`);
   that gap was set back to the one space the device prints between address and mask.

VDOM names, VDOM indexes, the tunnel name `netops-172-p1`, counters and the model and build are real.

## `context-197.json` (verification)

Excerpts of the CLI evidence of the multi-VDOM live check (verification, `ref/60f-cli/33–35`, FortiGate-60F 7.6.8 build
3744, 2026-11-14), same transcript format; carriage returns removed, the `get system status` steps (serial) and the
`config system accprofile` steps of 34 left out, nothing else changed:

- `197-33-diag-noconfig`: a global profile without `cli-config` (prompt `$`): `config vdom` answers
  `Unknown action 0` / `Command fail. Return code -1`;
- `197-34-gdiag-global`: a super_admin session: `config global` answers nothing and the prompt becomes
  `FortiGate-60F (global) # ` (FortiOS prints no context marker there);
- `197-35-diag-root`: the global diag profile with `cli-config` (prompt `$`): `edit root` prints `current vf=root:0`,
  `diagnose sys session stat` answers there and `get system performance status` is refused with `-61`.

## `status-197.json` (verification)

`197-21-A-noctx-status-one-vdom`: `get system status` of a super_admin right after `set vdom-mode multi-vdom`, before
any other VDOM was created (verification `ref/scenare-197-vdom/60f-cli/21-status-multivdom.out`, FortiGate-60F 7.6.8
build 3744, 2026-11-14): `Virtual domain configuration: multiple`, `Current virtual domain: root`,
`Virtual domains status: 1 in NAT mode, 0 in TP mode`. The capture had no command echo; the transcript adds the
`get system status` prompt line and the closing prompt as in `511-A-noctx-status`. Carriage returns removed; the
serial and the host name replaced by the values the anonymiser gave the same 60F in `transcripts.json`
(`SSS00SSS0001SSSS`, `host01`); the status holds no address or MAC. Nothing else changed.

## `vdom-admin-197.json` (verification)

The per-VDOM administrator of the multi-VDOM live check (verification, `ref/scenare-197-vdom/60f-cli/44-vd1acct-exec-run2.out`,
FortiGate-60F 7.6.8 build 3744, 2026-11-14): account `netops-197-ro-vd1` with `set vdom "nops172-vd1"` and a VDOM
profile with `cli-get`/`cli-show`/`cli-diagnose`/`cli-config` enabled, logged in through `nv1971`, an interface of
`nops172-vd1`. Each capture was one SSH exec call; it is written here in the same transcript format (one `[login]`
per call, the exec answers after the prompt `FortiGate-60F $ ` of each command):

- `197-44-vd1acct-status`: `get system status` names `Current virtual domain: nops172-vd1`, `Virtual domain configuration: multiple`;
- `197-44-vd1acct-config-vdom`: `config vdom`, `edit nops172-vd1` and `end` answer `Unknown action 0`, the
  `get system arp` between them answers the (empty) table of the login VDOM;
- `197-44-vd1acct-arp`: `get system arp` right after the login answers the table header (a global administrator
  gets `-61` there, `503-A-noctx-arp`);
- `197-44-vd1acct-intfshow`: `show system interface` lists only the interfaces of `nops172-vd1`;
- `197-44-vd1acct-physical`: `get system interface physical` lists the physical ports of every VDOM, with the
  addresses of `root` ports.

Preparation: the answers were cut from the exec captures (no carriage returns in them), anonymised  with
`tests/support/anonymize_fixture.py --check --serial <serial>` (serial, host name, IPv4 to RFC 5737; the mapping was not
stored), and the gap the anonymiser widened after a shortened IPv4 address was set back to one space. VDOM, interface
and description names, SNMP indexes and the model and build are real.
