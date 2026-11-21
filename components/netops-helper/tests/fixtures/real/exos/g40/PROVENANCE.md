# G40 EXOS fixtures

Captured 2026-11-20 through pinned OpenSSH using existing accounts, with no session or switch configuration changes.

- `vm-*` comes from d-exos, EXOS-VM 33.6.1.14, using netops-ro.
- `x440-*` comes from lab X440G2-12p-10G4, 33.7.1.6 patch1-11, using the existing ai-login SSH key.
- `log-empty` is the complete empty memory-window reply from d-exos.
- `log-port` and `log-nvram` are excerpts from X440 memory and d-exos NVRAM respectively. Their footer counts were adjusted to the excerpts.
- `log-audit` uses an actual d-exos AAA.LogSsh prefix with a synthetic positional credential in its body. Its count reflects the one selected record.

All files passed through `tests/support/anonymize_fixture.py` without saving a mapping. Whitespace at the end of lines was trimmed. Contacts, inline PSU serials and the VM serial were explicitly replaced. The capture program's automatic vault masking affected some ordinary letter sequences, which were restored for the selected fixtures before anonymization. Test-side mutations of the captures exercise short, paged, inconsistent and unauthorized replies.
