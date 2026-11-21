# FortiADC G34 captures

VM220 ran FortiADC-KVM 7.6.7 build0676. On 2026-11-18 the lab returned these answers to the read-only `show load-balance virtual-server [LAB_VS_SMTP]`, `show load-balance real-server`, `show load-balance pool [LAB_POOL_SMTP]` and `diagnose server-load-balance vs_stat vdom root vs <VS>` commands. `absent-vs.txt` records the diagnostic for a deliberately absent VS. The before and after files record changes made through the Admin preview, apply and undo flow in task netops-20261118-503.

The `Anonymizer` from `components/netops-helper/tests/support/anonymize_fixture.py` mapped addresses to documentation ranges and checked the results for residual identifiers. Trailing whitespace was removed from the prompt and ordinary lines. Embedded pager bytes and the lab's test object names were kept.
