# FortiGate-60F, FortiOS 7.6.8 build3744

The verification readings are from `fixture-reader` over pinned SSH. The change and cleanup commands used `fixture-operator`. See CLI measurement (private measurement record, not published) for the command sequence and section hashes. The `mac-delete-referenced.txt` fixture is the write account's response to the rejected delete.

The readback fixtures use the repository's `components/netops-helper/tests/support/anonymize_fixture.py --check`. The interface configuration retains the section markers and IPv4 address only. The hostname and IP and MAC identifiers are anonymized, and UUIDs are mapped consistently to documentation values. The addresses from RFC 5737 used to create the test objects were retained.
