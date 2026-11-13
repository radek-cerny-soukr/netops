"""Import G2 route/VLAN evidence with the standard capture anonymizer.

FG80 raw show-config was not retained: its VLAN fixture is an explicit
reconstruction from independent CLI fields, with a synthetic nested IPv6 node.
No network access and no product parser is used to generate expectations.
"""
import json
from pathlib import Path
import re
import tempfile

from . import add_capture

ROOT = Path(__file__).resolve().parents[4]
DEST = ROOT / 'components/netops-helper/tests/fixtures/real/scenarios'
REF = ROOT / 'ref/forti-cli'


def main():
    captures = []
    for filename, index in [('fg80/replay-input.json', None), ('replay-input.json', 0)]:
        source = json.loads((REF / filename).read_text())
        if index is not None:
            source = source[index]
        capture = next(c for c in source['captures'] if c['table'] == 'route')
        capture['expected'].update(status='ok', unparsed_count=0)
        # Store the manually chosen prefixes before normalization: the default
        # anonymizer maps hosts after three /24s and does not preserve host bits.
        # The focused replay normalizes these independent inputs with ipaddress.
        capture['expected_prefix_inputs'] = [r.pop('prefix') for r in capture['expected']['records']]
        captures.append(capture)

    raw60 = next(json.loads(line) for line in (REF / 'cli.jsonl').read_text().splitlines()
                 if json.loads(line).get('command') == 'show system interface')
    text60 = re.sub(r'(?m)^FortiGate-60F [#$] ?', '', raw60['stdout']).replace('\r\n', '\n')
    # Distinct documentation /27s keep VLAN networks disjoint. Source addresses
    # below are replaced by interface name before importing the CLI evidence.
    manual60 = [
        ('_default', 1, '192.0.2.1'), ('quarantine', 4093, '192.0.2.33'),
        ('voice', 4091, None), ('video', 4090, None), ('rspan', 4092, '192.0.2.65'),
        ('onboarding', 4089, None), ('nac_segment', 4088, '192.0.2.97'),
        ('PVE-MGMT', 100, '192.0.2.129'), ('224E-p11-open', 211, '192.0.2.161'),
    ]
    manual80 = [
        ('GUEST', 30, 'internal1', '198.51.100.1'),
        ('IoT', 20, 'internal1', '198.51.100.33'),
        ('KAMERY', 40, 'internal1', '198.51.100.65'),
        ('LAB', 50, 'internal1', '198.51.100.97'),
        ('ESXI-MGMT', 60, 'internal2', '198.51.100.129'),
        ('FGT801-WAN-A', 801, 'internal3', '198.51.100.161'),
        ('FGT801-WAN-B', 802, 'internal3', '198.51.100.193'),
    ]
    # Preserve the independent CLI structure while removing site addressing.
    addresses = {name: address for name, _, address in manual60 if address}
    interface = None
    lines = []
    for line in text60.splitlines():
        edit = re.fullmatch(r'    edit "([^"\n]+)"', line)
        if edit:
            interface = edit[1]
        if interface in addresses and re.match(r'        set ip ', line):
            line = f'        set ip {addresses[interface]} 255.255.255.224'
        lines.append(line)
    text60 = '\n'.join(lines) + '\n'
    # Each field is manually transcribed from get system interface / G2 CLI
    # comparison, not copied from the current parser's records.
    text80 = ['config system interface', '    edit "wan1"', '        config ipv6',
              '            set ip6-mode dhcp', '            set ip6-allowaccess ping',
              '        end', '    next']
    for name, vlan, parent, address in manual80:
        text80 += [f'    edit "{name}"', f'        set vlanid {vlan}',
                   f'        set interface "{parent}"', f'        set ip {address} 255.255.255.224', '    next']
    text80.append('end')
    for device, text, records in [
        ('fg60', text60, [dict(name=n, vlan_id=v, interface='fortilink', ip=a,
                             prefix_length=27 if a else None) for n, v, a in manual60]),
        ('fg80-reconstructed', '\n'.join(text80)+'\n',
         [dict(name=n, vlan_id=v, interface=p, ip=a, prefix_length=27) for n, v, p, a in manual80]),
    ]:
        captures.append(dict(platform='fortinet', firmware='FortiOS 7.6.8' if device == 'fg60' else 'FortiOS 8.0.2',
                             query='interface_vlan_ids', table='vlan', command='show system interface', rc=0,
                             evidence=device, stdout=text,
                             expected=dict(status='ok', record_count=len(records), unparsed_count=0, records=records)))
    with tempfile.TemporaryDirectory(dir=ROOT / '.git') as directory:
        folder = Path(directory)
        for i, capture in enumerate(captures):
            capture['file'] = f'raw-{i}.txt'
            (folder / capture['file']).write_text(capture.pop('stdout'))
        source = dict(scenario='fortios-g2-route-vlan',
                      expected_source='Manual independent G2 CLI transcription: FG80 32 routes, FG60 13 routes, FG60 9 VLANs. FG80 7 VLANs reconstructed from get system interface; nested IPv6 node synthetic because raw show config was not retained. All IPs anonymized with add_capture. Independent expected_prefix_inputs are normalized using ipaddress in test_fortios_g2, because default anonymization does not preserve CIDR host bits after three subnets.',
                      captures=captures)
        manifest = folder / 'manifest.json'
        manifest.write_text(json.dumps(source))
        add_capture.import_scenario(manifest, DEST / 'fortios-g2-route-vlan.json')


if __name__ == '__main__':
    main()
