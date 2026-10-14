# Fixtures captured on physical hardware (ExtremeXOS 33.7.1.6-patch1-11). Addresses are rewritten to documentation ranges (RFC 5737 / RFC 7042): private IPv4 -> 192.0.2.x, MAC -> 00:00:5e:00:53:xx, NTP pool host -> ntp.example.net, IPv6 all-ones mask -> 2001:db8:ffff::/128 form. Identities are generic: sysName, file names and device use the product line, sysLocation and the capturing account are neutral; serial numbers, SSH aliases and the SNMPv3 engine-id (from the documentation MAC) are placeholders.
GOLDEN_META = {'exos/33.7.1.6-patch1-11/X435-8P-4S/show-configuration/X435-8P-4S__normal-redacted-secrets': {'captured_utc': '2026-10-13T11:06:15Z',
                                                                                               'command': 'show '
                                                                                                          'configuration',
                                                                                               'device': 'X435-8P-4S',
                                                                                               'device_alias_ssh': 'x435-8p-4s',
                                                                                               'firmware': '33.7.1.6-patch1-11',
                                                                                               'length_bytes': 3625,
                                                                                               'model': 'X435-8P-4S',
                                                                                               'more_paging_observed': False,
                                                                                               'note': 'account '
                                                                                                       'and '
                                                                                                       'sshd2 '
                                                                                                       'lines '
                                                                                                       '(password '
                                                                                                       'hashes, '
                                                                                                       'public '
                                                                                                       'SSH '
                                                                                                       'keys) '
                                                                                                       'removed '
                                                                                                       'before '
                                                                                                       'storing.',
                                                                                               'serial': '0000Z-00001',
                                                                                               'sha256': 'f7bbbe5171b77a77cfacb25825f3738085be3d1142d007e96c2332d482fe398c',
                                                                                               'variant': 'normal-redacted-secrets'},
 'exos/33.7.1.6-patch1-11/X435-8P-4S/show-ports-key-information-detail/X435-8P-4S__normal-no-display-string': {'captured_utc': '2026-10-13T11:06:15Z',
                                                                                                               'command': 'show '
                                                                                                                          'ports '
                                                                                                                          '1 '
                                                                                                                          'information '
                                                                                                                          'detail',
                                                                                                               'device': 'X435-8P-4S',
                                                                                                               'device_alias_ssh': 'x435-8p-4s',
                                                                                                               'firmware': '33.7.1.6-patch1-11',
                                                                                                               'length_bytes': 2033,
                                                                                                               'model': 'X435-8P-4S',
                                                                                                               'more_paging_observed': False,
                                                                                                               'note': '',
                                                                                                               'serial': '0000Z-00001',
                                                                                                               'sha256': '0e305cd34c086b8fe50101e61c9076bc17458fc344c3d8ad7430f65aeebba8f8',
                                                                                                               'variant': 'normal-no-display-string'},
 'exos/33.7.1.6-patch1-11/X435-8P-4S/show-ports-key-vlan/X435-8P-4S__normal': {'captured_utc': '2026-10-13T11:06:15Z',
                                                                               'command': 'show '
                                                                                          'ports 1 '
                                                                                          'vlan',
                                                                               'device': 'X435-8P-4S',
                                                                               'device_alias_ssh': 'x435-8p-4s',
                                                                               'firmware': '33.7.1.6-patch1-11',
                                                                               'length_bytes': 159,
                                                                               'model': 'X435-8P-4S',
                                                                               'more_paging_observed': False,
                                                                               'note': '',
                                                                               'serial': '0000Z-00001',
                                                                               'sha256': 'd678f7e628d3c966c8f31c68f22958353f1693aa71b3d7865908da278feb4ec9',
                                                                               'variant': 'normal'},
 'exos/33.7.1.6-patch1-11/X435-8P-4S/show-ports-no-refresh/X435-8P-4S__normal': {'captured_utc': '2026-10-13T11:06:15Z',
                                                                                 'command': 'show '
                                                                                            'ports '
                                                                                            'no-refresh',
                                                                                 'device': 'X435-8P-4S',
                                                                                 'device_alias_ssh': 'x435-8p-4s',
                                                                                 'firmware': '33.7.1.6-patch1-11',
                                                                                 'length_bytes': 1712,
                                                                                 'model': 'X435-8P-4S',
                                                                                 'more_paging_observed': False,
                                                                                 'note': '',
                                                                                 'serial': '0000Z-00001',
                                                                                 'sha256': 'a341b2d8c2d8b97a7a46264bc2699dac22f38d0f627b4702e246fe9f6bbab297',
                                                                                 'variant': 'normal'},
 'exos/33.7.1.6-patch1-11/X435-8P-4S/show-session/X435-8P-4S__normal': {'captured_utc': '2026-10-13T11:06:15Z',
                                                                        'command': 'show session',
                                                                        'device': 'X435-8P-4S',
                                                                        'device_alias_ssh': 'x435-8p-4s',
                                                                        'firmware': '33.7.1.6-patch1-11',
                                                                        'length_bytes': 332,
                                                                        'model': 'X435-8P-4S',
                                                                        'more_paging_observed': False,
                                                                        'note': '',
                                                                        'serial': '0000Z-00001',
                                                                        'sha256': '74a61d134c7aafd645bf6b8335df6843e14ff7e0755290140650a49fa351573a',
                                                                        'variant': 'normal'},
 'exos/33.7.1.6-patch1-11/X435-8P-4S/show-switch/X435-8P-4S__normal': {'captured_utc': '2026-10-13T11:06:15Z',
                                                                       'command': 'show switch',
                                                                       'device': 'X435-8P-4S',
                                                                       'device_alias_ssh': 'x435-8p-4s',
                                                                       'firmware': '33.7.1.6-patch1-11',
                                                                       'length_bytes': 1177,
                                                                       'model': 'X435-8P-4S',
                                                                       'more_paging_observed': False,
                                                                       'note': '',
                                                                       'serial': '0000Z-00001',
                                                                       'sha256': '8783335ef337ffb6c971bff8b50ab9b08c05e319a293d5db44907764dffa6300',
                                                                       'variant': 'normal'},
 'exos/33.7.1.6-patch1-11/X435-8P-4S/show-upm-profile-name/X435-8P-4S__rejected-plain-name': {'captured_utc': '2026-10-13T11:06:15Z',
                                                                                              'command': 'show '
                                                                                                         'upm '
                                                                                                         'profile '
                                                                                                         'nosuchprofile',
                                                                                              'device': 'X435-8P-4S',
                                                                                              'device_alias_ssh': 'x435-8p-4s',
                                                                                              'firmware': '33.7.1.6-patch1-11',
                                                                                              'length_bytes': 88,
                                                                                              'model': 'X435-8P-4S',
                                                                                              'more_paging_observed': False,
                                                                                              'note': 'EXOS '
                                                                                                      'rejects '
                                                                                                      'even '
                                                                                                      'a '
                                                                                                      'syntactically '
                                                                                                      'valid '
                                                                                                      'profile '
                                                                                                      'name '
                                                                                                      'when '
                                                                                                      'the '
                                                                                                      'switch '
                                                                                                      'has '
                                                                                                      'no '
                                                                                                      'UPM '
                                                                                                      'profile; '
                                                                                                      'the '
                                                                                                      'capture '
                                                                                                      'was '
                                                                                                      'read-only '
                                                                                                      '(no '
                                                                                                      "'create "
                                                                                                      'upm '
                                                                                                      "profile'), "
                                                                                                      'so '
                                                                                                      'the '
                                                                                                      'successful '
                                                                                                      'branch '
                                                                                                      'was '
                                                                                                      'not '
                                                                                                      'captured.',
                                                                                              'serial': '0000Z-00001',
                                                                                              'sha256': '6c8b6d5e158e57f7ae0731db3676875f4433c477536a9254a1147b0b46d1babc',
                                                                                              'variant': 'rejected-plain-name'},
 'exos/33.7.1.6-patch1-11/X435-8P-4S/show-upm-profile-name/X435-8P-4S__rejected-safeguard-shaped-name': {'captured_utc': '2026-10-13T11:06:15Z',
                                                                                                         'command': 'show '
                                                                                                                    'upm '
                                                                                                                    'profile '
                                                                                                                    'netopsabcdefp',
                                                                                                         'device': 'X435-8P-4S',
                                                                                                         'device_alias_ssh': 'x435-8p-4s',
                                                                                                         'firmware': '33.7.1.6-patch1-11',
                                                                                                         'length_bytes': 88,
                                                                                                         'model': 'X435-8P-4S',
                                                                                                         'more_paging_observed': False,
                                                                                                         'note': 'same '
                                                                                                                 'as '
                                                                                                                 'above, '
                                                                                                                 'with '
                                                                                                                 'a '
                                                                                                                 'name '
                                                                                                                 'shaped '
                                                                                                                 'like '
                                                                                                                 'the '
                                                                                                                 'safeguard '
                                                                                                                 'profile '
                                                                                                                 'netopsXXXXXXp.',
                                                                                                         'serial': '0000Z-00001',
                                                                                                         'sha256': 'f2d747474827fc37d4dba9c2a01fe0d62744eb089016859b4b32a51b4e726699',
                                                                                                         'variant': 'rejected-safeguard-shaped-name'},
 'exos/33.7.1.6-patch1-11/X435-8P-4S/show-upm-profile/X435-8P-4S__empty': {'captured_utc': '2026-10-13T11:06:15Z',
                                                                           'command': 'show upm '
                                                                                      'profile',
                                                                           'device': 'X435-8P-4S',
                                                                           'device_alias_ssh': 'x435-8p-4s',
                                                                           'firmware': '33.7.1.6-patch1-11',
                                                                           'length_bytes': 495,
                                                                           'model': 'X435-8P-4S',
                                                                           'more_paging_observed': False,
                                                                           'note': '',
                                                                           'serial': '0000Z-00001',
                                                                           'sha256': '2019a18a5bc76d1552d24e00093f1129054ea8762f95b65bc8f0bc8a78b25251',
                                                                           'variant': 'empty'},
 'exos/33.7.1.6-patch1-11/X435-8P-4S/show-upm-timers/X435-8P-4S__empty': {'captured_utc': '2026-10-13T11:06:15Z',
                                                                          'command': 'show upm '
                                                                                     'timers',
                                                                          'device': 'X435-8P-4S',
                                                                          'device_alias_ssh': 'x435-8p-4s',
                                                                          'firmware': '33.7.1.6-patch1-11',
                                                                          'length_bytes': 605,
                                                                          'model': 'X435-8P-4S',
                                                                          'more_paging_observed': False,
                                                                          'note': '',
                                                                          'serial': '0000Z-00001',
                                                                          'sha256': '78e6e9674be37e68ba8cb8313c2687b08db87ea377ee64c6c5d1ab2dc1598510',
                                                                          'variant': 'empty'},
 'exos/33.7.1.6-patch1-11/X435-8P-4S/show-version/X435-8P-4S__normal': {'captured_utc': '2026-10-13T11:06:15Z',
                                                                        'command': 'show version',
                                                                        'device': 'X435-8P-4S',
                                                                        'device_alias_ssh': 'x435-8p-4s',
                                                                        'firmware': '33.7.1.6-patch1-11',
                                                                        'length_bytes': 407,
                                                                        'model': 'X435-8P-4S',
                                                                        'more_paging_observed': False,
                                                                        'note': '',
                                                                        'serial': '0000Z-00001',
                                                                        'sha256': 'a1346a06bbb87d9eaa8f8d5d9093ab4c262355d30a267b268eff74974d8b8f89',
                                                                        'variant': 'normal'},
 'exos/33.7.1.6-patch1-11/X435-8P-4S/show-vlan-key/X435-8P-4S__absent-alpha': {'captured_utc': '2026-10-13T11:06:15Z',
                                                                               'command': 'show '
                                                                                          'vlan '
                                                                                          'NoSuchVlan',
                                                                               'device': 'X435-8P-4S',
                                                                               'device_alias_ssh': 'x435-8p-4s',
                                                                               'firmware': '33.7.1.6-patch1-11',
                                                                               'length_bytes': 137,
                                                                               'model': 'X435-8P-4S',
                                                                               'more_paging_observed': False,
                                                                               'note': '',
                                                                               'serial': '0000Z-00001',
                                                                               'sha256': 'a3658c9fed7a59d463a6b24e5681c82a01191626cc0cf5f5849a51833f0915d9',
                                                                               'variant': 'absent-alpha'},
 'exos/33.7.1.6-patch1-11/X435-8P-4S/show-vlan-key/X435-8P-4S__absent-numeric': {'captured_utc': '2026-10-13T11:06:15Z',
                                                                                 'command': 'show '
                                                                                            'vlan '
                                                                                            '9999',
                                                                                 'device': 'X435-8P-4S',
                                                                                 'device_alias_ssh': 'x435-8p-4s',
                                                                                 'firmware': '33.7.1.6-patch1-11',
                                                                                 'length_bytes': 129,
                                                                                 'model': 'X435-8P-4S',
                                                                                 'more_paging_observed': False,
                                                                                 'note': 'captured '
                                                                                         'on the '
                                                                                         'X435-8P-4S '
                                                                                         'only; '
                                                                                         'the '
                                                                                         'error '
                                                                                         'message '
                                                                                         'is '
                                                                                         'generic '
                                                                                         'to '
                                                                                         'firmware '
                                                                                         '33.7.1.6-patch1-11 '
                                                                                         'and '
                                                                                         'applies '
                                                                                         'to the '
                                                                                         'X440-G2-12p-10G4 '
                                                                                         'on the '
                                                                                         'same '
                                                                                         'firmware.',
                                                                                 'serial': '0000Z-00001',
                                                                                 'sha256': 'a5a1e4858f05b59d44090c22e7bbead89775efed018e36023dfab38638dda7b3',
                                                                                 'variant': 'absent-numeric'},
 'exos/33.7.1.6-patch1-11/X435-8P-4S/show-vlan-key/X435-8P-4S__normal-existing': {'captured_utc': '2026-10-13T11:06:15Z',
                                                                                  'command': 'show '
                                                                                             'vlan '
                                                                                             'Default',
                                                                                  'device': 'X435-8P-4S',
                                                                                  'device_alias_ssh': 'x435-8p-4s',
                                                                                  'firmware': '33.7.1.6-patch1-11',
                                                                                  'length_bytes': 1978,
                                                                                  'model': 'X435-8P-4S',
                                                                                  'more_paging_observed': False,
                                                                                  'note': '',
                                                                                  'serial': '0000Z-00001',
                                                                                  'sha256': 'b7ad23aeee355116c734c944d728ffb1c808994da161121df141a518d0fb05e2',
                                                                                  'variant': 'normal-existing'},
 'exos/33.7.1.6-patch1-11/X440G2-12p-10G4/show-configuration/X440-G2-12p-10G4__normal-redacted-secrets': {'captured_utc': '2026-10-13T11:06:15Z',
                                                                                                          'command': 'show '
                                                                                                                     'configuration',
                                                                                                          'device': 'X440-G2-12p-10G4',
                                                                                                          'device_alias_ssh': 'x440-g2-12p-10g4',
                                                                                                          'firmware': '33.7.1.6-patch1-11',
                                                                                                          'length_bytes': 4627,
                                                                                                          'model': 'X440G2-12p-10G4',
                                                                                                          'more_paging_observed': False,
                                                                                                          'note': 'account '
                                                                                                                  'and '
                                                                                                                  'sshd2 '
                                                                                                                  'lines '
                                                                                                                  '(password '
                                                                                                                  'hashes, '
                                                                                                                  'public '
                                                                                                                  'SSH '
                                                                                                                  'keys) '
                                                                                                                  'removed '
                                                                                                                  'before '
                                                                                                                  'storing.',
                                                                                                          'serial': '0000Z-00002',
                                                                                                          'sha256': '17c967280fe393d99c5b0d8707db28a152aec1ea05a9f8093c81c5c69d6fd23a',
                                                                                                          'variant': 'normal-redacted-secrets'},
 'exos/33.7.1.6-patch1-11/X440G2-12p-10G4/show-ports-key-information-detail/X440-G2-12p-10G4__normal-no-display-string': {'captured_utc': '2026-10-13T11:06:15Z',
                                                                                                                          'command': 'show '
                                                                                                                                     'ports '
                                                                                                                                     '1 '
                                                                                                                                     'information '
                                                                                                                                     'detail',
                                                                                                                          'device': 'X440-G2-12p-10G4',
                                                                                                                          'device_alias_ssh': 'x440-g2-12p-10g4',
                                                                                                                          'firmware': '33.7.1.6-patch1-11',
                                                                                                                          'length_bytes': 2264,
                                                                                                                          'model': 'X440G2-12p-10G4',
                                                                                                                          'more_paging_observed': False,
                                                                                                                          'note': '',
                                                                                                                          'serial': '0000Z-00002',
                                                                                                                          'sha256': '7993921838f776b9f81a1d764b2c1261ec96d3365cff714c15d81abc3259d5f9',
                                                                                                                          'variant': 'normal-no-display-string'},
 'exos/33.7.1.6-patch1-11/X440G2-12p-10G4/show-ports-key-vlan/X440-G2-12p-10G4__normal': {'captured_utc': '2026-10-13T11:06:15Z',
                                                                                          'command': 'show '
                                                                                                     'ports '
                                                                                                     '1 '
                                                                                                     'vlan',
                                                                                          'device': 'X440-G2-12p-10G4',
                                                                                          'device_alias_ssh': 'x440-g2-12p-10g4',
                                                                                          'firmware': '33.7.1.6-patch1-11',
                                                                                          'length_bytes': 159,
                                                                                          'model': 'X440G2-12p-10G4',
                                                                                          'more_paging_observed': False,
                                                                                          'note': '',
                                                                                          'serial': '0000Z-00002',
                                                                                          'sha256': 'd678f7e628d3c966c8f31c68f22958353f1693aa71b3d7865908da278feb4ec9',
                                                                                          'variant': 'normal'},
 'exos/33.7.1.6-patch1-11/X440G2-12p-10G4/show-ports-no-refresh/X440-G2-12p-10G4__normal': {'captured_utc': '2026-10-13T11:06:15Z',
                                                                                            'command': 'show '
                                                                                                       'ports '
                                                                                                       'no-refresh',
                                                                                            'device': 'X440-G2-12p-10G4',
                                                                                            'device_alias_ssh': 'x440-g2-12p-10g4',
                                                                                            'firmware': '33.7.1.6-patch1-11',
                                                                                            'length_bytes': 2068,
                                                                                            'model': 'X440G2-12p-10G4',
                                                                                            'more_paging_observed': False,
                                                                                            'note': '',
                                                                                            'serial': '0000Z-00002',
                                                                                            'sha256': '765dbbdc376ca7fdb05f798f98437f1206d82edb34204b18d5149f8a23aefb2b',
                                                                                            'variant': 'normal'},
 'exos/33.7.1.6-patch1-11/X440G2-12p-10G4/show-session/X440-G2-12p-10G4__normal': {'captured_utc': '2026-10-13T11:06:15Z',
                                                                                   'command': 'show '
                                                                                              'session',
                                                                                   'device': 'X440-G2-12p-10G4',
                                                                                   'device_alias_ssh': 'x440-g2-12p-10g4',
                                                                                   'firmware': '33.7.1.6-patch1-11',
                                                                                   'length_bytes': 332,
                                                                                   'model': 'X440G2-12p-10G4',
                                                                                   'more_paging_observed': False,
                                                                                   'note': '',
                                                                                   'serial': '0000Z-00002',
                                                                                   'sha256': 'df3a38efbe226c7c45c24da9818a5baa9d5149bdfe4d178334cc75d66d21fdeb',
                                                                                   'variant': 'normal'},
 'exos/33.7.1.6-patch1-11/X440G2-12p-10G4/show-switch/X440-G2-12p-10G4__normal': {'captured_utc': '2026-10-13T11:06:15Z',
                                                                                  'command': 'show '
                                                                                             'switch',
                                                                                  'device': 'X440-G2-12p-10G4',
                                                                                  'device_alias_ssh': 'x440-g2-12p-10g4',
                                                                                  'firmware': '33.7.1.6-patch1-11',
                                                                                  'length_bytes': 1154,
                                                                                  'model': 'X440G2-12p-10G4',
                                                                                  'more_paging_observed': False,
                                                                                  'note': '',
                                                                                  'serial': '0000Z-00002',
                                                                                  'sha256': 'd75add44035dd7e2b2f52dfb0601d5a31437d81a40e51278e4d3bfca2cd53313',
                                                                                  'variant': 'normal'},
 'exos/33.7.1.6-patch1-11/X440G2-12p-10G4/show-upm-profile-name/X440-G2-12p-10G4__rejected-safeguard-shaped-name': {'captured_utc': '2026-10-13T11:06:15Z',
                                                                                                                    'command': 'show '
                                                                                                                               'upm '
                                                                                                                               'profile '
                                                                                                                               'netopsabcdefp',
                                                                                                                    'device': 'X440-G2-12p-10G4',
                                                                                                                    'device_alias_ssh': 'x440-g2-12p-10g4',
                                                                                                                    'firmware': '33.7.1.6-patch1-11',
                                                                                                                    'length_bytes': 88,
                                                                                                                    'model': 'X440G2-12p-10G4',
                                                                                                                    'more_paging_observed': False,
                                                                                                                    'note': 'same '
                                                                                                                            'as '
                                                                                                                            'on '
                                                                                                                            'the '
                                                                                                                            'X435-8P-4S '
                                                                                                                            '- '
                                                                                                                            'same '
                                                                                                                            'firmware.',
                                                                                                                    'serial': '0000Z-00002',
                                                                                                                    'sha256': 'f2d747474827fc37d4dba9c2a01fe0d62744eb089016859b4b32a51b4e726699',
                                                                                                                    'variant': 'rejected-safeguard-shaped-name'},
 'exos/33.7.1.6-patch1-11/X440G2-12p-10G4/show-upm-profile/X440-G2-12p-10G4__empty': {'captured_utc': '2026-10-13T11:06:15Z',
                                                                                      'command': 'show '
                                                                                                 'upm '
                                                                                                 'profile',
                                                                                      'device': 'X440-G2-12p-10G4',
                                                                                      'device_alias_ssh': 'x440-g2-12p-10g4',
                                                                                      'firmware': '33.7.1.6-patch1-11',
                                                                                      'length_bytes': 570,
                                                                                      'model': 'X440G2-12p-10G4',
                                                                                      'more_paging_observed': False,
                                                                                      'note': '',
                                                                                      'serial': '0000Z-00002',
                                                                                      'sha256': '419b80e6b88f313bb72750f090aa6bff5a65d659080b912ab1c19cf7f2df7370',
                                                                                      'variant': 'empty'},
 'exos/33.7.1.6-patch1-11/X440G2-12p-10G4/show-upm-timers/X440-G2-12p-10G4__empty': {'captured_utc': '2026-10-13T11:06:15Z',
                                                                                     'command': 'show '
                                                                                                'upm '
                                                                                                'timers',
                                                                                     'device': 'X440-G2-12p-10G4',
                                                                                     'device_alias_ssh': 'x440-g2-12p-10g4',
                                                                                     'firmware': '33.7.1.6-patch1-11',
                                                                                     'length_bytes': 605,
                                                                                     'model': 'X440G2-12p-10G4',
                                                                                     'more_paging_observed': False,
                                                                                     'note': '',
                                                                                     'serial': '0000Z-00002',
                                                                                     'sha256': '78e6e9674be37e68ba8cb8313c2687b08db87ea377ee64c6c5d1ab2dc1598510',
                                                                                     'variant': 'empty'},
 'exos/33.7.1.6-patch1-11/X440G2-12p-10G4/show-version/X440-G2-12p-10G4__normal': {'captured_utc': '2026-10-13T11:06:15Z',
                                                                                   'command': 'show '
                                                                                              'version',
                                                                                   'device': 'X440-G2-12p-10G4',
                                                                                   'device_alias_ssh': 'x440-g2-12p-10g4',
                                                                                   'firmware': '33.7.1.6-patch1-11',
                                                                                   'length_bytes': 462,
                                                                                   'model': 'X440G2-12p-10G4',
                                                                                   'more_paging_observed': False,
                                                                                   'note': '',
                                                                                   'serial': '0000Z-00002',
                                                                                   'sha256': '0cde0c34915085144da29b8b497d223af833f25c96f2f132b89bcfc538c5294a',
                                                                                   'variant': 'normal'},
 'exos/33.7.1.6-patch1-11/X440G2-12p-10G4/show-vlan-key/X440-G2-12p-10G4__absent-alpha': {'captured_utc': '2026-10-13T11:06:15Z',
                                                                                          'command': 'show '
                                                                                                     'vlan '
                                                                                                     'NoSuchVlan',
                                                                                          'device': 'X440-G2-12p-10G4',
                                                                                          'device_alias_ssh': 'x440-g2-12p-10g4',
                                                                                          'firmware': '33.7.1.6-patch1-11',
                                                                                          'length_bytes': 137,
                                                                                          'model': 'X440G2-12p-10G4',
                                                                                          'more_paging_observed': False,
                                                                                          'note': '',
                                                                                          'serial': '0000Z-00002',
                                                                                          'sha256': 'a3658c9fed7a59d463a6b24e5681c82a01191626cc0cf5f5849a51833f0915d9',
                                                                                          'variant': 'absent-alpha'},
 'exos/33.7.1.6-patch1-11/X440G2-12p-10G4/show-vlan-key/X440-G2-12p-10G4__normal-existing': {'captured_utc': '2026-10-13T11:06:15Z',
                                                                                             'command': 'show '
                                                                                                        'vlan '
                                                                                                        'Default',
                                                                                             'device': 'X440-G2-12p-10G4',
                                                                                             'device_alias_ssh': 'x440-g2-12p-10g4',
                                                                                             'firmware': '33.7.1.6-patch1-11',
                                                                                             'length_bytes': 2025,
                                                                                             'model': 'X440G2-12p-10G4',
                                                                                             'more_paging_observed': False,
                                                                                             'note': '',
                                                                                             'serial': '0000Z-00002',
                                                                                             'sha256': '66ce3b0ac8875d33322c37f94955220748fc2de3cd0173dbe107bc5a63475287',
                                                                                             'variant': 'normal-existing'},
 'exos/33.7.1.6-patch1-11/X440G2-12p-10G4/show-vlan-key/X440-G2-12p-10G4__normal-existing-zero-active-ports': {'captured_utc': '2026-10-13T11:06:15Z',
                                                                                                               'command': 'show '
                                                                                                                          'vlan '
                                                                                                                          'Mgmt',
                                                                                                               'device': 'X440-G2-12p-10G4',
                                                                                                               'device_alias_ssh': 'x440-g2-12p-10g4',
                                                                                                               'firmware': '33.7.1.6-patch1-11',
                                                                                                               'length_bytes': 820,
                                                                                                               'model': 'X440G2-12p-10G4',
                                                                                                               'more_paging_observed': False,
                                                                                                               'note': 'VLAN '
                                                                                                                       'Mgmt '
                                                                                                                       'has '
                                                                                                                       '0 '
                                                                                                                       'active '
                                                                                                                       'ports '
                                                                                                                       '- '
                                                                                                                       'the '
                                                                                                                       'Ports '
                                                                                                                       'section '
                                                                                                                       'differs '
                                                                                                                       'from '
                                                                                                                       'the '
                                                                                                                       'one '
                                                                                                                       'of '
                                                                                                                       'Default.',
                                                                                                               'serial': '0000Z-00002',
                                                                                                               'sha256': '548a8f70988336a744fbc4145f1925508d3aa186b0290e9ac2278fa364efc1c9',
                                                                                                               'variant': 'normal-existing-zero-active-ports'}}
