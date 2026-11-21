# Cisco Catalyst 9800 fixtures

Published Cisco CLI output. Prompt and trailing whitespace removed. MAC and IP addresses and selected host names anonymized with `tests/support/anonymize_fixture.py`. The global AP user name was redacted separately. No WLAN configuration or credentials were captured.

| File | Release or document | Source | Notes |
|---|---|---|---|
| version.out | C9800 Command Reference, sample releases generally unspecified | [Cisco](https://www.cisco.com/c/en/us/td/docs/wireless/controller/9800/command-reference/b_wireless_cr/show-commands.html) | IOS XE 17.3.5b. Only the show version block from the diagnostic transcript. |
| aps.out | C9800 Command Reference, sample releases generally unspecified | [Cisco](https://www.cisco.com/c/en/us/td/docs/wireless/controller/9800/command-reference/b_wireless_cr/show-commands.html) |  |
| clients.out | IOS XE 17.15.x | [Cisco](https://www.cisco.com/c/en/us/td/docs/wireless/controller/9800/17-15/config-guide/b_wl_17_15_cg/m_enabling_ap_console.html) |  |
| clients_alt.out | C9800 Command Reference, sample releases generally unspecified | [Cisco](https://www.cisco.com/c/en/us/td/docs/wireless/controller/9800/command-reference/b_wireless_cr/show-commands.html) |  |
| client_detail.out | IOS XE 17.15.x | [Cisco](https://www.cisco.com/c/en/us/td/docs/wireless/controller/9800/17-15/config-guide/b_wl_17_15_cg/m_enabling_ap_console.html) | Cisco excerpt ends with ellipses and does not include VLAN and RSSI. |
| client_stats.out | IOS XE 17.15.x | [Cisco](https://www.cisco.com/c/en/us/td/docs/wireless/controller/9800/17-15/config-guide/b_wl_17_15_cg/m_enabling_ap_console.html) |  |
| radio_5.out | C9800 Command Reference, sample releases generally unspecified | [Cisco](https://www.cisco.com/c/en/us/td/docs/wireless/controller/9800/command-reference/b_wireless_cr/show-commands.html) |  |
| radio_24.out | IOS XE 16.10.x, PDF table transcribed | [Cisco](https://www.cisco.com/c/en/us/td/docs/wireless/controller/9800/config-guide/b_wl_16_10_cg/b_wl_16_10_cg_chapter_01101110.pdf) |  |
| ap_load.out | C9800 Command Reference, sample releases generally unspecified | [Cisco](https://www.cisco.com/c/en/us/td/docs/wireless/controller/9800/command-reference/b_wireless_cr/show-commands.html) |  |
| wlans.out | C9800 Configuration Model, release unspecified | [Cisco](https://www.cisco.com/c/en/us/td/docs/wireless/controller/9800/config-guide/newconfigmodel/b_catalyst-9800-configuration-model/m_validating_configuration.html) |  |
| ap_tags.out | C9800 Configuration Model, release unspecified | [Cisco](https://www.cisco.com/c/en/us/td/docs/wireless/controller/9800/config-guide/newconfigmodel/b_catalyst-9800-configuration-model/m_validating_configuration.html) |  |
| policy_profiles.out | C9800 IRCM Configuration Guide, release unspecified | [Cisco](https://www.cisco.com/c/en/us/td/docs/wireless/controller/9800/config-guide/ConfiguringIRCM/b-configuring-inter-release-controller-mobility-in-wireless-deployments-supporting-aireos-and-catalyst-9800-controllers/m-troubleshooting-ircm-configuration.html) | Cisco shows 5 of the 12 announced profiles. |
| client_deletes.out | C9800 Command Reference, sample releases generally unspecified | [Cisco](https://www.cisco.com/c/en/us/td/docs/wireless/controller/9800/command-reference/b_wireless_cr/show-commands.html) |  |
| exclusions.out | C9800 Command Reference, sample releases generally unspecified | [Cisco](https://www.cisco.com/c/en/us/td/docs/wireless/controller/9800/command-reference/b_wireless_cr/show-commands.html) |  |
| rogue_aps.out | C9800-L IOS XE 17.12.1 | [Cisco](https://www.cisco.com/c/en/us/support/docs/wireless/catalyst-9800-series-wireless-controllers/221688-identify-and-locate-a-rogue-ap-client-on.html) | Excerpt. The printed total remains unchanged. |
| redundancy.out | C9800-CL IOS XE 17.9.2 | [Cisco](https://www.cisco.com/c/en/us/support/docs/wireless/catalyst-9800-series-wireless-controllers/220277-configure-high-availability-sso-on-catal.html) |  |
| chassis_rmi.out | C9800-CL IOS XE 17.9.2 | [Cisco](https://www.cisco.com/c/en/us/support/docs/wireless/catalyst-9800-series-wireless-controllers/220277-configure-high-availability-sso-on-catal.html) |  |
| ap_tag_detail.out | C9800 Configuration Model, release unspecified | [Cisco](https://www.cisco.com/c/en/us/support/docs/wireless/catalyst-9800-series-wireless-controllers/213911-understand-catalyst-9800-wireless-contro.html) |  |
| aps_extended.out | IOS XE 17.4 deployment guide | [Cisco](https://www.cisco.com/c/dam/en/us/td/docs/wireless/controller/9800/17-4/deployment-guide/c9800-ha-sso-deployment-guide-rel-17-4.pdf) | Screenshot transcribed with the values, headers and order from the controller display. |
| clients_paired.out | IOS XE 17.4 deployment guide | [Cisco](https://www.cisco.com/c/dam/en/us/td/docs/wireless/controller/9800/17-4/deployment-guide/c9800-ha-sso-deployment-guide-rel-17-4.pdf) | Same AP/client pair as aps_extended.out. |
| clients_exclusions.out | IOS XE 17.9.x | [Cisco](https://www.cisco.com/c/en/us/td/docs/wireless/controller/9800/17-9/config-guide/b_wl_17_9_cg/m_fast_transition_ewlc.html) |  |
| ap_joins.out | Catalyst 9800 field notice, sample version unspecified | [Cisco](https://www.cisco.com/c/en/us/support/docs/field-notices/724/fn72424.html) |  |
| ap_joins_not_joined.out | IOS XE 17.3.x | [Cisco](https://www.cisco.com/c/en/us/td/docs/wireless/controller/9800/17-3/config-guide/b_wl_17_3_cg/m_ap_convert-autonomousaps_cg.pdf) | Cisco redacted both MACs. Screenshot layout transcribed. |
| radio_5_extended.out | C9800 IRCM guide, sample version unspecified | [Cisco](https://www.cisco.com/c/en/us/td/docs/wireless/controller/9800/config-guide/ConfiguringIRCM/b-configuring-inter-release-controller-mobility-in-wireless-deployments-supporting-aireos-and-catalyst-9800-controllers/m-troubleshooting-ircm-configuration.html) |  |
| client_detail_rf.out | C9800-CL IOS XE 17.9.3 | [Cisco](https://www.cisco.com/c/en/us/support/docs/wireless/catalyst-9166-series-access-points/220526-configure-and-verify-wi-fi-6e-band-opera.html) | Pixel 6a example. Gaps marked by Cisco, client session ID redacted. |
