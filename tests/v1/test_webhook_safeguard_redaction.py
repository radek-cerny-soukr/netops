from unittest import TestCase

from netops_admin import fortios
from netops_helper import configuration as c, config_fortios

TOKEN = "tk0000000000000000000000000042"


def render(raw, chunk):
    stream = c.StreamRedactor((), 'all', policy=config_fortios.policy_for(('FortiGate-VM64', '8.0.2', '0251')))
    data = raw.encode()
    for start in range(0, len(data), chunk):
        stream.feed(data[start:start + chunk])
    content, _hidden, _count = stream.finish()
    return content.page(0, content.total)[0]


class WebhookSafeguardRedaction(TestCase):
    def test_rendered_safeguard_action_hides_the_token(self):
        request = {"method": "put", "uri": "192.0.2.1/api/v2/cmdb/firewall/policy/7", "body": '{"comments":"old"}'}
        lines = fortios.render_webhook_safeguard("0123456789abcdef", request, "443", TOKEN, "2026-11-01 12:03:00")
        shown = ("config system automation-action\n    edit \"netops-sg-0123456789ab-a\"\n"
                 "        set action-type webhook\n        set uri \"192.0.2.1/api/v2/cmdb/firewall/policy/7\"\n"
                 "        config http-headers\n            edit 1\n                set key \"Authorization\"\n"
                 "                set value \"Bearer %s\"\n            next\n        end\n    next\nend\n" % TOKEN)
        for raw in ("\n".join(lines) + "\n", shown):
            for chunk in (1, 7, 65536):
                with self.subTest(chunk=chunk, indented=raw is shown):
                    output = render(raw, chunk)
                    self.assertNotIn(TOKEN, output)
                    self.assertIn("Authorization", output)
