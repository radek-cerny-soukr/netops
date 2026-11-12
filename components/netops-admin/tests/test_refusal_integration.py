import json
from dataclasses import replace

import pytest
from fake_fortios import FakeFortiOS
from test_execute import make_runtime, request
from netops_admin import execute, cli, mcp_server
from netops_admin.errors import Rejected


@pytest.mark.parametrize('case,code,message', [
    ('blocked', 'device_blocked', 'the device is blocked (investigate, operation none); a person must investigate and unblock it'),
    ('notification', 'notification_pending', 'the notification of operation %(change)s was not delivered; run notify-retry, or a person unblocks the device after checking the notification channel'),
    ('running', 'operation_unfinished', 'an unfinished operation exists on this device; run recover first'),
    ('reused', 'request_id_reused', execute.REUSED_REQUEST),
])
@pytest.mark.parametrize('method', ['apply', 'preview'])
def test_actual_refusals(tmp_path, case, code, message, method):
    runtime = make_runtime(tmp_path, FakeFortiOS())
    change = None
    if case == 'blocked':
        runtime.store.block('lab', None, 'investigate')
    elif case == 'notification':
        # a real finished operation whose notification failed stays in the journal as undelivered
        runtime.notifier = lambda record: 'failed'
        change = execute.apply(runtime, 'lab', request(key='first', request_id='req-first-123'))['change_id']
        assert runtime.store.operation(change)['notification'] == 'failed'
    elif case == 'running':
        # a real unfinished operation record in the journal
        runtime.store.save({'change_id': 'a' * 32, 'request_id': 'req-running-1', 'device': 'lab',
                            'status': 'running', 'created_at_epoch': 1.0})
        assert [record['change_id'] for record in runtime.store.running('lab')] == ['a' * 32]
    else:
        execute.apply(runtime, 'lab', request())
    message = message % {'change': change}
    req = request(key='different') if case == 'reused' else request(key='second', request_id='req-second-123')
    if method == 'preview':
        result = execute.preview(runtime, 'lab', req)
        assert result['reasons'] == [message]
        assert result['reason_codes'] == [code]
    else:
        with pytest.raises(Rejected) as caught:
            execute.apply(runtime, 'lab', req)
        assert caught.value.reasons == [message]
        assert caught.value.reason_codes == [code]
        result = mcp_server.rejected(caught.value)
        assert result['reasons'] == [message] and result['reason_codes'] == [code]


@pytest.mark.parametrize('budget,limit,message', [
    ('rejected_hour', 'rejections_per_hour', 'the budget of rejected requests for this hour is exhausted'),
    ('journal_records', 'journal_records', 'the journal holds its maximum number of operations; archive it before new changes'),
    ('device_hour', 'changes_per_device_per_hour', 'the budget of changes on this device for this hour is exhausted'),
    ('global_day', 'changes_per_day', 'the budget of changes for this day is exhausted'),
])
@pytest.mark.parametrize('method', ['apply', 'preview'])
def test_actual_budget_refusals(tmp_path, budget, limit, message, method):
    runtime = make_runtime(tmp_path, FakeFortiOS())
    runtime.config = replace(runtime.config, limits=dict(runtime.config.limits, **{limit: 0}))
    if method == 'preview':
        result = execute.preview(runtime, 'lab', request())
        reasons, codes, details = result['reasons'], result['reason_codes'], result['reason_details']
    else:
        with pytest.raises(Rejected) as caught:
            execute.apply(runtime, 'lab', request())
        reasons, codes, details = caught.value.reasons, caught.value.reason_codes, caught.value.reason_details
    assert reasons == [message]
    assert codes == ['budget_exhausted']
    assert details == [{'code': 'budget_exhausted', 'budget': budget}]


def test_cli_apply_preserves_refusal(tmp_path, monkeypatch, capsys):
    from netops_admin import config
    runtime = make_runtime(tmp_path, FakeFortiOS())
    runtime.store.block('lab', None, 'investigate')
    monkeypatch.setattr(config, 'load_config', lambda *args: runtime.config)
    monkeypatch.setattr(cli, 'build_runtime', lambda *args, **kwargs: runtime)
    from conftest import request_bytes
    path = tmp_path / 'request.json'
    path.write_bytes(request_bytes())
    assert cli.main(['apply', '--config', 'unused', '--device', 'lab', '--request', str(path)]) == cli.EXIT_REJECTED
    result = json.loads(capsys.readouterr().out)
    assert result['reason_codes'] == ['device_blocked']
    assert result['reasons'] == ['the device is blocked (investigate, operation none); a person must investigate and unblock it']


def test_enrollment_and_undo_codes(tmp_path):
    from netops_admin import enrollment
    device = FakeFortiOS()
    runtime = make_runtime(tmp_path, device)
    record = execute.apply(runtime, 'lab', request())
    execute.undo(runtime, record['change_id'], 'restore')
    with pytest.raises(Rejected) as caught:
        execute.undo(runtime, record['change_id'], 'different reason')
    assert caught.value.reasons == [execute.UNDO_DONE]
    assert caught.value.reason_codes == ['undo_already_done']
    runtime.store.enrollment = lambda name: None
    result = execute.preview(runtime, 'lab', request(key='another', request_id='req-another-123'))
    assert result['reason_codes'] == ['enrollment_required']
    assert result['reasons'] == ['a successful enroll self-test is required for this device, build and configuration']
    with pytest.raises(Rejected) as caught:
        enrollment.require(runtime, runtime.config.devices['lab'], 'accounts', 'firmware')
    assert caught.value.reason_codes == ['enrollment_required']


def test_unreadable_refusal_count_code(tmp_path):
    runtime = make_runtime(tmp_path, FakeFortiOS())
    from netops_admin.state import REJECTIONS_FILE
    (runtime.store.root / REJECTIONS_FILE).write_text('invalid')
    with pytest.raises(Rejected) as caught:
        execute.apply(runtime, 'lab', request())
    assert caught.value.reason_codes == ['state_unreadable']
    assert caught.value.reasons == ['the count of refused requests (%s) cannot be read; a person must check it' % REJECTIONS_FILE]


def test_reason_details_is_present_in_every_preview_outcome(tmp_path):
    runtime = make_runtime(tmp_path, FakeFortiOS())
    assert execute.preview(runtime, 'lab', request())['reason_details'] == []
    runtime.store.enrollment = lambda name: None
    missing = execute.preview(runtime, 'lab', request(key='another', request_id='req-another-123'))
    assert missing['result'] == 'rejected' and missing['reason_details'] == []
    runtime.store.block('lab', None, 'investigate')
    assert execute.preview(runtime, 'lab', request())['reason_details'] == []
