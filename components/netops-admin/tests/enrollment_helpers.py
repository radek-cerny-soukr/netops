from netops_admin import enrollment, engine, execute


def certify(runtime, target, name):
    device = runtime.config.devices[name]
    try:
        text = target.snapshot()
        firmware = engine.adapter_for(device.platform).load(text, device.firmware).firmware
        accounts = execute._adapter(device.platform).accounts_check(target, device, text)
    except Exception:
        return runtime
    runtime.store.save_enrollment(name, {
        "protocol": enrollment.PROTOCOL,
        "binding": enrollment.binding(device, accounts, firmware, runtime.config),
        "firmware": firmware,
        "change_id": "0" * 32,
    })
    return runtime
