import hashlib,json,os,resource,subprocess,sys,time
from unittest import mock
from netops_helper import engine,configuration
from test_h1_config_block import enrolled,STATUS

ROWS=int(sys.argv[1])
AUTH=enrolled()
KEY='192.0.2.20 ssh-ed25519 cmVwbGFjZS1tZS1ob3N0LWtleS1tYXRlcmlhbC1B'
POpen=subprocess.Popen
PRODUCER="""
import sys
n=int(sys.argv[1]);variant=int(sys.argv[2])
out=sys.stdout.buffer
out.write(b'#config-version=synthetic\\nconfig firewall address\\n')
for i in range(n):
    secret=('new' if variant and i==n-1 else 'old')+'-SyntheticPrivateValue-'+'x'*80
    status='down' if variant and i==n-1 else 'up'
    out.write((' edit "private-'+str(i)+'"\\n set subnet 192.0.2.1 255.255.255.255\\n set comment "'+secret+'"\\n set status '+status+'\\n next\\n').encode())
out.write(b'end\\n');out.flush()
"""
reads=0;raw_bytes=0;variant=0
def launch(argv,**kwargs):
    global reads
    command=argv[-1]
    if command=='get system status':
        code='import sys;sys.stdout.buffer.write('+repr(STATUS.encode())+')'
        return POpen([sys.executable,'-B','-c',code],**kwargs)
    assert command=='show'
    reads+=1
    return POpen([sys.executable,'-B','-c',PRODUCER,str(ROWS),str(variant)],**kwargs)
native=engine.core_ssh.run_command
def counted(*args,**kwargs):
    consumer=kwargs.get('stdout_consumer')
    if consumer:
        def accept(data):
            global raw_bytes
            raw_bytes+=len(data);consumer(data)
        kwargs['stdout_consumer']=accept
    return native(*args,**kwargs)
start=time.monotonic()
with mock.patch.object(engine,'record'),mock.patch.object(engine,'_resolve_target_ipv4',return_value=['192.0.2.20']),mock.patch.object(engine,'host_key_line',return_value=KEY),mock.patch.object(engine.core_ssh.subprocess,'Popen',side_effect=launch),mock.patch.object(engine.core_ssh,'run_command',side_effect=counted):
    left=engine.config_read(AUTH,'fortios','all',include_all=True)
    variant=1
    right=engine.config_read(AUTH,'fortios','all',include_all=True)
    diff=engine.config_diff(AUTH,'fortios',left['snapshot_id'],right['snapshot_id'])
    assert not diff['identical'] and diff['secrets_changed_count']==1
    assert '-    set status up' in diff['untrusted_device_output']
    assert '+    set status down' in diff['untrusted_device_output']
    digest=hashlib.sha256();page=left;offsets=0
    while True:
        digest.update(page['untrusted_device_output'].encode());offsets+=1
        if page['next_offset'] is None:break
        page=engine.config_read(AUTH,'fortios','all',include_all=True,snapshot_id=left['snapshot_id'],offset=page['next_offset'])
    assert digest.hexdigest()==left['snapshot_sha256']
    assert reads==2
    assert 'SyntheticPrivateValue' not in json.dumps(diff)+repr(configuration._SNAPSHOTS)
seconds=time.monotonic()-start
retained=sum(s.memory_bytes if hasattr(s,'memory_bytes') else len(s.text.encode()) for s in configuration._SNAPSHOTS.values())
public=left['total_bytes']+right['total_bytes']
rss=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024
print(json.dumps({'rows':ROWS,'raw_bytes_two_captures':raw_bytes,'public_snapshot_bytes':public,'retained_snapshot_bytes':retained,'maxrss_bytes':rss,'seconds':round(seconds,3),'read_pages':offsets,'device_show_count':reads,'rss_bound_pass':rss<=2*retained+64*1024*1024,'public_only_rss_bound_pass':rss<=2*public+64*1024*1024}))
assert seconds<=600 and rss<=2*retained+64*1024*1024
