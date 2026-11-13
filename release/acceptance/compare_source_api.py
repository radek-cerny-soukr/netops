#!/usr/bin/env python3
"""Offline catalogue/SwitchTable comparison through the real upgrade verifier.

Read both source trees in memory. Execute their real public catalogue producers,
server pagination/hash function and SwitchTable type declaration. Other tool
definitions and compared responses are held constant: this is a scoped source
regression check, not a live MCP upgrade or a replacement for upgrade-check.sh.
Requires the predecessor commit in the local Git object database; no network,
engine transport, credentials or runtime dependencies are used.
"""
import argparse
import ast
from contextlib import contextmanager
import hashlib
import importlib.abc
import importlib.util
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import tarfile
from typing import Any, Literal, get_args


ROOT = Path(__file__).resolve().parents[2]
PREDECESSOR = 'd803ddeaa34dd0470572c7327ddbbc6294649c2f'
SOURCE_DIRS = ('src', 'components/netops-helper/src', 'components/netops-core/src')
SERVER = 'components/netops-helper/src/netops_helper/server.py'


class SourceTree(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    def __init__(self, root, ref):
        self.root, self.ref, self.files = root, ref, None
        if ref:
            archive = subprocess.check_output(['git', '-C', str(root), 'archive', ref, *SOURCE_DIRS])
            with tarfile.open(fileobj=io.BytesIO(archive)) as tree:
                self.files = {m.name: tree.extractfile(m).read().decode()
                              for m in tree.getmembers() if m.isfile() and m.name.endswith('.py')}

    def read(self, path):
        if self.files is not None:
            return self.files.get(path)
        file = self.root / path
        return file.read_text() if file.is_file() else None

    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] not in ('netops', 'netops_helper', 'netops_core'):
            return None
        for source in SOURCE_DIRS:
            for suffix, package in (('/__init__.py', True), ('.py', False)):
                name = source + '/' + fullname.replace('.', '/') + suffix
                if self.read(name) is not None:
                    spec = importlib.util.spec_from_loader(fullname, self, is_package=package)
                    spec.loader_state = name
                    return spec
        return None

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        path = module.__spec__.loader_state
        module.__file__ = str(self.root / path)
        exec(compile(self.read(path), module.__file__, 'exec'), module.__dict__)


@contextmanager
def isolated(tree):
    prefixes = ('netops', 'netops_helper', 'netops_core')
    belongs = lambda name: name.split('.')[0] in prefixes
    saved = {name: module for name, module in sys.modules.items() if belongs(name)}
    for name in saved:
        del sys.modules[name]
    sys.meta_path.insert(0, tree)
    try:
        yield
    finally:
        sys.meta_path.remove(tree)
        for name in list(sys.modules):
            if belongs(name):
                del sys.modules[name]
        sys.modules.update(saved)


def public_contract(tree):
    with isolated(tree):
        from netops_helper.read_policy import public_query_catalog, public_query_metadata, normalize_platform
        from netops_helper.tables import FIELDS

        # Execute these exact server declarations without loading transport/MCP.
        parsed = ast.parse(tree.read(SERVER))
        declarations = [node for node in parsed.body
                        if isinstance(node, ast.FunctionDef) and node.name == '_query_catalog_payload'
                        or isinstance(node, ast.Assign) and any(isinstance(target, ast.Name)
                                                               and target.id == 'SwitchTable'
                                                               for target in node.targets)]
        if len(declarations) != 2:
            raise ValueError('expected the real server catalogue function and SwitchTable declaration')
        namespace = dict(Any=Any, Literal=Literal, SWITCH_TABLE_FIELDS=FIELDS,
                         public_query_catalog=public_query_catalog, public_query_metadata=public_query_metadata,
                         normalize_platform=normalize_platform, re=re, json=json, hashlib=hashlib)
        exec(compile(ast.Module(body=declarations, type_ignores=[]), SERVER, 'exec'), namespace)
        enum = list(get_args(namespace['SwitchTable']))
        pages, offset = [], 0
        while True:
            page = namespace['_query_catalog_payload'](offset=offset, limit=100)
            pages.append({'reply': {'result': {'structuredContent': page, 'isError': False}}})
            offset = page['next_offset']
            if offset is None:
                break
        return enum, pages


def capture(tree):
    enum, pages = public_contract(tree)
    # Only this genuine schema field differs in the reviewed definition change.
    tools = [{'name': 'switch_read', 'inputSchema': {'type': 'object', 'properties': {
        'table': {'type': 'string', 'enum': enum}}}}]
    calls = {'tools/list': {'reply': {'result': {'tools': tools}}},
             'read_query_catalog_pages': pages}
    for name in ('helper_status', 'target_scope', 'audit_status', 'admin_status', 'ssh_read_not_enrolled'):
        calls[name] = {'reply': {'result': {'structuredContent': {'offline_constant': name},
                                         'isError': name == 'ssh_read_not_enrolled'}}}
    return {'calls': calls}


def compare(root, from_ref, to_ref=None):
    spec = importlib.util.spec_from_file_location('source_api_verify', root / 'release/acceptance/verify_state.py')
    verify = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verify)
    items, problems, _ = verify.load_api_changes(root / 'release/acceptance/api-changes-1.0.7-1.0.8.json',
                                                {'FROM_VERSION': '1.0.7', 'TO_VERSION': '1.0.8'})
    before, after = capture(SourceTree(root, from_ref)), capture(SourceTree(root, to_ref))
    tools_ok, tools_detail, responses_ok, responses_detail = verify.compare_mcp(
        before, after, '1.0.7', '1.0.8', items, problems)
    return {'from_ref': from_ref, 'to_ref': to_ref or 'working-tree',
            'scope': 'source catalogue pages/hash and switch_read table enum; unrelated API held constant',
            'definitions': {'result': 'PASS' if tools_ok else 'FAIL', 'detail': tools_detail},
            'responses': {'result': 'PASS' if responses_ok else 'FAIL', 'detail': responses_detail}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--from-ref', default=PREDECESSOR)
    parser.add_argument('--to-ref', help='default: current working tree')
    args = parser.parse_args()
    result = compare(args.root.resolve(), args.from_ref, args.to_ref)
    print(json.dumps(result, indent=2))
    return int(any(result[k]['result'] != 'PASS' for k in ('definitions', 'responses')))


if __name__ == '__main__':
    raise SystemExit(main())
