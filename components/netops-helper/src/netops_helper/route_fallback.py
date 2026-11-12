"""IOS route lookup fallback using an authorized whole-table read."""
from . import tables


def lookup(result, address, read_table):
    if result['status'] != 'empty':
        return result
    table = read_table()
    table['sources'] = result['sources'] + table['sources']
    table['source'] = 'longest_prefix_from_table'
    table['records'] = tables.longest_prefix(table['records'], address)
    if table['status'] in ('ok', 'empty'):
        if not table['records']:
            table['status'] = 'empty'
    return table
