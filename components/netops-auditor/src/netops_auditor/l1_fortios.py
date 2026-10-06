from netops_core.fortios import (
    MAX_DEPTH, VDOM_SECTION, Attr, Node, ParseError, TruncatedError,
    _quote_state, logical_lines, parse, physical_lines, tokenize,
)
