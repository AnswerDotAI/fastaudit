import sys

_LXML_WRITERS = {'lxml.etree._ElementTree.write', 'lxml.etree._ElementTree.write_c14n', 'lxml.etree._XSLTResultTree.write_output',
    'lxml.etree.xmlfile', 'lxml.etree.xmlfile.__enter__'}

def lxml_monitor(caller, callee, fn, code, off, data, calls):
    # These native methods can write without Python open audit events.
    if callee.startswith('lxml.') and callee not in _LXML_WRITERS: return sys.monitoring.DISABLE

