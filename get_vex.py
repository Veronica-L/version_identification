import angr

_p = angr.Project('dnsdomainname',load_options={'auto_load_libs': False})
cfg = _p.analyses.CFGFast()
function_cfg = cfg.functions[0x8049700].graph
for cfg_node in function_cfg.nodes():
    irsb = _p.factory.block(cfg_node.addr).vex
    print(irsb)