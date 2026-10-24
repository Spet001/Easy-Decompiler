import Long from './long.js';
import JSONex from './JSONex.js';

function _new_evars(issue) {
    let evars = {};
    evars.arch = issue.arch;
    evars.archbits = issue.bits;
    evars.honor = {
        assembly: true,
        blocks: false,
        casts: true,
        offsets: false,
        paddr: false,
        pseudo: false,
        xrefs: false,
    };
    evars.extra = {
        allfuncs: false,
        ascodeline: false,
        ascomment: false,
        debug: true,
        file: 'testsuite',
        highlights: false,
        offset: Long.UZERO,
        slow: true,
        theme: 'default',
        annotation: false,
    };
    return evars;
}

function _fixup_old_graph(graph) {
    graph[0].blocks.forEach((block) => {
        block.ops.forEach((instr) => {
            instr.comment = instr.comment ? atob(instr.comment) : undefined;
        });
    });
    return graph;
}

function _new_data(issue) {
    if (!issue.arch) {
        throw new Error('missing architecture in JSON.');
    }
    let bits = issue.archbits || issue.bits || 32;
    if (bits) {

        bits = parseInt(bits.toString());
    }
    var testdata = {
        arch: issue.arch,
        bits: bits,
        graph: issue.agj ? _fixup_old_graph(issue.agj) : (issue.graph || []),
        xrefs: {
            symbols: issue.isj || [],
            strings: issue.Csj || issue.izj || [],
            functions: issue.aflj || [],
            classes: issue.icj || [],
            arguments: issue.afvj || {
                "stack": [],
                "reg": []
            }
        },
        argdb: issue.afcfj
    };
    testdata.xrefs.arguments.stack = testdata.xrefs.arguments.stack || [];
    testdata.xrefs.arguments.reg = testdata.xrefs.arguments.reg || [];
    return testdata;
}

export default function(filename) {
    const issue = JSONex.parse(unit.raw);
    this.data = _new_data(issue);
    this.evars = _new_evars(this.data);
}
