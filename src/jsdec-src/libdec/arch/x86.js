import Base from '../core/base.js';
import ObjC from '../core/objc.js';
import Variable from '../core/variable.js';
import Extra from '../core/extra.js';
import Syscalls from '../db/syscalls.js';
import Long from '../long.js';

var _return_regs_bits = {
    'al': 8,
    'ax': 16,
    'eax': 32,
    'rax': 64,
};

var _x86_x64_registers = [
    'rax', 'eax', 'ax', 'al', 'ah',
    'rbx', 'ebx', 'bx', 'bl', 'bh',
    'rcx', 'ecx', 'cx', 'cl', 'ch',
    'rdx', 'edx', 'dx', 'dl', 'dh',
    'rsi', 'esi', 'si', 'sil',
    'rdi', 'edi', 'di', 'dil',
    'rbp', 'ebp', 'bp', 'bpl',
    'rsp', 'esp', 'sp', 'spl',
    'r8', 'r8d', 'r8w', 'r8b',
    'r9', 'r9d', 'r9w', 'r9b',
    'r10', 'r10d', 'r10w', 'r10b',
    'r11', 'r11d', 'r11w', 'r11b',
    'r12', 'r12d', 'r12w', 'r12b',
    'r13', 'r13d', 'r13w', 'r13b',
    'r14', 'r14d', 'r14w', 'r14b',
    'r15', 'r15d', 'r15w', 'r15b'
];

var _REGEX_STACK_REG = /^[re]?sp$/;
var _FP_STATUS_REG = 'fp_status';
var _FP_STACK = 'fp_stack';

var _is_stack_reg = function(name) {
    name = (name || "").replace(/([re]?sp).+/, "$1");
    return _REGEX_STACK_REG.test(name);
};

var _is_xmm = function(op) {
    return op.token && op.token.startsWith('xmm');
};

var _value_at = function(address) {
    if (rizin && address) {
        try {

            var bytes = Global().evars.archbits > 32 ? 8 : 4;
            var p = JSON.parse(rizin.command('pxj ' + bytes + ' @ 0x' + address.toString(16)).trim()).reverse().map(function(x) {
                x = x.toString(16);
                return x.length > 1 ? x : '0' + x;
            }).join('');
            return Long.from(p, true, 16);
        } catch (e) {}
    }
    return null;
};

var _REGEX_FRAME_REG = /^[re]?bp$/;

var _is_frame_reg = function(name) {
    return name && _REGEX_FRAME_REG.test(name);
};

var _is_func_arg = function(name, context) {
    return context.args.some(function(a) {
        return (a.name === name);
    });
};

var _is_local_var = function(name, context) {
    return context.vars.some(function(v) {
        return (v.name === name);
    });
};

var _is_stack_based_local_var = function(name, context) {
    return context.vars.some(function(v) {
        return (v.name === name) && (v.storage.type === "stack");
    });
};

var _get_var_offset = function(name, context) {

    var info;

    context.vars.forEach(function(v) {
        if (v.name == name) {
            info = v;
        }
    });

    return info && info.storage.type === "stack" ? info.storage.stack_off.low : undefined;
};

var _has_changed_return = function(reg, signed, context) {
    if (_return_regs_bits[reg] > context.returns.bits) {
        context.returns.bits = _return_regs_bits[reg];
        context.returns.signed = signed;
    }
};

var _is_last_instruction = function(instr, instructions) {
    return instructions.indexOf(instr) == (instructions.length - 1);
};

var _is_jumping_externally = function(instr, instructions) {
    var first_inst = instructions[0];
    var last_inst = instructions[instructions.length - 1];

    return instr.jump && (instr.jump.gt(last_inst) || instr.jump.lt(first_inst.location));
};

var _get_jump_instruction = function(instr, instructions) {
    var i, current = instructions.indexOf(instr);
    if (instr.jump && instr.location.eq(instr.jump)) {
        return instr;
    } else if (instr.jump && instr.location.lt(instr.jump)) {
        for (i = current + 1; i < instructions.length; i++) {
            if (instructions[i].location.eq(instr.jump)) {
                return instructions[i];
            }
        }
    } else if (instr.jump && instr.location.gt(instr.jump)) {
        for (i = 0; i < current; i++) {
            if (instructions[i].location.eq(instr.jump)) {
                return instructions[i];
            }
        }
    }
    return null;
};

var _find_bits = function(reg) {
    var elems = reg.match(/([re])?(.?[^dwhl]?)([dwhl])?/);

    var sz;

    if (elems[3] != undefined) {
        sz = {
            'h': 8,
            'l': 8,
            'w': 16,
            'd': 32
        }[elems[3]];
    } else if (elems[1] != undefined) {
        sz = {
            'e': 32,
            'r': 64
        }[elems[1]];
    } else {

        var avx_elems = elems[2].match(/([xyz])mm\d+/);

        if (avx_elems) {
            sz = {
                'x': 128,
                'y': 256,
                'z': 512
            }[avx_elems[1]];
        } else {
            sz = 16;
        }
    }

    return sz;
};

var _num_operands = function(p) {
    var operands = p.opd.slice();

    while (operands.length > 0) {
        if (operands.pop().token != undefined) {
            return operands.length + 1;
        }
    }

    return 0;
};

var _math_common = function(p, op, flags, context) {
    var lhand = p.opd[0];
    var rhand = p.opd[1];
    var signed = context.returns.signed;

    if (_is_stack_reg(lhand.token)) {
        return null;
    }

    _has_changed_return(lhand.token, signed, context);

    var lhand_arg = lhand.mem_access ? Variable.pointer(lhand.token, lhand.mem_access, signed) : lhand.token;
    var rhand_arg = rhand.mem_access ? Variable.pointer(rhand.token, rhand.mem_access, signed) : rhand.token;

    if (flags) {
        context.cond.a = lhand_arg;
        context.cond.b = '0';
    }

    return op(lhand_arg, lhand_arg, rhand_arg);
};

var _math_divide = function(p, signed, context) {
    var divisor = p.opd[0];
    var divisor_is_ptr = !!divisor.mem_access;
    var osize = divisor.mem_access || _find_bits(divisor.token);

    var dividend = {
        8: ['ax'],
        16: ['dx', 'ax'],
        32: ['edx', 'eax'],
        64: ['rdx', 'rax']
    }[osize];

    var remainder = {
        8: 'ah',
        16: 'dx',
        32: 'edx',
        64: 'rdx',
    }[osize];

    var quotient = {
        8: 'al',
        16: 'ax',
        32: 'eax',
        64: 'rax'
    }[osize];

    _has_changed_return(quotient, signed, context);

    var dividend_type = divisor_is_ptr ? 'pointer' : 'local';
    var arg_dividend = Variable[dividend_type](dividend.join(':'), osize, signed);
    var arg_quotient = Variable.local(quotient, osize, signed);
    var arg_remainder = Variable.local(remainder, osize, signed);

    return Base.composed([
        new Base.divide(arg_quotient, arg_dividend, divisor.token),
        new Base.module(arg_remainder, arg_dividend, divisor.token)
    ]);
};

var _math_multiply = function(p, signed, context) {
    var multiplier;
    var multiplicand;
    var destination;

    var osize = p.opd[0].mem_access || _find_bits(p.opd[0].token);

    switch (_num_operands(p)) {
        case 3:
            multiplier = p.opd[2];
            multiplicand = p.opd[1];
            destination = [p.opd[0].token];
            break;
        case 2:
            multiplier = p.opd[1];
            multiplicand = p.opd[0];
            destination = [p.opd[0].token];
            break;
        case 1:
            multiplier = p.opd[0];

            multiplicand = {
                token: {
                    8: 'al',
                    16: 'ax',
                    32: 'eax',
                    64: 'rax'
                }[osize]
            };

            destination = {
                8: ['ax'],
                16: ['dx', 'ax'],
                32: ['edx', 'eax'],
                64: ['rdx', 'rax']
            }[osize];

            break;
    }

    _has_changed_return(destination[destination.length - 1], signed, context);

    var multiplicand_type = multiplicand.mem_access ? 'pointer' : 'local';
    var multiplier_type = multiplier.mem_access ? 'pointer' : 'local';

    var arg_destination = Variable.local(destination.join(':'), osize * destination.length, signed, false, false);
    var arg_multiplicand = Variable[multiplicand_type](multiplicand.token, osize, signed);
    var arg_multiplier = Variable[multiplier_type](multiplier.token, osize, signed);

    return Base.multiply(arg_destination, arg_multiplicand, arg_multiplier);
};

var _bitwise_rotate = function(p, op, context) {
    var lhand = p.opd[0];
    var rhand = p.opd[1];
    var signed = context.returns.signed;

    _has_changed_return(lhand.token, signed, context);

    var lhand_arg = lhand.mem_access ? Variable.pointer(lhand.token, lhand.mem_access, signed) : lhand.token;
    var rhand_arg = rhand.mem_access ? Variable.pointer(rhand.token, rhand.mem_access, signed) : rhand.token;

    return op(lhand_arg, lhand_arg, rhand_arg, lhand.mem_access || _find_bits(lhand.token));
};

var _setcc_common = function(p, signed, condition, context) {
    var dest = p.opd[0];

    _has_changed_return(dest.token, signed, context);

    return Base.conditional_assign(dest.token, context.cond.a, context.cond.b, condition, '1', '0');
};

var _jcc_common = function(instr, context, type) {
    instr.conditional(context.cond.a, context.cond.b, type);

    return Base.nop();
};

var _cmov_common = function(instr, context, instrs, type) {
    instr.conditional(context.cond.a, context.cond.b, type);
    instr.jump = instrs[instrs.indexOf(instr) + 1].location;

    return _standard_mov(instr, context, instrs);
};

var _check_known_neg = function(x) {
    var arch_minus_one;
    switch (Global().evars.archbits) {
        case 64:
            arch_minus_one = '0xffffffffffffffff';
            break;
        case 32:
            arch_minus_one = '0xffffffff';
            break;
        case 16:
            arch_minus_one = '0xffff';
            break;
    }

    return (x === arch_minus_one ? '-1' : x);
};

var _guess_cdecl_nargs = function(instrs, context) {
    var nargs = 0;

    for (var i = (instrs.length - 1); i >= 0; i--) {
        var mnem = instrs[i].parsed.mnem;
        var opd1 = instrs[i].parsed.opd[0];

        if ((mnem === 'push') && !_is_frame_reg(opd1.token)) {
            nargs++;
        } else if (mnem === 'mov' && ((opd1.mem_access && _is_stack_reg(opd1.token)) || _is_stack_based_local_var(opd1.token, context))) {
            nargs++;
        } else if ((mnem === 'add') && _is_stack_reg(opd1.token)) {

            break;
        } else if (mnem === 'call') {

            break;
        }
    }

    return nargs;
};

var _guess_amd64_nargs = function(instrs, context) {
    var nargs = 0;

    return nargs;
};

var _populate_cdecl_call_args = function(instrs, nargs, context, instr) {
    var args = [];
    var argidx = 0;
    var arg;

    var varsname = context.vars.map(function(x) {
        return x.name;
    });

    for (var i = instrs.length - 1; i >= 0 && nargs > 0; i--) {
        arg = null;
        var mnem = instrs[i].parsed.mnem;
        var opd1 = instrs[i].parsed.opd[0];
        var opd2 = instrs[i].parsed.opd[1];
        if (instrs[i].jump || mnem == 'call') {
            break;
        }

        if (mnem === 'mov') {

            var offset, idx;

            idx = varsname.indexOf(opd1.token);
            if (idx >= 0) {
                offset = nargs;
            } else if (opd1.mem_access && _is_stack_reg(opd1.token)) {
                var deref = opd1.token.match(/[er]?[bs]p(?:\s+\+\s+(\d+))/);
                offset = deref ? (parseInt(deref[1]) / (Global().evars.archbits / 8)) : 0;
            } else if (_is_stack_based_local_var(opd1.token, context)) {
                offset = Math.abs(_get_var_offset(opd1.token, context)) / (Global().evars.archbits / 8);
            } else {

                continue;
            }
            arg = instrs[i].string ?
                Variable.string(instrs[i].string) :
                Variable[opd2.mem_access ? 'pointer' : 'local'](opd2.token, Extra.to.type(opd2.mem_access || context.arch_bits, false));

            instrs[i].valid = false;
            args[offset] = arg;
            nargs--;
        } else if (mnem === 'push') {

            if (instrs[i - 1] &&
                ['lea'].indexOf(instrs[i - 1].parsed.mnem) >= 0 &&
                opd1.token == instrs[i - 1].parsed.opd[0].token) {
                instrs[i - 1].valid = false;
                opd2 = instrs[i - 1].parsed.opd[1];
                arg = instrs[i - 1].string ?
                    Variable.string(instrs[i - 1].string) :
                    Variable[opd2.mem_access ? 'pointer' : 'local'](opd2.token, Extra.to.type(opd2.mem_access || context.arch_bits, false));
            } else {
                arg = instrs[i].string ?
                    Variable.string(instrs[i].string) :
                    Variable[opd1.mem_access ? 'pointer' : 'local'](opd1.token, Extra.to.type(opd1.mem_access || context.arch_bits, false));
            }
            instrs[i].valid = false;
            args[argidx++] = arg;
            nargs--;
        }
    }

    return args.filter(function(x) {
        return !!x;
    });
};

var _populate_generic_amd64_call_args = function(instrs, nargs, context, regs) {
    var _regs64 = regs['regs64'];
    var _regs32 = regs['regs32'];
    var _krnl64 = regs['krnl64'];
    var _krnl32 = regs['krnl32'];

    var amd64 = Array.prototype.concat(_regs64, _regs32, _krnl64, _krnl32);

    var args = _regs64.slice(0, nargs);
    var seen_regs = [];

    for (var i = (instrs.length - 1);
        (i >= 0) && (nargs > 0); i--) {
        if (instrs[i].jump || instrs[i].parsed.mnem == 'call') {
            break;
        }
        var opd1 = instrs[i].parsed.opd[0];
        var opd2 = instrs[i].parsed.opd[1];

        if (opd2.token && ['mov', 'xor', 'lea'].indexOf(instrs[i].parsed.mnem) >= 0) {
            var argidx = amd64.indexOf(opd1.token) % _regs64.length;
            var argvalue = opd2.token;
            var argsize = opd2.mem_access;
            var notseen = seen_regs.indexOf(opd2.token) < 0;
            if (notseen) {
                seen_regs.push(opd2.token);
                if (instrs[i].parsed.mnem == 'xor' && opd1.token == opd2.token) {
                    argvalue = '0';
                }
            } else {
                argvalue = opd1.token;
                argsize = opd1.mem_access;
            }

            if ((argidx > (-1)) && (typeof args[argidx] === 'string')) {

                var arg = instrs[i].string ?
                    Variable.string(instrs[i].string) :
                    Variable[opd2.mem_access ? 'pointer' : 'local'](argvalue, Extra.to.type(argsize || context.arch_bits, false));

                instrs[i].valid = !notseen;
                args[argidx] = arg;
                nargs--;
            }
        }
    }

    return args.filter(function(x) {
        return !!x;
    });
};

var _populate_systemv_amd64_call_args = function(instrs, nargs, context) {
    var regs = {
        regs64: [  'rdi',  'rsi',  'rdx',  'rcx',  'r8',  'r9'],
        regs32: [  'edi',  'esi',  'edx',  'ecx',  'r8d',  'r9d'],
        krnl64: [  null,  null,  null,  'r10'],
        krnl32: [  null,  null,  null,  'r10d'],
    };
    return _populate_generic_amd64_call_args(instrs, nargs, context, regs);
};

var _populate_ms_amd64_call_args = function(instrs, nargs, context) {
    var regs = {
        regs64: ['rcx', 'rdx', 'r8', 'r9'],
        regs32: ['ecx', 'edx'],
        krnl64: [],
        krnl32: [],
    };
    return _populate_generic_amd64_call_args(instrs, nargs, context, regs);
};

var _call_function = function(instr, context, instrs, is_pointer, cannot_return) {
    var call, start = instrs.indexOf(instr);
    var i, j;

    var returnval = undefined;

    var tailcall = false;

    if (_is_last_instruction(instr, instrs)) {
        tailcall = true;
    } else {

        for (i = (start + 1); i < instrs.length; i++) {
            var mnem = instrs[i].parsed.mnem;
            var dst = instrs[i].parsed.opd[0].token;
            var src = instrs[i].parsed.opd[1].token;

            var insn_uses_dst_as_src = (mnem.match(/pop|lea|c?mov\w*|set\w+/) == null);

            if (src in _return_regs_bits) {
                returnval = src;

                _has_changed_return(src, false, context);
                break;
            } else if (insn_uses_dst_as_src && (dst in _return_regs_bits)) {
                returnval = dst;

                _has_changed_return(dst, false, context);
                break;
            } else if (dst in _return_regs_bits) {

                break;
            } else if (mnem.match(/\b(call|i?div|i?mul|lods[bwdq]?|in(?:s[bwd]?)?)\b/)) {

                break;
            }
        }
    }

    var callsite = instr.parsed.opd[0];
    var callname = instr.symbol || callsite.token;
    var nargs, args = [];
    var callee = instr.callee;
    var marker = context.markers[instr.marker];
    if (_x86_x64_registers.indexOf(callname) >= 0 &&
        context.markers[instr.marker] &&
        context.markers[instr.marker][callname]) {
        marker[callname].instr.valid = false;
        callname = marker[callname].instr.parsed.opd[1].token;
    }

    if (ObjC.is(callname)) {
        var pargs, receiver, selector, pcounted = 0;
        if (!ObjC.is_class_method(callname)) {
            return ObjC.handle_others(callname, instr, context, instrs);
        } else {
            receiver = ObjC.receiver(callname);
            selector = ObjC.selector(callname);
            returnval = ObjC.returns(callname);
            pargs = ObjC.arguments(callname);
            var subslice = instrs.slice((start - 8) < 0 ? 0 : start - 8, start);
            args = [receiver, selector].map(function(reg) {
                for (var i = subslice.length - 1; i >= 0; i--) {
                    if (subslice[i].parsed.mnem == "call" || subslice[i].jump) {
                        break;
                    }
                    if (reg == subslice[i].parsed.opd[0].token && ["mov", "lea"].indexOf(subslice[i].parsed.mnem) >= 0) {

                        var opd2 = subslice[i].parsed.opd[1];
                        if (opd2.token.startsWith('str.') && !subslice[i].string) {
                            return opd2.token.substr(4);
                        } else if (opd2.token.startsWith('reloc.')) {
                            return opd2.token.substr(6);
                        }

                        if (subslice[i].symbol) {
                            return subslice[i].symbol;
                        } else if (subslice[i].string) {
                            return subslice[i].string;
                        } else if (subslice[i].klass) {
                            return subslice[i].klass;
                        }
                        if (marker && marker[opd2.token]) {

                            if (marker[opd2.token].instr.parsed.opd[1].token.startsWith('str.')) {
                                return marker[opd2.token].instr.parsed.opd[1].token.substr(4);
                            } else if (marker[opd2.token].instr.parsed.opd[1].token.startsWith('reloc.')) {
                                return marker[opd2.token].instr.parsed.opd[1].token.substr(6);
                            }
                            if (marker[opd2.token].instr.klass) {
                                return marker[opd2.token].instr.klass;
                            } else if (marker[opd2.token].instr.string) {
                                return marker[opd2.token].instr.string;
                            } else if (marker[opd2.token].instr.symbol) {
                                return marker[opd2.token].instr.symbol;
                            }
                            return marker[opd2.token].instr.parsed.opd[1].token;
                        }
                        return Variable[opd2.mem_access ? 'pointer' : 'local'](opd2.token, Extra.to.type(opd2.mem_access, false));
                    } else if (marker && marker[reg]) {
                        marker[reg].instr.valid = false;
                        if (marker[reg].instr.parsed.opd[1].token.startsWith('str.')) {
                            return marker[reg].instr.parsed.opd[1].token.substr(4);
                        } else if (marker[reg].instr.parsed.opd[1].token.startsWith('reloc.')) {
                            return marker[reg].instr.parsed.opd[1].token.substr(6);
                        }
                        if (marker[reg].instr.klass) {
                            return marker[reg].instr.klass;
                        } else if (marker[reg].instr.string) {
                            return marker[reg].instr.string;
                        } else if (marker[reg].instr.symbol) {
                            return marker[reg].instr.symbol;
                        }
                        return marker[reg].instr.parsed.opd[1].token;
                    }

                }
                return reg;
            });
            for (j = 0; j < pargs.length; j++) {

                for (i = subslice.length - 1; i >= 0; i--) {
                    if (subslice[i].parsed.mnem == "call" || subslice[i].jump) {
                        break;
                    }
                    if (pargs[j] == subslice[i].parsed.opd[0].token ||
                        pargs[j][0] == subslice[i].parsed.opd[0].token ||
                        pargs[j][1] == subslice[i].parsed.opd[0].token) {
                        if (["mov", "lea"].indexOf(subslice[i].parsed.mnem) >= 0) {
                            var opd2 = subslice[i].parsed.opd[1];
                            if (opd2.token.startsWith('str.') && !subslice[i].string) {
                                pargs[j] = opd2.token.substr(4);
                            } else {

                                pargs[j] = subslice[i].string ?
                                    Variable.string(subslice[i].string) :
                                    Variable[opd2.mem_access ? 'pointer' : 'local'](opd2.token, Extra.to.type(opd2.mem_access, false));
                            }
                            subslice[i].valid = false;
                        } else if (subslice[i].parsed.mnem == "xor" &&
                            subslice[i].parsed.opd[0].token == subslice[i].parsed.opd[1].token) {
                            subslice[i].valid = false;
                            pargs[j] = Variable.number(0);
                        }
                        pcounted++;
                        break;
                    }
                }
            }
            call = Base.objc_call(args[0], args[1], pargs.slice(0, pcounted).map(function(r) {
                if (Extra.is.array(r)) {
                    return r[r.length - 1];
                }
                return r;
            }));
            if (tailcall && _x86_x64_registers.indexOf(callsite.token) > (-1)) {

                return Base.return(call);
            } else if (returnval) {

                return Base.assign(returnval, call);
            }
        }
    } else if (callee && callee.calltype) {
        var guess_nargs = {
            'cdecl': _guess_cdecl_nargs,
            'amd64': _guess_amd64_nargs,
            'sysv': _guess_amd64_nargs,
            'ms': _guess_amd64_nargs
        }[callee.calltype] || (Global().evars.archbits === 64 ? _guess_amd64_nargs : _guess_cdecl_nargs);

        var populate_call_args = {
            'cdecl': _populate_cdecl_call_args,
            'amd64': _populate_systemv_amd64_call_args,
            'sysv': _populate_systemv_amd64_call_args,
            'ms': _populate_ms_amd64_call_args
        }[callee.calltype] || (Global().evars.archbits === 64 ? _populate_systemv_amd64_call_args : _populate_cdecl_call_args);

        nargs = callee.name.startsWith('sym.') || callname.startsWith('reloc.') || callname.startsWith('sub.') ?
            Extra.find.arguments_number(callee.name) :
            callee.nargs;

        if (nargs == (-1)) {
            nargs = guess_nargs(instrs.slice(0, start), context);
        }

        args = populate_call_args(instrs.slice(0, start), nargs, context, instr);
    } else {

        nargs = callname.startsWith('sym.') || callname.startsWith('reloc.') ?
            Extra.find.arguments_number(callname) : -1;

        if (nargs == -1) {
            nargs = _guess_cdecl_nargs(instrs.slice(0, start), context);
            callee = _populate_cdecl_call_args;
            if (nargs == -1) {
                nargs = _guess_amd64_nargs(instrs.slice(0, start), context);
                callee = _populate_systemv_amd64_call_args;
            }

            if (callee && nargs > -1) {
                args = callee(instrs.slice(0, start), nargs, context, instr);
            }
        } else {
            args = _populate_systemv_amd64_call_args(instrs.slice(0, start), nargs, context);
            if (args.length < 1 && nargs > 0) {
                _populate_cdecl_call_args(instrs.slice(0, start), nargs, context, instr);
            }
        }
    }

    if (callname.startsWith('0x') || (!callname.startsWith('imp.') && !callname.startsWith('sym.imp.') && !callname.startsWith('reloc.') && callsite.mem_access)) {
        callname = Variable.functionPointer(callname, callsite.mem_access, args);
    } else if (is_pointer || (!callsite.mem_access && _x86_x64_registers.indexOf(callname) > (-1))) {
        callname = Variable.functionPointer(callname, 0, args);
    }

    call = Base.call(callname, args);

    if (tailcall) {

        if (_x86_x64_registers.indexOf(callsite.token) > (-1)) {
            return Base.return(call);
        }

        return call;
    }

    if (returnval && !cannot_return) {
        return Base.assign(returnval, call);
    }
    return call;
};

var _standard_mov = function(instr, context, instructions) {
    var marker = _apply_marker_math(instr, context);
    if (marker) {
        return marker;
    }
    var dst = instr.parsed.opd[0];
    var src = instr.parsed.opd[1];
    var prev = instructions[instructions.indexOf(instr) - 1];

    _has_changed_return(dst.token, context.returns.signed, context);

    if (dst.mem_access) {
        return Base.write_memory(dst.token, instr.string ? Variable.string(instr.string) : src.token, dst.mem_access, true);
    } else if (src.mem_access) {
        if (src.token.startsWith('0x')) {
            var v = _value_at(Long.from(src.token, true, 16));
            instr.string = Global().xrefs.find_string(v);
            instr.symbol = Global().xrefs.find_symbol(v);
            instr.klass = Global().xrefs.find_class(_value_at(v)) || Global().xrefs.find_class(v);
        } else if (src.token == dst.token && prev.parsed.mnem == 'lea' && prev.parsed.opd[0].token == src.token) {
            prev.valid = false;
            return prev.code;
        }
        if (instr.string) {
            return Base.assign(dst.token, Variable.string(instr.string));
        } else if (instr.symbol) {
            return Base.assign(dst.token, instr.symbol);
        }
        return Base.read_memory(src.token, dst.token, src.mem_access, true);
    } else if (_is_stack_reg(dst.token) || _is_frame_reg(dst.token)) {
        return null;
    } else {
        if (src.token.startsWith('str.') && !instr.string) {
            var sref = Long.from(x86x64.parse(instr.simplified).opd[1].token, true);
            instr.string = Global().xrefs.find_string(sref);
        }
        if (prev && prev.parsed.mnem == instr.parsed.mnem &&
            prev.parsed.opd[0].token == src.token &&
            !prev.parsed.opd[0].mem_access && !src.mem_access) {
            src = instr.parsed.opd[1] = prev.parsed.opd[1];
            instr.symbol = prev.symbol;
            instr.string = prev.string;
        }
        var arg = instr.string ?
            Variable.string(instr.string) : (
                instr.symbol ? instr.symbol :
                Variable[src.mem_access ? 'pointer' : 'local'](src.token, src.mem_access, false));

        return Base.assign(dst.token, arg);
    }
};

var _extended_mov = function(p, signed, context) {
    var dst = p.opd[0];
    var src = p.opd[1];

    _has_changed_return(dst.token, signed, context);

    if (src.mem_access) {
        return Base.read_memory(src.token, dst.token, src.mem_access, signed);
    } else {
        return Base.cast(dst.token, src.token, Extra.to.type(_find_bits(dst.token), true));
    }
};

var _string_common = function(instr, context) {

    var p = instr.parsed;
    var lhand = p.opd[0];
    var rhand = p.opd[1];

    var counter = {
        16: 'cx',
        32: 'ecx',
        64: 'rcx'
    }[Global().evars.archbits];

    if (p.mnem == "stosd") {
        return Base.call('memset', [lhand.token.replace(/\w+:/, ''), rhand.token, counter]);
    }

    var reciept = {
        'lods': [lhand, rhand, [rhand]],
        'stos': [lhand, rhand, [lhand]],
        'movs': [lhand, rhand, [rhand, lhand]],

    }[p.mnem.substr(0, 4)];

    var dflag = 0;

    var incdec = dflag ?
        Base.decrease :
        Base.increase;

    var loop = p.pref && p.pref.match(/(rep)(n)?([ze])?/);

    if (loop) {
        instr.conditional(counter, '0', 'NE');
        instr.jump = instr.location;
    }

    var dst = reciept[0];
    var src = reciept[1];
    var inc = reciept[2];
    var ops = [];

    var assign_dst = Variable[dst.mem_access ? 'pointer' : 'local'](dst.token, dst.mem_access, false);
    var assign_src = Variable[src.mem_access ? 'pointer' : 'local'](src.token, src.mem_access, false);
    ops.push(Base.assign(assign_dst, assign_src));

    if (loop) {
        ops.push(Base.decrease(counter, 1));
    }

    ops = ops.concat(inc.map(function(r) {
        return incdec(r.token, (dst.mem_access || src.mem_access) / 8);
    }));

    return Base.composed(ops);
};

var _get_reg_value_from_map = function(expected, map) {
    var regs_def = null;
    if (map[expected]) {
        return map[expected];
    }
    for (var i = 0; i < _x86_x64_registers.length; i++) {
        if (_x86_x64_registers[i].indexOf(expected) >= 0) {
            regs_def = _x86_x64_registers[i];
            break;
        }
    }
    if (!regs_def) {
        return null;
    }
    for (i = 0; i < regs_def.length; i++) {
        var data = map[regs_def[i]];
        if (data) {
            return data;
        }
    }
    return null;
};

var _syscall_common = function(instr, instructions, sysinfo, regs) {
    if (!sysinfo) {
        return null;
    }
    if (sysinfo.comment) {
        instr.comments.push(sysinfo.comment);
    }
    if (!sysinfo.table) {
        return null;
    }
    var reglist = {};
    var pos = instructions.indexOf(instr);
    var end = pos - regs.length;

    var push_instr = null;
    var dst, src;
    for (var i = pos - 1; i >= end; i--) {
        var prev = instructions[i] || {};
        if (!prev || !prev.parsed) {
            continue;
        }
        if (prev.parsed.mnem == 'int' || prev.parsed.mnem == 'syscall') {
            break;
        }
        if (prev.parsed.mnem == 'pop' && end > 0) {
            end--;
            push_instr = prev;
        }
        if (prev.parsed.mnem != 'mov' && prev.parsed.mnem != 'push') {
            continue;
        }
        if (prev.parsed.mnem == 'push') {
            if (!push_instr) {
                break;
            }
            dst = push_instr.parsed.opd[0];
            push_instr = null;
            src = prev.parsed.opd[0];
        } else {
            dst = prev.parsed.opd[0];
            src = prev.parsed.opd[1];
        }
        if (prev.string) {
            src = Variable.string(prev.string);
        }
        if (!reglist[dst.token]) {
            reglist[dst.token] = {
                value: src,
                instr: prev,
            };
        }
    }
    var reg0 = regs.shift();
    if (!reglist[reg0]) {
        return null;
    }
    var syscall_num = parseInt(reglist[reg0].value.token).toString(16);
    if (typeof syscall_num != 'string') {
        return null;
    }
    sysinfo = sysinfo.table[syscall_num];
    if (!sysinfo) {
        return null;
    }
    if (sysinfo.comment) {
        instr.comments.push(sysinfo.comment);
    }
    reglist[reg0].instr.valid = false;
    regs = regs.slice(0, sysinfo.args);
    for (i = 0; i < regs.length; i++) {
        var data = _get_reg_value_from_map(regs[i], reglist);
        if (!data || !data.instr) {
            continue;
        }
        data.instr.valid = false;
        src = data.value;
        src = src.token ? Extra.tryas.int(src.token) : src;
        if (Long.isLong(src)) {
            src = Variable.number('0x' + src.toString(16));
        }
        regs[i] = src || regs[i];
    }

    return {
        args: regs,
        name: sysinfo.name
    };
};

var _nop = function() {
    return Base.nop();
};

var _fp_n_opd = function(opd) {
    return opd.filter(function(x) {
        return x.token;
    }).length;
};

var _fp_parse_index = function(s) {
    return s && s.match(/^st\(\d+\)$/) ? parseInt(s.replace(/^st\(|\)$/g, '')) : NaN;
};

var _fp_stack_at = function(idx) {
    if (isNaN(idx)) {
        idx = '?';
    }
    return [_FP_STACK, '[', idx, ']'].join('');
};

var _fp_resolve_opd = function(opd) {
    if (opd.mem_access) {
        return Variable.pointer(opd.token, opd.mem_access, true);
    }
    opd = _fp_parse_index(opd.token);
    if (isNaN(opd)) {
        return '?';
    }
    return _fp_stack_at(opd);
};

var _fp_math_special = function(op, dst, src) {
    return Base.assign(_fp_stack_at(dst), op + '(' + _fp_stack_at(src) + ')');
};

var _fp_compare = function(instr, context, instructions, pops) {
    var rop = null;
    if (_fp_n_opd(instr.parsed.opd) < 1) {
        rop = Base.assign(_FP_STATUS_REG, "fp_compare(" + _fp_stack_at(0) + ", " + _fp_stack_at(1) + ")");
    } else {
        var arg = _fp_resolve_opd(instr.parsed.opd[0]);
        rop = Base.assign(_FP_STATUS_REG, "fp_compare(" + _fp_stack_at(0) + ", " + arg + ")");
    }
    return pops > 0 ? Base.composed([rop, Base.increase(_FP_STACK, pops)]) : rop;
};

var _fp_math_common = function(p, context, pops, op) {
    var rop;
    if (_fp_n_opd(p.opd) == 0) {
        rop = op(_fp_stack_at(1), _fp_stack_at(1), _fp_stack_at(0));
    } else if (_fp_n_opd(p.opd) == 1) {
        rop = op(_fp_stack_at(0), _fp_stack_at(0), _fp_resolve_opd(p.opd[0]));
    } else {
        var a = _fp_resolve_opd(p.opd[0]);
        var b = _fp_resolve_opd(p.opd[1]);
        rop = op(a, a, b);
    }
    return pops > 0 ? Base.composed([rop, Base.increase(_FP_STACK, pops)]) : rop;
};

var _fp_math_common_rev = function(p, context, pops, op) {
    var rop;
    if (_fp_n_opd(p.opd) == 0) {
        rop = op(_fp_stack_at(0), _fp_stack_at(0), _fp_stack_at(1));
    } else if (_fp_n_opd(p.opd) == 1) {
        var value = _fp_resolve_opd(p.opd[0]);
        rop = op(value, value, _fp_stack_at(0));
    } else {
        var a = _fp_stack_at(_fp_parse_index(p.opd[0].token));
        var b = _fp_stack_at(_fp_parse_index(p.opd[1].token));
        rop = op(b, b, a);
    }
    return pops > 0 ? Base.composed([rop, Base.increase(_FP_STACK, pops)]) : rop;
};

const x86x64 = {
    instructions: {
        inc: function(instr, context) {
            instr.parsed.opd[1].token = '1';

            return _math_common(instr.parsed, Base.add, true, context);
        },
        dec: function(instr, context) {
            instr.parsed.opd[1].token = '1';

            return _math_common(instr.parsed, Base.subtract, true, context);
        },
        cld: _nop,
        add: function(instr, context) {
            return _math_common(instr.parsed, Base.add, true, context);
        },
        adc: function(instr, context) {
            return _math_common(instr.parsed, Base.add, true, context);
        },
        sub: function(instr, context) {
            return _math_common(instr.parsed, Base.subtract, true, context);
        },
        sbb: function(instr, context) {
            return _math_common(instr.parsed, Base.subtract, true, context);
        },
        sar: function(instr, context) {
            return _math_common(instr.parsed, Base.shift_right, true, context);
        },
        sal: function(instr, context) {
            return _math_common(instr.parsed, Base.shift_left, true, context);
        },
        shr: function(instr, context) {
            return _math_common(instr.parsed, Base.shift_right, true, context);
        },
        shl: function(instr, context) {
            return _math_common(instr.parsed, Base.shift_left, true, context);
        },
        and: function(instr, context) {
            return _math_common(instr.parsed, Base.and, true, context);
        },
        or: function(instr, context) {
            return _math_common(instr.parsed, Base.or, true, context);
        },
        xor: function(instr, context) {
            return _math_common(instr.parsed, Base.xor, false, context);
        },
        pand: function(instr, context) {
            return _math_common(instr.parsed, Base.and, false, context);
        },
        por: function(instr, context) {
            return _math_common(instr.parsed, Base.or, false, context);
        },
        pxor: function(instr, context) {
            return _math_common(instr.parsed, Base.xor, false, context);
        },
        div: function(instr, context) {
            return _math_divide(instr.parsed, false, context);
        },
        idiv: function(instr, context) {
            return _math_divide(instr.parsed, true, context);
        },
        mul: function(instr, context) {
            return _math_multiply(instr.parsed, false, context);
        },
        imul: function(instr, context) {
            return _math_multiply(instr.parsed, true, context);
        },
        neg: function(instr, context) {
            var dst = instr.parsed.opd[0];

            _has_changed_return(dst.token, true, context);
            return Base.negate(dst.token, dst.token);
        },
        not: function(instr, context) {
            var dst = instr.parsed.opd[0];

            _has_changed_return(dst.token, false, context);
            return Base.not(dst.token, dst.token);
        },
        lea: function(instr, context) {
            var dst = instr.parsed.opd[0];
            var val = instr.parsed.opd[1];

            _has_changed_return(dst.token, false, context);

            var calc = val.token.match(/([re]?(?:[abcd]x|[ds]i)|r(?:1[0-5]|[8-9])[lwd]?)\s*\+\s*\1\s*\*(\d)/);

            if (calc) {
                return Base.multiply(dst.token, calc[1], parseInt(calc[2]) + 1 + '');
            }

            var amp = _is_func_arg(val.token, context) || _is_local_var(val.token, context);

            var arg = instr.string ?
                Variable.string(instr.string) :
                (amp ? '&' : '') + val.token.replace(/\./g, '_');

            return Base.assign(dst.token, arg);
        },
        call: _call_function,
        cmova: function(instr, context, instructions) {
            return _cmov_common(instr, context, instructions, 'LE');
        },
        cmovae: function(instr, context, instructions) {
            return _cmov_common(instr, context, instructions, 'LT');
        },
        cmovb: function(instr, context, instructions) {
            return _cmov_common(instr, context, instructions, 'GE');
        },
        cmovbe: function(instr, context, instructions) {
            return _cmov_common(instr, context, instructions, 'GT');
        },
        cmove: function(instr, context, instructions) {
            return _cmov_common(instr, context, instructions, 'NE');
        },
        cmovg: function(instr, context, instructions) {
            return _cmov_common(instr, context, instructions, 'LE');
        },
        cmovge: function(instr, context, instructions) {
            return _cmov_common(instr, context, instructions, 'LT');
        },
        cmovl: function(instr, context, instructions) {
            return _cmov_common(instr, context, instructions, 'GE');
        },
        cmovle: function(instr, context, instructions) {
            return _cmov_common(instr, context, instructions, 'GT');
        },
        cmovne: function(instr, context, instructions) {
            return _cmov_common(instr, context, instructions, 'EQ');
        },
        bswap: function(instr, context) {
            var dst = instr.parsed.opd[0];

            return Base.swap_endian(dst.token, dst.token, _find_bits(dst.token));
        },
        mov: _standard_mov,
        movd: _standard_mov,
        movq: _standard_mov,
        movss: _standard_mov,

        movabs: _standard_mov,
        cbw: function(instr, context) {
            _has_changed_return('ax', true, context);
            return Base.cast('ax', 'al', 'int16_t');
        },
        cwde: function(instr, context) {
            _has_changed_return('eax', true, context);
            return Base.cast('eax', 'ax', 'int32_t');
        },
        cdq: function(instr, context) {
            _has_changed_return('eax', true, context);
            return Base.cast('edx:eax', 'eax', 'int64_t');
        },
        cdqe: function(instr, context) {
            _has_changed_return('rax', true, context);
            return Base.cast('rax', 'eax', 'int64_t');
        },
        movsx: function(instr, context) {
            return _extended_mov(instr.parsed, true, context);
        },
        movsxd: function(instr, context) {
            return _extended_mov(instr.parsed, true, context);
        },
        movzx: function(instr, context) {
            return _extended_mov(instr.parsed, false, context);
        },
        seta: function(instr, context) {
            return _setcc_common(instr.parsed, false, 'GT', context);
        },
        setae: function(instr, context) {
            return _setcc_common(instr.parsed, false, 'GE', context);
        },
        setb: function(instr, context) {
            return _setcc_common(instr.parsed, false, 'LT', context);
        },
        setbe: function(instr, context) {
            return _setcc_common(instr.parsed, false, 'LE', context);
        },
        setg: function(instr, context) {
            return _setcc_common(instr.parsed, true, 'GT', context);
        },
        setge: function(instr, context) {
            return _setcc_common(instr.parsed, true, 'GE', context);
        },
        setl: function(instr, context) {
            return _setcc_common(instr.parsed, true, 'LT', context);
        },
        setle: function(instr, context) {
            return _setcc_common(instr.parsed, true, 'LE', context);
        },
        sete: function(instr, context) {
            return _setcc_common(instr.parsed, context.returns.signed, 'EQ', context);
        },
        setne: function(instr, context) {
            return _setcc_common(instr.parsed, context.returns.signed, 'NE', context);
        },
        nop: _nop,
        leave: _nop,
        rol: function(instr, context) {
            return _bitwise_rotate(instr.parsed, Base.rotate_left, context);
        },
        ror: function(instr, context) {
            return _bitwise_rotate(instr.parsed, Base.rotate_right, context);
        },
        rcl: function(instr, context) {
            return _bitwise_rotate(instr.parsed, Base.rotate_left, context);
        },
        rcr: function(instr, context) {
            return _bitwise_rotate(instr.parsed, Base.rotate_right, context);
        },
        jmp: function(instr, context, instructions) {
            var dst = instr.parsed.opd[0];

            if (dst.mem_access) {
                if (_is_jumping_externally(instr, instructions) || dst.token.startsWith('reloc.')) {

                    return Base.call(dst.token);
                } else if (_is_local_var(dst.token, context) || dst.token.startsWith('0x')) {

                    return _call_function(instr, context, instructions, true);
                }
            } else if (_is_last_instruction(instr, instructions) && dst.token.startsWith('sym.')) {
                return Base.call(dst.token);
            }

            var ijmp = _get_jump_instruction(instr, instructions);
            if (ijmp && ijmp.parsed.mnem == 'call') {
                var prev = instructions[instructions.indexOf(ijmp) - 1];
                if (prev && prev.parsed.mnem == 'push') {
                    instr.parsed = ijmp.parsed;
                    var r = _call_function(instr, context, instructions, false, true);
                    return r ? Base.composed([r]) : null;
                }
            }

            var ref = dst.token.split(' ');

            if (_x86_x64_registers.indexOf(ref[0]) > (-1)) {
                return _call_function(instr, context, instructions, true);
            }

            return Base.nop();
        },
        cmp: function(instr, context) {
            var lhand = instr.parsed.opd[0];
            var rhand = instr.parsed.opd[1];

            var a = lhand.mem_access ? Variable.pointer(lhand.token, lhand.mem_access, true) : _check_known_neg(lhand.token);
            var b = rhand.mem_access ? Variable.pointer(rhand.token, rhand.mem_access, true) : _check_known_neg(rhand.token);

            context.cond.a = a;
            context.cond.b = b;

            return Base.nop();
        },
        test: function(instr, context) {
            var lhand = instr.parsed.opd[0];
            var rhand = instr.parsed.opd[1];

            var a = lhand.mem_access ? Variable.pointer(lhand.token, lhand.mem_access, true) : _check_known_neg(lhand.token);
            var b = rhand.mem_access ? Variable.pointer(rhand.token, rhand.mem_access, true) : _check_known_neg(rhand.token);

            context.cond.a = (a === b) ? a : '(' + a + ' & ' + b + ')';
            context.cond.b = '0';

            return Base.nop();
        },
        bt: function(instr, context) {
            var a = instr.parsed.opd[0].token;
            var b = instr.parsed.opd[1].token;

            context.cond.a = '((' + a + ' >> ' + b + ') & 1)';
            context.cond.b = '0';

            return Base.nop();
        },
        ret: function(instr, context, instructions) {
            var register = {
                8: 'al',
                16: 'ax',
                32: 'eax',
                64: 'rax'
            }[context.returns.bits] || '';

            if (_is_last_instruction(instr, instructions) && (register === '')) {
                return Base.nop();
            }

            return Base.return(register);
        },
        push: function(instr, context) {
            instr.valid = false;

            var val = instr.parsed.opd[0];

            return val.mem_access ?
                Variable.pointer(val.token, Extra.to.type(val.mem_access, false)) :
                val.token;
        },
        pop: function(instr, context, instrs) {
            var dst = instr.parsed.opd[0];

            if (!_is_frame_reg(dst.token)) {
                for (var i = instrs.indexOf(instr); i >= 0; i--) {
                    var mnem = instrs[i].parsed.mnem;
                    var opd1 = instrs[i].parsed.opd[0];

                    if (mnem === 'push') {
                        var value = instrs[i].string ?
                            Variable.string(instrs[i].string) :
                            opd1.token;

                        return Base.assign(dst.token, value);
                    } else if ((mnem === 'call') || _is_stack_reg(opd1.token)) {
                        break;
                    }
                }
            }

            if (dst.token.match(/[er]?ax/)) {
                context.returns.bits = _return_regs_bits[dst];
                context.returns.signed = false;
            }

            return Base.nop();
        },
        lodsb: _string_common,
        lodsw: _string_common,
        lodsd: _string_common,
        lodsq: _string_common,
        stosb: _string_common,
        stosw: _string_common,
        stosd: _string_common,
        stosq: _string_common,
        movsb: _string_common,
        movsw: _string_common,
        movsd: function(instr, context, instructions) {
            var p = instr.parsed;
            var lhand = p.opd[0];
            var rhand = p.opd[1];

            if (_is_xmm(lhand) || _is_xmm(rhand)) {
                return _standard_mov(instr, context, instructions);
            } else {
                return _string_common(instr, context);
            }
        },
        movsq: _string_common,

        movaps: _standard_mov,

        jo: function(i, c) {
            return _jcc_common(i, c, 'LO');
        },
        jno: function(i, c) {
            return _jcc_common(i, c, 'NO');
        },
        jnp: function(i, c) {
            return _jcc_common(i, c, 'NE');
        },
        jne: function(i, c) {
            return _jcc_common(i, c, 'NE');
        },
        jpo: function(i, c) {
            return _jcc_common(i, c, 'NE');
        },
        jp: function(i, c) {
            return _jcc_common(i, c, 'EQ');
        },
        jpe: function(i, c) {
            return _jcc_common(i, c, 'EQ');
        },
        je: function(i, c) {
            return _jcc_common(i, c, 'EQ');
        },
        ja: function(i, c) {
            return _jcc_common(i, c, 'GT');
        },
        jae: function(i, c) {
            return _jcc_common(i, c, 'GE');
        },
        jb: function(i, c) {
            return _jcc_common(i, c, 'LT');
        },
        jbe: function(i, c) {
            return _jcc_common(i, c, 'LE');
        },
        jg: function(i, c) {
            return _jcc_common(i, c, 'GT');
        },
        jge: function(i, c) {
            return _jcc_common(i, c, 'GE');
        },
        jle: function(i, c) {
            return _jcc_common(i, c, 'LE');
        },
        jl: function(i, c) {
            return _jcc_common(i, c, 'LT');
        },
        js: function(i, c) {
            return _jcc_common(i, c, 'LT');
        },
        jns: function(i, c) {
            return _jcc_common(i, c, 'GE');
        },
        jz: function(i, c) {
            return _jcc_common(i, c, 'EQ');
        },
        jnz: function(i, c) {
            return _jcc_common(i, c, 'NE');
        },
        jc: function(i, c) {
            return _jcc_common(i, c, 'LT');
        },
        jnc: function(i, c) {
            return _jcc_common(i, c, 'GE');
        },
        setz: function(instr, context) {
            return _setcc_common(instr.parsed, context.returns.signed, 'EQ', context);
        },
        setnz: function(instr, context) {
            return _setcc_common(instr.parsed, context.returns.signed, 'NE', context);
        },
        cmovz: function(instr, context, instructions) {
            return _cmov_common(instr, context, instructions, 'NE');
        },
        cmovnz: function(instr, context, instructions) {
            return _cmov_common(instr, context, instructions, 'EQ');
        },
        endbr64: _nop,
        endbr32: _nop,
        xchg: function(instr, context) {
            var lhand = instr.parsed.opd[0];
            var rhand = instr.parsed.opd[1];

            var tmp = Variable.uniqueName('tmp');

            return Base.composed([
                Base.assign(tmp, lhand.token),
                Base.assign(lhand.token, rhand.token),
                Base.assign(rhand.token, tmp)
            ]);
        },
        int: function(instr, context, instructions) {
            var syscall_num = parseInt(instr.parsed.opd[0].token).toString(16);
            var name = 'syscall_' + syscall_num + 'h';
            var regs = ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'edp'];
            var info = _syscall_common(instr, instructions, Syscalls(syscall_num, 'x86'), regs);
            if (info) {
                name = info.name;
                regs = info.args;
            }
            return Base.assign('eax', Base.call(name, regs));
        },
        syscall: function(instr, context, instructions) {
            var name = 'syscall_80h';
            var regs = ['rax', 'rdi', 'rsi', 'rdx', 'r10', 'r8', 'r9'];
            var info = _syscall_common(instr, instructions, Syscalls('80', 'x86'), regs);
            if (info) {
                name = info.name;
                regs = info.args;
            }
            return Base.assign('rax', Base.call(name, regs));
        },
        hlt: function() {
            return Base.return(Base.call('_hlt', []));
        },

        fld1: function(instr, context, instrs) {
            return Base.write_memory(_FP_STACK + '--', '1.0', 64, true);
        },

        fldl2t: function(instr, context, instrs) {
            return Base.write_memory(_FP_STACK + '--', 'log_2(10)', 64, true);
        },

        fldl2e: function(instr, context, instrs) {
            return Base.write_memory(_FP_STACK + '--', 'log_2(e)', 64, true);
        },

        fldpi: function(instr, context, instrs) {
            return Base.write_memory(_FP_STACK + '--', 'pi', 64, true);
        },

        fldlg2: function(instr, context, instrs) {
            return Base.write_memory(_FP_STACK + '--', 'log_10(2)', 64, true);
        },

        fldln2: function(instr, context, instrs) {
            return Base.write_memory(_FP_STACK + '--', 'log_e(2)', 64, true);
        },

        fldz: function(instr, context, instrs) {
            return Base.write_memory(_FP_STACK + '--', '0.0', 64, true);
        },
        fild: function(instr, context, instrs) {
            var arg = instr.parsed.opd[0];
            var value = Variable.pointer(arg.token, arg.mem_access, true);
            return Base.write_memory(_FP_STACK + '--', value, 64, true);
        },
        fbld: function(instr, context, instrs) {
            var arg = instr.parsed.opd[0];
            var value = Variable.pointer(arg.token, arg.mem_access, true);
            return Base.write_memory(_FP_STACK + '--', value, 64, true);
        },
        fld: function(instr, context, instrs) {
            var arg = instr.parsed.opd[0];
            var value = arg.mem_access ? Variable.pointer(arg.token, arg.mem_access, true) : _fp_stack_at(_fp_parse_index(arg.token));
            return Base.write_memory(_FP_STACK + '--', value, 64, true);
        },
        fbstp: function(instr, context, instrs) {
            var arg = instr.parsed.opd[0];
            return Base.composed([
                Base.write_memory(arg.token, _fp_stack_at(0), arg.mem_access, true),
                Base.decrease(_FP_STACK, 1)
            ]);
        },
        fst: function(instr, context, instrs) {
            return Base.assign(_fp_resolve_opd(instr.parsed.opd[0]), _fp_stack_at(0));
        },
        fstp: function(instr, context, instrs) {
            var arg = instr.parsed.opd[0];
            if (_fp_parse_index(arg.token) == 0) {
                return Base.increase(_FP_STACK, 1);
            }
            arg = _fp_resolve_opd(arg);
            return Base.composed([Base.assign(arg, _fp_stack_at(0)), Base.decrease(_FP_STACK, 1)]);
        },
        fdecstp: function() {
            return Base.increase(_FP_STACK, 1);
        },
        fincstp: function() {
            return Base.decrease(_FP_STACK, 1);
        },
        fist: function(instr, context, instrs) {
            var arg = instr.parsed.opd[0];
            return Base.write_memory(arg.token, _fp_stack_at(0), arg.mem_access, true);
        },
        fisttp: function(instr, context, instrs) {
            var arg = instr.parsed.opd[0];
            return Base.composed([
                Base.write_memory(arg.token, _fp_stack_at(0), arg.mem_access, true),
                Base.decrease(_FP_STACK, 1)
            ]);
        },
        fistp: function(instr, context, instrs) {
            var arg = instr.parsed.opd[0];
            return Base.composed([
                Base.write_memory(arg.token, _fp_stack_at(0), arg.mem_access, true),
                Base.decrease(_FP_STACK, 1)
            ]);
        },
        fxch: function(instr, context) {
            var idx = 1;
            if (_fp_n_opd(instr.parsed.opd) > 0) {
                idx = _fp_parse_index(instr.parsed.opd[0].token);
            }
            var tmp = Variable.uniqueName('fp_tmp');
            var src = _fp_stack_at(0);
            var dest = _fp_stack_at(idx);

            return Base.composed([
                Base.assign(tmp, dest),
                Base.assign(dest, src),
                Base.assign(src, tmp)
            ]);
        },

        ftst: function(instr, context, instructions) {
            context.cond.a = _fp_stack_at(0);
            context.cond.b = '0.0';
            return Base.nop();
        },

        fcomi: function(instr, context, instructions) {
            context.cond.a = _fp_stack_at(0);
            context.cond.b = _fp_resolve_opd(instr.parsed.opd[0]);
            return Base.nop();
        },
        fucomi: function(instr, context, instructions) {
            context.cond.a = _fp_stack_at(0);
            context.cond.b = _fp_resolve_opd(instr.parsed.opd[0]);
            return Base.nop();
        },

        fcomip: function(instr, context, instructions) {
            context.cond.a = _fp_stack_at(0);
            context.cond.b = _fp_resolve_opd(instr.parsed.opd[0]);
            return Base.decrease(_FP_STACK, 1);
        },
        fucomip: function(instr, context, instructions) {
            context.cond.a = _fp_stack_at(0);
            context.cond.b = _fp_resolve_opd(instr.parsed.opd[0]);
            return Base.decrease(_FP_STACK, 1);
        },

        fcom: function(instr, context, instructions) {
            return _fp_compare(instr, context, instructions, 0);
        },

        fcomp: function(instr, context, instructions) {
            return _fp_compare(instr, context, instructions, 1);
        },

        fucomp: function(instr, context, instructions) {
            return _fp_compare(instr, context, instructions, 1);
        },

        fcompp: function(instr, context, instructions) {
            return _fp_compare(instr, context, instructions, 2);
        },

        fucompp: function(instr, context, instructions) {
            return _fp_compare(instr, context, instructions, 2);
        },
        fstsw: function(instr, context) {
            var v = instr.parsed.opd[0];
            return Base.assign(v.token, _FP_STATUS_REG);
        },
        fnstsw: function(instr, context) {
            var v = instr.parsed.opd[0];
            return Base.assign(v.token, _FP_STATUS_REG);
        },
        fadd: function(instr, context) {
            return _fp_math_common(instr.parsed, context, 0, Base.add);
        },
        fiadd: function(instr, context) {
            return _fp_math_common(instr.parsed, context, 0, Base.add);
        },
        faddp: function(instr, context) {
            return _fp_math_common(instr.parsed, context, 1, Base.add);
        },
        fsub: function(instr, context) {
            return _fp_math_common(instr.parsed, context, 0, Base.subtract);
        },
        fisub: function(instr, context) {
            return _fp_math_common(instr.parsed, context, 0, Base.subtract);
        },
        fsubp: function(instr, context) {
            return _fp_math_common(instr.parsed, context, 1, Base.subtract);
        },
        fsubr: function(instr, context) {
            return _fp_math_common_rev(instr.parsed, context, 0, Base.subtract);
        },
        fisubr: function(instr, context) {
            return _fp_math_common_rev(instr.parsed, context, 0, Base.subtract);
        },
        fsubrp: function(instr, context) {
            return _fp_math_common_rev(instr.parsed, context, 1, Base.subtract);
        },
        fmul: function(instr, context) {
            return _fp_math_common(instr.parsed, context, 0, Base.multiply);
        },
        fimul: function(instr, context) {
            return _fp_math_common(instr.parsed, context, 0, Base.multiply);
        },
        fmulp: function(instr, context) {
            return _fp_math_common(instr.parsed, context, 1, Base.multiply);
        },
        fdiv: function(instr, context) {
            return _fp_math_common(instr.parsed, context, 0, Base.divide);
        },
        fidiv: function(instr, context) {
            return _fp_math_common(instr.parsed, context, 0, Base.divide);
        },
        fdivp: function(instr, context) {
            return _fp_math_common(instr.parsed, context, 1, Base.divide);
        },
        fdivr: function(instr, context) {
            return _fp_math_common_rev(instr.parsed, context, 0, Base.divide);
        },
        fidivr: function(instr, context) {
            return _fp_math_common_rev(instr.parsed, context, 0, Base.divide);
        },
        fdivrp: function(instr, context) {
            return _fp_math_common_rev(instr.parsed, context, 1, Base.divide);
        },
        fabs: function(instr, context) {
            return _fp_math_special('abs', 0, 0);
        },
        fchs: function(instr, context) {
            return Base.negate(_fp_stack_at(0), _fp_stack_at(0));
        },
        fsqrt: function(instr, context) {
            return _fp_math_special('sqrt', 0, 0);
        },
        fprem: function(instr, context) {
            return Base.module(_fp_stack_at(0), _fp_stack_at(0), _fp_stack_at(1));
        },
        fprem1: function(instr, context) {
            return Base.module(_fp_stack_at(0), _fp_stack_at(0), _fp_stack_at(1));
        },
        fcos: function(instr, context) {
            return _fp_math_special('cos', 0, 0);
        },
        fsin: function(instr, context) {
            return _fp_math_special('sin', 0, 0);
        },
        fsincos: function(instr, context) {
            return Base.composed([
                _fp_math_special('sin', 0, 0),
                Base.write_memory(_FP_STACK + '--', 'cos(' + _fp_stack_at(0) + ')', 64, true)
            ]);
        },
        fptan: function(instr, context) {
            return Base.composed([
                _fp_math_special('tan', 0, 0),
                Base.write_memory(_FP_STACK + '--', '1.0', 64, true)
            ]);
        },
        fpatan: function(instr, context) {
            return Base.composed([
                Base.assign(_fp_stack_at(1), 'arctan(' + _fp_stack_at(1) + '/' + _fp_stack_at(0) + ')'),
                Base.decrease(_FP_STACK, 1)
            ]);
        },
        frndint: function(instr, context) {
            return _fp_math_special('round', 0, 0);
        },
        f2xm1: function(instr, context) {
            return Base.assign(_fp_stack_at(0), 'pow(2, ' + _fp_stack_at(0) + ') - 1.0');
        },
        fyl2x: function(instr, context) {
            return Base.assign(_fp_stack_at(1), _fp_stack_at(1) + ' * log_2(' + _fp_stack_at(0) + ')');
        },
        fyl2xp1: function(instr, context) {
            return Base.assign(_fp_stack_at(1), _fp_stack_at(1) + ' * log_2(' + _fp_stack_at(0) + ' + 1.0)');
        },
        ffree: _nop,
        finit: _nop,
        fldcw: _nop,
        fldenv: _nop,
        fnclex: _nop,
        fnop: _nop,
        fnsave: _nop,
        fnstcw: _nop,
        fnstenv: _nop,
        frstor: _nop,
        fsave: _nop,
        fwait: _nop,
        fxrstor: _nop,
        fxsave: _nop,
        endbr64: _nop,
        invalid: _nop
    },
    preanalisys: function(instrs, context) {
        instrs.forEach(function(i) {
            var opd1 = i.parsed.opd[0];
            var opd2 = i.parsed.opd[1];

            if (_is_func_arg(opd1.token, context) ||
                _is_local_var(opd1.token, context)) {
                opd1.mem_access = undefined;
            }

            if (opd1.segovr && opd1.token) {
                opd1.token = opd1.segovr + opd1.token;
            }

            if (_is_func_arg(opd2.token, context) ||
                _is_local_var(opd2.token, context)) {
                opd2.mem_access = undefined;
            }

            if (opd2.segovr && opd2.token) {
                opd2.token = opd2.segovr + opd2.token;
            }
        });
    },
    parse: function(asm) {

        var tokens = asm.match(/(?:(repn?[ez]?|lock)\s+)?(\w+)(?:\s+(byte|(?:[dq]|[xyz]mm)?word))?(?:\s*([c-gs]s:)?(?:\[?)([^[\],]+)(?:\]?))?(?:(?:,)(?:\s+(byte|(?:[dq]|[xyz]mm)?word)(?: ptr)?)?(?:\s*([d-g]s:)?(?:\[?)([^[\],]+)(?:\]?))?)?(?:,(?:\s+([^[\],]+))?)?/);

        var prefix = tokens[1];
        var mnemonic = tokens[2];

        var qualifier = {
            'byte': 8,
            'word': 16,
            'dword': 32,
            'qword': 64,
            'xmmword': 128,
            'ymmword': 256,
            'zmmword': 512
        };

        var operand1 = {
            mem_access: qualifier[tokens[3]],
            segovr: tokens[4],
            token: tokens[5]
        };

        var operand2 = {
            mem_access: qualifier[tokens[6]],
            segovr: tokens[7],
            token: tokens[8]
        };

        var operand3 = {
            mem_access: undefined,
            segovr: undefined,
            token: tokens[9]
        };

        return {
            pref: prefix,
            mnem: mnemonic,
            opd: [operand1, operand2, operand3]
        };
    },
    context: function(data) {
        var fcnargs = data.xrefs.arguments;

        var vars_args = Array.prototype.concat(fcnargs.stack, fcnargs.reg).map(function(x) {
            if (x.type === 'int' || x.type === 'signed int') {
                x.type = (Global().evars.archbits < 32) ? 'int16_t' : 'int32_t';
            } else if (x.type === 'unsigned int') {
                x.type = (Global().evars.archbits < 32) ? 'uint16_t' : 'uint32_t';
            }

            return x;
        });

        return {
            cond: {
                a: '?',
                b: '?',
            },
            markers: {},
            returns: {
                bits: 0,
                signed: true
            },
            arch_bits: data.bits,
            vars: vars_args.filter(function(e) {
                return !e.arg;
            }) || [],
            args: vars_args.filter(function(e) {
                return e.arg;
            }) || []
        };
    },
    localvars: function(context) {
        return context.vars.map(function(v) {
            return v.type + ' ' + v.name;
        }).concat(context.args.filter(function(v) {
            return v.storage.type === "reg";
        }).map(function(v) {
            return v.storage.reg + ' = ' + v.name;
        }));
    },
    globalvars: function(context) {
        return [];
    },
    arguments: function(context) {
        return context.args.length == 0 ?
            ['void'] :
            context.args.map(function(v) {
                return v.type + ' ' + v.name;
            });
    },
    returns: function(context) {
        if (context.returns.bits > 0) {
            return (context.returns.signed ? 'int' : 'uint') + context.returns.bits + '_t';
        }
        return 'void';
    }
};

function _apply_marker_math(instr, context) {
    if (!context.markers[instr.marker]) {
        context.markers[instr.marker] = {};
    }
    var m = context.markers[instr.marker];
    if (_apply_math_x86[instr.parsed.mnem]) {
        _apply_math_x86[instr.parsed.mnem](m, instr, context);
    }
    return instr.code;
}

var _apply_math_x86 = {
    mov: function(marker, instr) {
        if (_x86_x64_registers.indexOf(instr.parsed.opd[0].token) < 0 ||
            _x86_x64_registers.indexOf(instr.parsed.opd[1].token) >= 0 ||
            (!instr.parsed.opd[1].token.startsWith('0x') &&
                !instr.parsed.opd[1].token.startsWith('reloc.') &&
                !instr.parsed.opd[1].token.startsWith('sym.') &&
                !instr.parsed.opd[1].token.startsWith('str.'))) {
            return;
        }

        var value = instr.parsed.opd[1].token.startsWith('0x') ? Long.from(instr.parsed.opd[1].token) : null;
        marker[instr.parsed.opd[0].token] = {
            value: value,
            instr: instr,
        };
    },
};

export default x86x64;
