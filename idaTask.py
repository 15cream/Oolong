# coding=utf-8

import os
import re
import time
import pickle
import idc
import idaapi
import idautils
import ida_bytes
import ida_funcs
import ida_segment
import ida_typeinf
import ida_hexrays
import ida_xref
import ida_gdl

ERROR = dict()
memptr = []
miss_arg = dict()
blr = []
helper = []
case_1 = []
ptr_arg = []
INVALID_EA = 0xffffffffffffffffL
USELESS_TYPES = ['id', 'void *', 'void **', 'struct objc_object *', '__int64', 'char *', '_QWORD *', '_QWORD',
                 'const char *']
execute_block_through_timer = ['scheduledTimerWithTimeInterval:repeats:block:',
                               'timerWithTimeInterval:repeats:block:',
                               'initWithFireDate:interval:repeats:block:', ]

execute_invocation_through_timer = ['scheduledTimerWithTimeInterval:invocation:repeats:',
                                    'timerWithTimeInterval:invocation:repeats:']

dispatch_msg_in_timer = ['scheduledTimerWithTimeInterval:target:selector:userInfo:repeats:',
                         'timerWithTimeInterval:target:selector:userInfo:repeats:',
                         'initWithFireDate:interval:target:selector:userInfo:repeats:', ]

ptypes = {
    'B': 'bool',
    'Q': '__int64',  # unsigned __int64
    'I': '__int64',  # unsigned int
    'i': '__int64',  # int
    'q': '__int64',  # signed __int64


}

# NOP : 1F 20 03 D5
# MOV X0, X0 : E0 03 00 AA
# MOV X29, X29 : FD 03 1D AA

arc_calls_as_nop = [
    '_objc_autorelease',  # id objc_autorelease(id value); Always returns value
    '_objc_autoreleaseReturnValue',  # Always returns X0
    '_objc_retain',  # Always returns X0
    '_objc_release',  # release X0
    '_objc_retainAutorelease',  # id objc_retainAutorelease(id value); Always returns value
    '_objc_retainAutoreleasedReturnValue',  # Always returns x0
    '_objc_retainAutoreleaseReturnValue',
    "_objc_destroyWeak",  # void objc_destroyWeak(id *object);
    '_objc_retainBlock',  # id objc_retainBlock(id value);
]

objc_funcs = {
    "_objc_copyWeak",  # "MOV X0, X1",  # void objc_copyWeak(id *dest, id *src);
    "_objc_moveWeak",  # "MOV X0, X1",  # void objc_moveWeak(id *dest, id *src);
    "_objc_initWeak",  # "MOV X0, X1",  # id objc_initWeak(id *object, id value);
    "_objc_loadWeak",  # "LDR X0, [X0]",  # id objc_loadWeak(id *object);
    "_objc_loadWeakRetained",  # "LDR X0, [X0]",  # id objc_loadWeakRetained(id *object);
    "_objc_storeStrong",  # "STR X0, X1",  # void objc_storeStrong(id *object, id value);
    "_objc_storeWeak",  # id objc_storeWeak(id *object, id value);
}

stop_words = ['NS_AVAILABLE', 'NS_DEPRECATED', 'NS_DESIGNATED_INITIALIZER', '__OSX_AVAILABLE_STARTING',
              'NS_UNAVAILABLE', 'NS_EXTENSION_UNAVAILABLE_IOS']

cdecls = {'_dispatch_async': 'void dispatch_once(void *a1, void *a2);',  # void dispatch_async(dispatch_queue_t queue, dispatch_block_t block);
          '_dispatch_once': 'void dispatch_once(void *a1, void *a2);',  # void dispatch_once(dispatch_once_t *predicate, dispatch_block_t block);
          '_dispatch_sync': 'void dispatch_once(void *a1, void *a2);',  # void dispatch_sync(dispatch_queue_t queue, dispatch_block_t block);
          '_objc_retainAutoreleaseReturnValue': '__int64 __fastcall objc_retainAutoreleaseReturnValue(__int64 a1);',
          '_objc_retain': '__int64 __fastcall objc_retain(__int64 a1);',
          '_objc_release': 'void __fastcall objc_release(void *a1);',
          }

log_on = True

# --------------------------------------------CG--------------------------------------------------


class CG:
    sharedCG = None

    def __init__(self):
        self.nodes = {}
        self.edges = dict()
        self.invoke_info = dict()
        CG.sharedCG = self

    def add_node(self, f, name):
        self.nodes[f] = name

    def add_edge(self, src, target, ea, _type, details=None, message=None, ccall=None, block=None):
        # print 'from {} to {} at {}, type: {}, args:'.format(hex(src), target, hex(ea), _type)
        if ea in self.edges:
            self.edges[ea].append([src, target, ea, _type, details or ''])
        else:
            self.edges[ea] = [[src, target, ea, _type, details or ''], ]

        record = None
        func = None
        if message or ccall:
            cargs = message.cargs if message else ccall.cargs
            func = message.f if message else ccall.f
            callsite = message.callsite if message else ccall.callsite
            record = (func, cargs, callsite)
        elif block and block.frm_func:
            func = block.frm_func
            record = (block.frm_func, block.vars, ea)
        if record and func:
            func.calls.append(record)
            self.invoke_info[ea] = record



    def pprint(self):
        lines = dict()
        for edge in self.edges:
            if edge[3] in ['E_MSG', 'X_MSG']:
                lines[edge[2]] = idc.GetFunctionName(edge[0]), edge[1], edge[3], edge[4]
            else:
                lines[edge[2]] = idc.GetFunctionName(edge[0]), idc.GetFunctionName(edge[1]), edge[3], edge[4]
        for ea in sorted(lines.keys()):
            print hex(ea), lines[ea]

    def clear(self):
        self.nodes = []
        self.edges = []


# ---------------------------------process arc calls------------------------------------------------------
def process_arc_calls(func_start):
    ret = MachO.func_data[func_start].rettype.__str__() if func_start in MachO.func_data else None
    for ins in FuncItems(func_start):
        if idc.GetMnem(ins) == 'BL':
            call = idc.GetOpnd(ins, 0)
            if call in arc_calls_as_nop:
                # if idc.GetMnem(ins-4) == 'MOV':
                # 	ida_bytes.patch_dword(ins, idc.Dword(ins-4))
                ida_bytes.patch_dword(ins, 0xD503201F)  # NOP
                ida_bytes.set_cmt(ins, call, False)
        # elif idc.GetMnem(ins) == 'B':
        #     call = idc.GetOpnd(ins, 0)
        #     if ret and ret == 'id' and call in arc_calls_as_nop:
        #         ida_bytes.patch_dword(ins, 0xD65F03C0)  # C0 03 5F D6
        #         ida_bytes.set_cmt(ins, call, False)

    # reanalyze the function or the CFG may be sliced by the PATCH OPERATION.
    f = ida_funcs.get_func(func_start)
    ida_funcs.reanalyze_function(f)


# ----------------------------------load framework headers-------------------------------------

class Frameworks:

    cls_dict = dict()
    proto_dict = dict()
    sel_dict = dict()

    def __init__(self, name=None):
        self.name = name
        self.super = None
        self.methods = dict()
        self.props = dict()
        self.protocols = []

    def pprint(self):
        print '--------------------------'
        print 'Class Name: ', self.name
        print 'Super class: ', self.super
        print 'Methods:'
        for sel, types in self.methods.items():
            print sel, types
        print 'Properties:'
        for p, type in self.props.items():
            print p, type

    def respond_to_sel(self, sel):
        # print 'debug', self.name, sel
        for SEL in self.methods:
            if SEL.strip('*') == sel:
                return self.methods[SEL][0]
        for property in self.props:
            if property.strip('*') == sel:
                return self.props[property]

        # cannot find the method in this class
        if self.super and self.super in Frameworks.cls_dict:
            return Frameworks.cls_dict[self.super].respond_to_sel(sel)
        if self.name != 'NSProxy':
            return Frameworks.cls_dict['NSProxy'].respond_to_sel(sel)
        else:
            return None

    def add_method(self, sel, typeinfo):
        if sel not in self.methods:
            self.methods[sel] = typeinfo

    def get_method(self, sel):
        if sel in self.methods:
            return self.methods[sel]
        else:
            return None

    @staticmethod
    def build_sel_dict():
        for n, cls in Frameworks.cls_dict.items():
            for pn in cls.protocols:
                if pn in Frameworks.proto_dict:
                    p = Frameworks.proto_dict[pn]
                    cls.methods.update(p.methods)
                    cls.props.update(p.props)

        for d in [Frameworks.cls_dict, Frameworks.proto_dict]:
            for name, i in d.items():
                for sel in i.methods:
                    if sel not in Frameworks.sel_dict:
                        Frameworks.sel_dict[sel] = {i}
                    else:
                        Frameworks.sel_dict[sel].add(i)
                for p in i.props:
                    if p.strip('*') not in Frameworks.sel_dict:
                        Frameworks.sel_dict[p.strip('*')] = {i}
                    else:
                        Frameworks.sel_dict[p.strip('*')].add(i)

    @staticmethod
    def build_from_pkl(fp):
        f = open(fp)
        Frameworks.cls_dict, Frameworks.proto_dict = pickle.load(f)
        f.close()
        Frameworks.build_sel_dict()

    @staticmethod
    def get_proto(proto_name):
        if proto_name not in Frameworks.proto_dict:
            p = Frameworks(proto_name)
            Frameworks.proto_dict[proto_name] = p
            return p
        else:
            return Frameworks.proto_dict[proto_name]

    @staticmethod
    def get_class(cls_name):
        if cls_name not in Frameworks.cls_dict:
            cls = Frameworks(cls_name)
            Frameworks.cls_dict[cls_name] = cls
            return cls
        else:
            return Frameworks.cls_dict[cls_name]

    @staticmethod
    def build_from_file(fp):
        file = open(fp)
        current_fs = None

        for line in file.readlines():
            m1 = re.search('@interface\s+(?P<class>[^()\s]\w+)', line)
            if m1:
                current_fs = Frameworks.get_class(m1.group('class'))
                m2 = re.search('@interface\s+(?P<class>\w+)[\s:]+(?P<superclass>\w+)\s+', line)
                current_fs.super = m2.group('superclass') if m2 else current_fs.super
                m3 = re.search('\<(?P<protocol>.+)\>', line)
                if m3:
                    for p in m3.group('protocol').split(','):
                        current_fs.protocols.append(p.strip())
                continue

            m = re.search('@protocol\s+(?P<proto>[^<>;\s]\w+).*', line)
            if m:
                current_fs = Frameworks.get_proto(m.group('proto'))
                continue

            if line.startswith('@end'):
                current_fs = None

            if line.startswith(('+', '-')):
                line = Frameworks.refine_line(line)
                m = re.match('[+-] \((?P<ret>[^:]+)\)(?P<sel>.+)', line)
                if m:
                    ret = m.group('ret')
                    sel = m.group('sel')
                    _sel = []
                    _args = []
                    if ':' in sel:
                        for item in re.findall('(?P<meth>[^:\s]+):\((?P<type>[^:]+)\)', sel):
                            _sel.append(item[0])
                            _args.append(item[1])
                        sel = ":".join(_sel) + ':'
                    types = [ret, ] + _args
                    current_fs.methods[sel] = types
                    continue

            if line.startswith('@property'):
                line = line.split(';')[0]
                for word in stop_words:
                    if word in line:
                        line = line.split(word)[0].strip()
                m = re.match('@property\s*\((?P<attr>.+)\)\s+(?P<rest>.+)', line)
                if m:
                    rest = m.group('rest').split()
                    prop = {
                        'type': rest[0],
                        'name': rest[-1],
                        'proto': rest[1] if len(rest) == 3 else None
                    }
                    current_fs.props[prop['name']] = prop['type']
                continue

    @staticmethod
    def build_from_dir(dir):
        for f in os.listdir(dir):
            Frameworks.build_from_file(os.path.join(dir, f))
        Frameworks.build_sel_dict()

    @staticmethod
    def refine_line(line):
        line = line.split(';')[0]
        words = line.split()
        for word in words:
            for sw in stop_words:
                if sw in word:
                    words = words[:words.index(word)]
                    return ' '.join(words)
        return line

    @staticmethod
    def dump():
        f = open(r'E:\0_share\experiments\IDA\analysis\tools\FrameworkHeaders.pkl', 'wb')
        pickle.dump([Frameworks.cls_dict, Frameworks.proto_dict], f)
        f.close()

# ------------------------------- Mach-O---------------------------------------------------------


class MachO:
    funcs_index_by_sel = dict()
    funcs_index_by_rec = dict()

    subroutines = []
    oc_methods = []

    funcs_need_calc = []  # calc the ret value (oc method)
    func_with_no_args = []

    func_data = dict()
    updated_func_ret = dict()
    updated_func_args = dict()
    bss_data = dict()

    def __init__(self):
        pass

    @staticmethod
    def build():
        seg = ida_segment.get_segm_by_name('__text')
        for f in Functions(start=seg.startEA, end=seg.endEA):
            name = GetFunctionName(f)
            CG.sharedCG.add_node(f, name)
            if name[0] in ['-', '+']:
                MachO.oc_methods.append(f)
            elif name.startswith('sub_'):
                MachO.subroutines.append(f)

            func_type = MachO.get_func_type(f)
            # may fail to get func_type (func_type may be complicated, leave it alone for the moment)
            if func_type:
                MachO.func_data[f] = func_type
                if f in MachO.oc_methods:
                    cls, sel = name[1:].strip('[]').split()
                    rec = func_type[0].type.__str__()
                    MachO.add(rec, sel, f)

                    if len(func_type) == 2:
                        MachO.func_with_no_args.append(f)

                    ret_type = func_type.rettype.__str__()
                    if ret_type == 'id' and cls in OCClass.cls_dict:  # TODO category
                        if not OCClass.cls_dict[cls].is_method_a_getter(sel, f):
                            MachO.funcs_need_calc.append(f)

        seg = ida_segment.get_segm_by_name('__stubs')
        for f in Functions(start=seg.startEA, end=seg.endEA):
            name = GetFunctionName(f)
            if name in cdecls:
                print 'change the cdecl, ', name
                ida_typeinf.apply_cdecl(idaapi.til_t(), f, cdecls[name])

    @staticmethod
    def query_ivar(base, offset):
        if type(offset) is long and type(base) is str:
            offset *= 8
            if MachO.is_rec_decidable(base):
                cls = OCClass.cls_dict[Utils.nice_str(base)]
                if offset in cls.ivars:
                    return cls.ivars[offset]

    @staticmethod
    def get_func_type(f_start):
        tif = ida_typeinf.tinfo_t()
        idaapi.get_tinfo2(f_start, tif)
        funcdata = idaapi.func_type_data_t()
        got_data = tif.get_func_details(funcdata)
        if got_data:
            return funcdata
        else:
            return None

    @staticmethod
    def add(rec, sel, f):
        if rec not in MachO.funcs_index_by_rec:
            MachO.funcs_index_by_rec[rec] = {sel: f}
        else:
            MachO.funcs_index_by_rec[rec][sel] = f

        if sel not in MachO.funcs_index_by_sel:
            MachO.funcs_index_by_sel[sel] = {rec: f}
        else:
            MachO.funcs_index_by_sel[sel][rec] = f

    @staticmethod
    def query_msg_handler(sel, rec):
        # rec is decidable, # name * or name_meta *
        # return target, ret_type
        pretty_rec = Utils.nice_str(rec)
        if pretty_rec in OCClass.cls_dict:
            if rec in MachO.funcs_index_by_rec and sel in MachO.funcs_index_by_rec[rec]:
                return MachO.funcs_index_by_rec[rec][sel], None
            else:
                # send to the rec's super (NSObject mostly)
                super = OCClass.get_super(pretty_rec)
                super = rec.replace(pretty_rec, super) if super in OCClass.cls_dict else super
                if super:
                    return MachO.query_msg_handler(sel, super)
                else:
                    return None, None
        elif pretty_rec in Frameworks.cls_dict:
            return None, Frameworks.cls_dict[pretty_rec].respond_to_sel(sel)
        else:
            return None, None

    @staticmethod
    def update_func_data_and_analyze(fi, args, frm=None, a=None):
        # 按理说，如果fi已经完成分析，那么更新func_data是没有意义的
        if fi in Func.pool:
            return
        MachO.update_func_data(fi, args, frm=frm, a=a)
        Func.analyze(fi)

    @staticmethod
    def update_func_data(fi, args, frm=None, a=None):
        # 所有的func_data更新都在这里发生，包括Block类型的参数。但具体的block数据需要与caller的调用信息对应起来
        # 根据frm（oc_method以及subroutine都会传入frm），可以查询到frm（callsite）处是否使用了block以及具体使用的block
        # 因为仅仅根据arg的类型只能判断该对象为block，却无法获知block的数据。
        new_func_type = []  # 0L表示不对原参数类型做变动
        if fi in MachO.oc_methods:
            new_func_type = [0L, 0L]  # 前两个参数为rec、sel，不用做变动

        for idx in range(0, len(args)):
            arg = args[idx]
            new_type = arg.tif.__str__() if type(arg) is ida_hexrays.lvar_t else arg
            if type(new_type) is str:
                if MachO.is_rec_decidable(new_type):
                    pass
                elif 'NSConcrete' in new_type and frm:
                    block = Block.usage[(frm, idx)] if (frm, idx) in Block.usage else None
                    if block:
                        pass  # todo
            else:
                new_type = 0L  # 暂时不支持该参数的类型更新
            new_func_type.append(new_type)
        if len(set(new_func_type)) == 1 and 0L in new_func_type:
            pass
        else:
            print 'UPDATE {} from {}: {}'.format(fi, frm, new_func_type)
        MachO.updated_func_args[fi] = new_func_type

    @staticmethod
    def guess(sel, rec=None):
        # rec could be None or invalid: void * , id, ...
        # return target, ret_type, inferred_rec
        first_attempt = Frameworks.cls_dict['NSProxy'].respond_to_sel(sel)
        if first_attempt:
            return None, first_attempt, None
        second_attempt = Frameworks.cls_dict['NSObject'].respond_to_sel(sel)
        if second_attempt:
            return None, second_attempt, None

        if rec and rec != 'id' and 'void *' not in rec and 'struct' not in rec:
            third_attempt = Frameworks.cls_dict['NSString'].respond_to_sel(sel)
            if third_attempt:
                return None, third_attempt, 'NSString'

        if sel in MachO.funcs_index_by_sel and sel not in Frameworks.sel_dict:
            fuzzy_cls = MachO.funcs_index_by_sel[sel]
            if len(fuzzy_cls) == 1:
                inferred_rec = fuzzy_cls.keys()[0]
                target = fuzzy_cls[inferred_rec]
                return target, None, inferred_rec

        if sel not in MachO.funcs_index_by_sel and sel in Frameworks.sel_dict:
            fuzzy = Frameworks.sel_dict[sel]
            if len(fuzzy) == 1:
                cls = list(fuzzy)[0]
                return None, cls.respond_to_sel(sel), cls.name
            fuzzy_ret = set()
            for cls in fuzzy:
                fuzzy_ret.add(cls.respond_to_sel(sel))
            if len(fuzzy_ret) == 1:
                return None, fuzzy_ret.pop(), None  # fuzzy_ret.pop() may be None

        return None, None, None

    @staticmethod
    def query_ret(call, ea=None):
        ret_type = None
        if ea:  # OC method
            if ea in MachO.funcs_need_calc:
                if ea in MachO.updated_func_ret:
                    ret_type = MachO.updated_func_ret[ea]
                else:
                    Func.analyze(ea)
                    ret_type = MachO.updated_func_ret[ea] if ea in MachO.updated_func_ret else MachO.query_ori_func_data(ea)
            else:
                ret_type = MachO.query_ori_func_data(ea)
        else:  # C method, such as _NSStringFromClass
            pass
        return ret_type

    @staticmethod
    def query_ori_func_data(ea):
        if ea and ea in MachO.func_data:
            return MachO.func_data[ea].rettype.__str__()

    @staticmethod
    def query_bss(data_ea):
        if data_ea not in MachO.bss_data:
            stores = []
            for xref in XrefsTo(data_ea):
                if idc.GetMnem(xref.frm) == 'STR':
                    stores.append(xref.frm)
            for def_ea in stores:
                f = Func.analyze(idaapi.get_func(def_ea).startEA)
                if data_ea in MachO.bss_data:  # 在上述解析过程中通过赋值语句获得bss_data
                    break
                else:
                    # val = f.resolve_def(def_ea=def_ea)
                    val = f.def_analysis(def_ea, idc.GetOpnd(def_ea, 0))
                    if val:
                        MachO.bss_data[data_ea] = val
                        break
            if data_ea not in MachO.bss_data:  # 如果通过解析仍然没有获得bss_data的值，那么返回
                MachO.bss_data[data_ea] = idc.Name(data_ea) or 'id'
        return MachO.bss_data[data_ea]

    @staticmethod
    def is_rec_decidable(rec_type):
        if rec_type:
            nice_str = Utils.nice_str(rec_type)
            if nice_str in OCClass.cls_dict:
                return True
            if nice_str in Frameworks.cls_dict:
                return True
        return False

# -----------------------------Protocol----------------------------------------------------

class Protocol:
    pool = dict()
    prot_dict = dict()

    def __init__(self, data_ea):
        self.ea = data_ea  # ea in __data
        self.name = idc.get_bytes(idc.Qword(self.ea + 0x8), idc.get_item_size(idc.Qword(self.ea + 0x8)) - 1)
        self.classes = []
        self.prots = []
        self.meths = {}

        prots = ida_bytes.get_qword(self.ea + 0x10)
        if prots:
            count = ida_bytes.get_qword(prots)
            entrysize = 0x8
            p_ea = prots + 8
            for i in range(count):
                proto_ea = idc.get_qword(p_ea)
                self.prots.append(proto_ea)
                p_ea += entrysize

        type_info = ida_bytes.get_qword(self.ea + 0x48)
        for idx in range(0, 4):
            # 0: inst_meths
            # 1: class_meths
            # 2: opt_inst_meths
            # 3: opt_class_meths
            meth_list = ida_bytes.get_qword(self.ea + 0x18 + idx*8)
            if meth_list:
                entrysize = ida_bytes.get_dword(meth_list)
                count = ida_bytes.get_dword(meth_list+4)
                ea = meth_list + 8
                for i in range(0, count):
                    sel = idc.get_bytes(idc.Qword(ea), idc.get_item_size(idc.Qword(ea)) - 1)
                    meth_type = idc.get_bytes(idc.Qword(type_info), idc.get_item_size(idc.Qword(type_info)) - 1)
                    self.meths[sel] = meth_type
                    ea += entrysize
                    type_info += 8

        if self.ea not in Protocol.pool:
            Protocol.pool[self.ea] = self
        if self.name not in Protocol.prot_dict:
            Protocol.prot_dict[self.name] = [self, ]
        else:
            Protocol.prot_dict[self.name].append(self)

    @staticmethod
    def build():
        seg = ida_segment.get_segm_by_name('__objc_protolist')
        for ea in range(seg.startEA, seg.endEA, 8):
            Protocol(ida_bytes.get_qword(ea))

    @staticmethod
    def add_class(p, c):
        if p in Protocol.pool:
            Protocol.pool[p].classes.append(c)

# -----------------------------OCClass-----------------------------------------------------

class OCClass:
    cls_dict = dict()
    pool = dict()

    def __init__(self, ea):
        # ea: objc_data address
        self.ea = ea
        self.info = ida_bytes.get_qword(ea + 0x20)
        # idc.Name(self.superclass): _OBJC_METACLASS_$_UIView
        self.superclass = ida_bytes.get_qword(ida_bytes.get_qword(ea) + 0x08)
        self.name = idc.get_bytes(idc.Qword(self.info + 0x18), idc.get_item_size(idc.Qword(self.info + 0x18)) - 1)
        self.classref = None
        self.superref = None
        self.prots = []
        self.ivars = dict()

        for xref in XrefsTo(ea):
            frm = xref.frm
            if idc.SegName(frm) == '__objc_classrefs':
                self.classref = frm
            if idc.SegName(frm) == '__objc_superrefs':
                self.superref = frm

        base_ivars = ida_bytes.get_qword(self.info + 0x30)
        if base_ivars and idc.SegName(base_ivars) == '__objc_const':
            entrysize = ida_bytes.get_dword(base_ivars)
            count = ida_bytes.get_dword(base_ivars + 4)
            ea = base_ivars + 8
            for i in range(count):
                offset = ida_bytes.get_dword(idc.get_qword(ea))
                _type = idc.get_bytes(idc.Qword(ea + 0X10), idc.get_item_size(idc.Qword(ea + 0X10)) - 1)
                self.ivars[offset] = _type
                # print offset, _type, self.name
                ea += entrysize

        base_prots = ida_bytes.get_qword(self.info + 0x28)
        if base_prots and idc.SegName(base_prots) == '__objc_const':
            count = ida_bytes.get_qword(base_prots)
            entrysize = 0x8
            p_ea = base_prots + 8
            for i in range(count):
                proto_ea = idc.get_qword(p_ea)
                self.prots.append(proto_ea)
                Protocol.add_class(proto_ea, self.ea)
                p_ea += entrysize

        if self.name not in OCClass.cls_dict:
            OCClass.cls_dict[self.name] = self
        OCClass.pool[self.ea] = self

    def is_method_a_getter(self, sel, f=None):
        base_props = ida_bytes.get_qword(self.info + 0x40)
        if not base_props:
            return False
        entrysize = ida_bytes.get_dword(base_props)
        count = ida_bytes.get_dword(base_props+4)
        p_ea = base_props + 8
        for i in range(count):
            p_name = idc.get_bytes(idc.Qword(p_ea), idc.get_item_size(idc.Qword(p_ea)) - 1)
            if p_name == sel:
                return True
            p_ea += entrysize
        return False

    def get_superclass(self):
        # if idc.SegName(self.superclass) == 'UNDEF':
        if self.superclass:
            name = idc.Name(self.superclass)
            if '_OBJC_METACLASS_$_' in name:
                return name.split('_OBJC_METACLASS_$_')[1]
            elif '_OBJC_CLASS_$_' in name:
                return name.split('_OBJC_CLASS_$_')[1]
        return None

    @staticmethod
    def get_super(cls):
        if cls in OCClass.cls_dict:
            return OCClass.cls_dict[cls].get_superclass()

    def get_class_meths(self):
        rec = '{}_meta *'.format(self.name)
        if rec in MachO.funcs_index_by_rec:
            return MachO.funcs_index_by_rec[rec]
        else:
            return {}

    def get_instance_meths(self):
        rec = '{} *'.format(self.name)
        if rec in MachO.funcs_index_by_rec:
            return MachO.funcs_index_by_rec[rec]
        else:
            return {}

    @staticmethod
    def build():
        seg = ida_segment.get_segm_by_name('__objc_classlist')
        for class_ea in range(seg.startEA, seg.endEA, 8):
            objc_data = ida_bytes.get_qword(class_ea)
            cls = OCClass(objc_data)


# -----------------------------Block------------------------------------------------


class Block:
    ignore_dispatch_calls = ['_dispatch_get_global_queue', '_dispatch_semaphore_create',
                             '_dispatch_semaphore_wait', '_dispatch_semaphore_signal',
                             '_dispatch_time']

    pool = dict()  # {block_func_ptr: block}
    usage = dict()  # {callsite: block which is used as the argument of the call at this callsite}

    def __init__(self, ea, args, vars, frm_func=None):
        self.start_ea = ea
        self.args = args
        self.vars = vars
        self.frm_func =frm_func
        if ea not in Block.pool:
            Block.pool[ea] = self

    @staticmethod
    def handle(callsite, call_type, call, args, f):
        # if call_type is GCD, connect callsite and subroutine, this is a dispatch* call
        # if call_type is MSG, the block might be a complete handler
        if call in Block.ignore_dispatch_calls:
            return None

        lvars_t = f.cfunc_t.get_lvars()
        subroutine = None
        block_args = []
        block_vars = []
        # start = 0 if call_type == 'GCD' else 2

        for idx in range(0, len(args)):
            arg = args[idx]
            if type(arg) is long and idc.Name(idc.Qword(arg)) == '__NSConcreteGlobalBlock':
                subroutine = idc.Qword(arg + 0x10)
            elif type(arg) is ida_hexrays.lvar_t and arg.tif.__str__() == 'NSConcreteStackBlock **':
                try:
                    base = arg.location.stkoff()
                    subroutine_var = lvars_t[lvars_t.find_stkvar(base + 0x10, 64)]
                    defea = subroutine_var.defea / 4 * 4
                    subroutine = f.cfunc_t.eamap[defea][0].details.y.obj_ea if subroutine_var.is_stk_var() else None
                    for idx in range(0, 3):
                        stkoff = base + 0x20 + idx*8
                        if lvars_t.find_stkvar(stkoff, 64) != -1:
                            block_arg = lvars_t[lvars_t.find_stkvar(stkoff, 64)]
                            if type(block_arg) is ida_hexrays.lvar_t:
                                block_vars.append(block_arg)
                                block_args.append(block_arg.tif.__str__())
                                block_args.append(f.get_var_type(block_arg))
                        # TODO v27 = *(_QWORD *)(v4 + 32); sub_10000E1A0, CPUDasher
                except Exception as e:
                    print 'FAIL TO RESOLVE BLOCK', hex(callsite), call
                    return None
            elif type(arg) is str and arg.startswith('sub_'):  # dispatch_once_f
                try:
                    subroutine = int(arg.split('sub_')[1], 16)
                    break
                except Exception as e:
                    pass

            if subroutine in MachO.subroutines:
                block = Block(subroutine, block_args, block_vars, frm_func=f)
                if call_type == 'GCD':
                    CG.sharedCG.add_edge(ida_funcs.get_func(callsite).startEA, subroutine, callsite, 'GCD', block=block)
                else:
                    Block.usage[(callsite, idx)] = block
                f = Func.analyze(subroutine)

        return subroutine

    @staticmethod
    def update_var_tif_if_needed(var, cfunc_t):
        try:
            if var.tif.__str__() == 'void **':
                if var.is_stk_var():
                    defea = var.defea / 4 * 4
                    obj = idc.Name(cfunc_t.eamap[defea][0].details.y.obj_ea)
                    if obj == '__NSConcreteStackBlock':
                        var.tif = ida_hexrays.create_typedef('NSConcreteStackBlock **')
                    elif obj == '__NSConcreteGlobalBlock':
                        print 'CHECK 323, ', hex(cfunc_t.entry_ea)
                        var.tif = ida_hexrays.create_typedef('NSConcreteGlobalBlock **')
        except Exception as e:
            pass


class CCall:

    def __init__(self, f, callsite, call, args=[]):
        self.f = f  # Func instance
        self.callsite = callsite
        self.call = call
        self.ctx = ida_funcs.get_func(self.callsite).startEA
        self.a = args
        self.cargs = f.resolve_args(args, 0, callsite, 'arg')
        self.details = ''

# ------------------------Message --------------------------------------------------


class Message:

    def __init__(self, f, callsite, call, rec=None, sel=None, args=[]):
        self.f = f  # Func instance
        self.callsite = callsite
        self.call = call
        self.ctx = ida_funcs.get_func(self.callsite).startEA
        self.a = args
        self.cargs = f.resolve_args(args, 0, callsite, 'arg')

        if len(self.cargs) > 1:
            self.rec = rec or self.cargs[0]
            self.sel = sel or self.cargs[1]
            self.args = self.cargs[2:]
        else:
            self.rec = None
            self.sel = None
            self.args = []
            print 'ERROR 789,', hex(callsite)

        self.details = ''

    def resolve_sel_succeed(self):
        if type(self.sel) is ida_hexrays.lvar_t:
            self.sel = self.f.get_var_type(self.sel) or self.f.def_analysis(self.callsite, 'X1')
        if not self.sel or type(self.sel) is not str:
            print 'unidentified sel ', hex(self.callsite), self.sel
            return False

        if self.sel.startswith('performSelector:onTarget:'):
            pass  # TODO CASE 6
        elif self.sel.startswith('performSelector') and self.args:
            virtual_sel = self.args[0]
            if type(virtual_sel) is str:
                self.sel = virtual_sel
            elif type(virtual_sel) is ida_hexrays.lvar_t:
                self.sel = self.f.get_var_type(virtual_sel)
            else:
                print 'unidentified sel ', hex(self.callsite), virtual_sel
                return False
            self.details += ';nestedMSG_1'
            self.args = []  # TODO to avoid conflict with args used in Mach.update_func_data
        else:
            Block.handle(self.callsite, 'MSG', self.call, self.args, self.f)
        return True

    def resolve_rec(self):
        rec_type = None
        if type(self.rec) is str:
            rec_type = self.rec
        elif type(self.rec) is ida_hexrays.lvar_t:
            rec_type = self.f.get_var_type(self.rec)
        else:
            print 'unidentified rec ', hex(self.callsite), self.rec
        if not MachO.is_rec_decidable(rec_type):
            rec_type = self.f.def_analysis(self.callsite, 'X0') or rec_type

        if MachO.is_rec_decidable(rec_type) and self.call == '_objc_msgSendSuper2':
            if self.sel.startswith('init'):
                return rec_type
            pretty_rec = Utils.nice_str(rec_type)
            super = OCClass.get_super(pretty_rec)
            super = rec_type.replace(pretty_rec, super) if super in OCClass.cls_dict else super
            rec_type = super or rec_type
        return rec_type

    def dynamic_bind(self):
        ret_type, target, msg, rec_type, inferred_rec = None, None, None, None, None
        if not self.resolve_sel_succeed():
            return target, ret_type

        rec_type = self.resolve_rec()
        # print '!!!', rec_type, self.sel, target, ret_type, inferred_rec

        if MachO.is_rec_decidable(rec_type):  # simply query
            target, ret_type = MachO.query_msg_handler(self.sel, rec_type)
        else:  # could be None or invalid: void * , id, ...   we need to guess
            target, ret_type, inferred_rec = MachO.guess(self.sel, rec=rec_type)

        # print '!!!', hex(self.callsite), rec_type, self.sel, target, ret_type, inferred_rec

        if target:
            CG.sharedCG.add_edge(self.ctx, target, self.callsite, 'I_MSG', details=self.details, message=self)
            if inferred_rec and type(self.rec) is ida_hexrays.lvar_t:
                self.rec.tif = ida_hexrays.create_typedef(inferred_rec)
            MachO.update_func_data_and_analyze(target, self.args, frm=self.callsite, a=self.a)
            ret_type = MachO.query_ret(self.call, ea=target)
            return target, ret_type
        else:
            msg_type = None
            rec_type = inferred_rec or rec_type
            if ret_type:
                if MachO.is_rec_decidable(rec_type):
                    msg_type = 'E_MSG'  # framework message
                else:
                    msg_type = 'U_MSG'  # inferred the ret_val according to the sel, but still don't know the receiver.
            else:
                # void * alloc
                if MachO.is_rec_decidable(rec_type):
                    msg_type = 'X_MSG'
                else:
                    msg_type = 'B_MSG'
                    print 'Invalid rec, ', rec_type, self.sel, hex(self.callsite)

            pt_rec = Utils.nice_str(rec_type)
            ret_type = self.analyze_msg(pt_rec) or ret_type

            if msg_type:
                CG.sharedCG.add_edge(self.ctx, '[{} {}]'.format(pt_rec, self.sel), self.callsite, msg_type,
                                     details=self.details, message=self)
        # ret_type adjustment
        if self.sel in ['class', 'init']:
            ret_type = rec_type if MachO.is_rec_decidable(rec_type) else ret_type
        elif self.sel == 'isKindOfClass:':
            ret_type = 'BOOL'
        elif self.sel == 'alloc' and MachO.is_rec_decidable(rec_type):  # the ori ret_type is id
            ret_type = '{} *'.format(rec_type.split('_meta *')[0]) if '_meta *' in rec_type else rec_type

        if ret_type == 'instancetype' and MachO.is_rec_decidable(rec_type):
            ret_type = '{} *'.format(Utils.nice_str(rec_type))
        elif ret_type == 'BOOL':
            ret_type = ret_type.lower()

        return target, ret_type

    def analyze_msg(self, rec_type):
        if not rec_type:
            return None

        # ---------- NSUserDefaults ----------------------------
        if 'NSUserDefaults' in rec_type:
            key, data = None, None
            if self.sel == 'objectForKey:':
                key = self.f.get_var_type(self.args[0]) if type(self.args[0]) is ida_hexrays.lvar_t else self.args[0]
            elif self.sel == 'setObject:forKey:' and len(self.args) > 1:
                data = self.f.get_var_type(self.args[0]) if type(self.args[0]) is ida_hexrays.lvar_t else self.args[0]
                key = self.f.get_var_type(self.args[1]) if type(self.args[1]) is ida_hexrays.lvar_t else self.args[1]
            if key:
                NSUserdefaults.shared.add_invoke(key, self.callsite, data=data)
                if not data:
                    return NSUserdefaults.shared.get_data(key)
            # self.details += '; key_{}'.format(self.args[0] if len(self.args) > 0 else None)

        # ------------NSTimer----------------------------------
        # Add an edge from the callsite to the resolved target.
        # Skip this message if failed to resolve the target.

        # Target is a block
        # if self.sel in execute_block_through_timer and len(self.args) > 0:
        #     if (self.callsite, len(self.args)-1) in Block.usage:
        #         block = Block.usage[(self.callsite, len(self.args)-1)]
        #
        # # Target is a NSInvocation
        # if self.sel in execute_invocation_through_timer and len(self.args) > 1:
        #     invocation = self.args[1]
        #
        # # Target is a message
        # if self.sel in dispatch_msg_in_timer and len(self.args) > 4:
        #     msg = Message(self.callsite, rec=self.args[-4], sel=self.args[-3])
        #     msg.dynamic_bind()
        #
        # # --------------NSNotification-------------------------
        # if self.sel is 'addObserverForName:object:queue:usingBlock:':
        #     block = self.args[3]
        #     NSNotificationCenter.add(self.args[0], block=self.args[-1])
        #     return
        # if self.sel is 'addObserver:selector:name:object:':
        #     msg = Message(self.callsite, rec=self.args[0], sel=self.args[1])
        #     msg.resolve_target()
        #     NSNotificationCenter.add(self.args[2], msg=msg)
        #     return
        # if self.sel is 'postNotificationName:object:userInfo:' or 'postNotificationName:object:':
        #     name = self.args[0]
        # elif self.sel is 'postNotification:':
        #     # TODO
        #     pass
        # target = NSNotificationCenter.retrieve(name)
        #
        # # ------------------NSOperation---------------------------------
        # if self.sel is 'addOperation:' or 'addOperations:waitUntilFinished:':
        #     operation = self.args[0]
        # # TODO: check the type of operation and find target
        # # non-concurrent operations, main method
        #
        # # concurrent operations, start method
        # elif self.sel is 'addOperationWithBlock:':
        #     block = self.args[0]


class NSNotificationCenter:
    dispatch_table = dict()

    def __init__(self):
        pass

    def add(name, block=None, msg=None):
        if name in NSNotificationCenter.dispatch_table:
            NSNotificationCenter.dispatch_table[name].append(block or msg)
        else:
            NSNotificationCenter.dispatch_table[name] = [block or msg]

    def retrieve(name):
        if name in NSNotificationCenter.dispatch_table:
            return NSNotificationCenter.dispatch_table[name]
        else:
            return []

# ---------------------------Task--------------------------------------


class TaskManager:

    def __init__(self):
        self.prepared_pool = []
        TaskManager.init()

    @staticmethod
    def init():
        CG()
        NSUserdefaults()
        # Frameworks.build_from_pkl(r'E:\0_share\experiments\IDA\analysis\tools\FrameworkHeaders.pkl')
        Frameworks.build_from_dir(r'E:\0_share\experiments\IDA\analysis\headers')
        print 'Load FrameworkHeaders.pkl.'
        Protocol.build()
        OCClass.build()
        MachO.build()

    def init_pool(self):
        # UIApplicationDelegate
        if 'UIApplicationDelegate' in Protocol.prot_dict:
            for p in Protocol.prot_dict['UIApplicationDelegate']:
                for c in p.classes:
                    appdelegate = OCClass.pool[c]
                    self.prepared_pool.extend(appdelegate.get_class_meths().values())
                    self.prepared_pool.extend(appdelegate.get_instance_meths().values())
        # init method
        self.prepared_pool.extend(MachO.funcs_index_by_sel['init'].values())
        # other delegate methods (Besides UIApplicationDelegate), one kind of callback
        # all the protocol methods
        for ea, p in Protocol.pool.items():
            cls = []
            for c in p.classes:
                cls.append(OCClass.pool[c].name)
            for sel, func_type in p.meths.items():
                if sel in MachO.funcs_index_by_sel:
                    for rec, f in MachO.funcs_index_by_sel[sel].items():
                        if Utils.nice_str(rec) in cls:
                            args = Utils.meth_type_parser(func_type)[1:]
                            MachO.update_func_data(f, args)
                            self.prepared_pool.append(f)

        self.prepared_pool.extend(MachO.func_with_no_args)

    def analyze_in_sequence(self):
        print 'START: ', time.asctime(time.localtime(time.time()))
        self.init_pool()
        while self.prepared_pool:
            Func.analyze(self.prepared_pool.pop(0))
        for f in Functions():
            if f not in MachO.subroutines:
                Func.analyze(f)
        for f in MachO.subroutines:
            Func.analyze(f)
        print 'END: ', time.asctime(time.localtime(time.time()))

    def _continue(self):
        while self.prepared_pool:
            Func.analyze(self.prepared_pool.pop(0))

    def dump_result(self):
        f = open(r'cg.pkl', 'wb')
        pickle.dump([CG.sharedCG.nodes, CG.sharedCG.edges], f)
        f.close()

# ---------------------------Func--------------------------------------
class lvar_usage:

    def __init__(self, name, ea, idx):
        self.name = name
        self.ea = ea
        self.idx = idx

class Func:
    pool = dict()  # functions which have been analyzed
    decompilation_failed = []
    analyzed_subroutines = []

    def __init__(self, start_ea):
        self.start_ea = start_ea  # cfunc.entry_ea
        self.cfunc_t = None
        self.call_and_ret = dict()
        self.ret = []  # possible return types
        self.ret_vars = []
        self.ret_ea = []
        self.calls = []
        self.asg = dict()  # key: rvalue val: [lvalue, ...]
        self.asg_processed = False
        self.lvars = dict()  # name: [lu]
        self.lvars_used_at_ea = dict()  # ea: [lu]

        if self.start_ea not in Func.pool:
            Func.pool[self.start_ea] = self
        else:
            print 'AGAIN? WHY?'
            Func.pool[self.start_ea] = self

    @staticmethod
    def analyze(f, forced=False):
        if f in Func.pool and not forced:
            return Func.pool[f]
        func = Func(f)
        func.decompile()
        try:
            if func.cfunc_t:
                func.init_state()
                func.resolve_cfunc()
        except Exception as e:
            print '!!!', e
        return func

    def decompile(self):  # wrapper of ida_hexrays.decompile
        try:
            process_arc_calls(self.start_ea)
            self.cfunc_t = ida_hexrays.decompile(self.start_ea)
        except Exception as e:
            Func.decompilation_failed.append(self.start_ea)
            print 'Decompilation Failed: ', hex(self.start_ea), e

    def init_state(self):
        # if self.start_ea in Block.pool:
        #     lvars = self.cfunc_t.get_lvars()
        #     lvars[0].tif = ida_hexrays.create_typedef('NSConcreteStackBlock *')
        if self.start_ea in MachO.updated_func_args:
            new_func_data = MachO.updated_func_args[self.start_ea]
            if len(new_func_data) != len(self.cfunc_t.arguments):
                print 'WRONG FUNC DATA INFO', hex(self.start_ea)

            for idx in range(0, len(self.cfunc_t.arguments)):
                if idx < len(new_func_data) and new_func_data[idx]:
                    self.cfunc_t.arguments[idx].tif = ida_hexrays.create_typedef(new_func_data[idx])

    def resolve_cfunc(self):
        if not self.cfunc_t:
            return
        if not len(self.cfunc_t.treeitems):
            self.cfunc_t.get_pseudocode()

        for item in self.cfunc_t.treeitems:
            op_code = item.cexpr.op
            if op_code != 57:  # call
                continue
            ret_type = self.process_call(item.ea, item.cexpr)
            if type(ret_type) is ida_hexrays.lvar_t:
                ret_type = self.get_var_type(ret_type)
                print 'WHY', hex(item.ea)
            self.call_and_ret[item.ea] = ret_type
            self.process_item(item, _type=ret_type)

        for item in self.cfunc_t.treeitems:
            op_code = item.cexpr.op
            if op_code == 80:
                self.process_ret(item.cexpr)

        for t in ['id', 'void *']:
            if t in self.ret:
                self.ret.remove(t)

        # update Mach-O data
        if self.start_ea in MachO.funcs_need_calc and self.ret:
            rets = set(self.ret)
            rets.discard(None)
            if rets:
                if len(rets) == 1:
                    pass
                else:
                    print 'ERROR 454, ', hex(self.start_ea), rets
                MachO.updated_func_ret[self.start_ea] = rets.pop()
            else:
                pass  # failed to calc the ret type

    def process_item(self, item, _type=None):
        p = self.cfunc_t.body.find_parent_of(item)
        if p.op == 2:  # asg expr
            self.process_asg(p.cexpr, _type)
        elif p.op == 48:  # cast expr
            cast_type = item.cexpr.type.__str__()  # struct objc_object *, id, ...
            self.process_item(p, _type=_type or cast_type)
        elif p.op == 80:  # return insn
            self.process_ret(p.cexpr, _type=_type)
        elif p.op == 72:  # cexpr
            pass
        elif p.op == 73:  # if
            pass
        else:
            if p.op in ERROR:
                ERROR[p.op].append(p.ea)
            else:
                ERROR[p.op] = [p.ea, ]

    def process_asg(self, cexpr, _type):
        if not _type or _type in USELESS_TYPES:
            return
        lvalue = cexpr.x
        rvalue = cexpr.y
        if lvalue.opname == 'var':
            lvalue = self.resolve_var(lvalue.v)
            if 'tif' in dir(lvalue) and lvalue.tif.__str__() != _type:
                lvalue.tif = ida_hexrays.create_typedef(_type)
                rvalue.tif = ida_hexrays.create_typedef(_type)
        elif lvalue.opname == 'obj':
            if idc.SegName(lvalue.obj_ea) in ['__bss', '__common']:
                if lvalue.obj_ea not in MachO.bss_data:
                    MachO.bss_data[lvalue.obj_ea] = _type
            else:
                print 'TODO case 4', hex(cexpr.ea)
        else:
            if lvalue.opname == 'memptr':
                memptr.append(cexpr.ea)
            else:
                print 'lvalue, ', lvalue.opname, hex(cexpr.ea)

    def process_ret(self, cexpr, _type=None):
        self.ret_ea.append(cexpr.ea)
        if _type:
            self.ret.append(_type)
        else:
            if cexpr.op == 65:  # var
                var = self.resolve_var(cexpr.v)
                self.ret_vars.append(var.name)
                self.ret.append(var.tif.__str__())

    def process_call(self, ea, cexpr_t):
        callee = None
        if cexpr_t.x.opname == 'cast':  # the func_type is cast
            callee = cexpr_t.x.x.obj_ea
        elif cexpr_t.x.opname == 'obj':
            callee = cexpr_t.x.obj_ea
        elif cexpr_t.x.opname == 'helper':
            helper.append(ea)
        elif cexpr_t.x.opname in ['ptr', 'idx']:
            blr.append(ea)
        else:
            print 'ERROR 4: the first operand of call is : ', cexpr_t.x.opname, hex(ea)

        if not callee:
            return None
        call = self.resolve_obj(callee)
        if not call or type(call) is not str:
            print 'ERROR 20:', hex(ea), callee
            return

        ret_type = None
        target = None
        if call.startswith('_objc_msgSend'):
            target, ret_type = Message(self, ea, call, args=cexpr_t.a).dynamic_bind()
        elif call.startswith('_dispatch'):
            target = Block.handle(ea, 'GCD', call, self.resolve_args(cexpr_t.a, 0, ea, 'GCD'), self)
        elif call in arc_calls_as_nop:
            CG.sharedCG.add_edge(self.start_ea, callee, ea, 'C', ccall=CCall(self, ea, call, args=cexpr_t.a))
            if cexpr_t.a:
                ret_type = self.resolve_cexpr(cexpr_t.a[0], ea, usage='arc', ret_type=True)
            else:
                miss_arg[ea] = call
        elif call.startswith('loc_'):
            pass
        elif callee in MachO.subroutines:
            args = self.resolve_args(cexpr_t.a, 0, ea, 'sub')
            target = Block.handle(ea, 'SUB', call, args, self)
            MachO.update_func_data_and_analyze(callee, args, frm=ea)
            CG.sharedCG.add_edge(self.start_ea, callee, ea, 'C', ccall=CCall(self, ea, call, args=cexpr_t.a))
        else:
            if call[0] in ['-', '+']:
                msg = Message(self, ea, call, args=cexpr_t.a)
                CG.sharedCG.add_edge(self.start_ea, callee, ea, 'MSG', message=msg)
                MachO.update_func_data_and_analyze(callee, self.resolve_args(cexpr_t.a, 2, ea, 'arg'), frm=ea, a=cexpr_t.a)
                ret_type = MachO.query_ret(call, ea=callee)
            else:
                CG.sharedCG.add_edge(self.start_ea, callee, ea, 'C', ccall=CCall(self, ea, call, args=cexpr_t.a))
                # ret_type = MachO.query_ret(call, ea=callee)
        # if target:
        #     ida_xref.add_cref(ea, target, ida_xref.XREF_USER)
        return ret_type

    def resolve_cexpr(self, cexpr_t, ea, usage=None, ret_type=False):
        if cexpr_t.opname == 'cast':
            ori_type = cexpr_t.x.type.__str__()
            # cast_type = cexpr_t.type.__str__()
            if ori_type not in USELESS_TYPES:
                return ori_type
            return self.resolve_cexpr(cexpr_t.x, ea, usage=usage, ret_type=ret_type)
        if cexpr_t.v:
            var = self.resolve_var(cexpr_t.v)
            return self.get_var_type(var) if ret_type else var
        if cexpr_t.obj_ea and cexpr_t.obj_ea != INVALID_EA:
            return self.resolve_obj(cexpr_t.obj_ea)  # ret str or long
        if cexpr_t.n:
            return cexpr_t.n._value
        if cexpr_t.opname == 'ref':
            # (GrayCtl_meta *)&OBJC_CLASS___GrayCtl: obj
            # &var: var
            referenced_obj = self.resolve_cexpr(cexpr_t.x, ea, usage=usage, ret_type=ret_type)
            return referenced_obj
        if cexpr_t.opname == 'ptr':
            # *(void **)(v4 + 32)；*(struct objc_object **)(a1 + 32)
            # obj_address = self.resolve_arg(carg_t.x, ea, idx, usage=usage, ret_type=ret_type)
            if cexpr_t.x.opname == 'cast' and cexpr_t.x.x.opname == 'add':
                return self.resolve_block_var(cexpr_t.x.x)
            # *((_QWORD *)v6 + 5)
            if cexpr_t.x.opname == 'add':
                x = self.resolve_cexpr(cexpr_t.x.x, ea, ret_type=True)
                y = self.resolve_cexpr(cexpr_t.x.y, ea)
                ivar = MachO.query_ivar(x, y)
                return Utils.pprint_type(ivar) if ivar else 'id'
            else:
                return  #todo
        if cexpr_t.opname == 'idx':
            base = self.resolve_cexpr(cexpr_t.x, ea, ret_type=True)
            offset = self.resolve_cexpr(cexpr_t.y, ea)
            ivar = MachO.query_ivar(base, offset)
            return Utils.pprint_type(ivar) if ivar else None

        if cexpr_t.opname == 'memptr':  # (void *)v5->_locationManager
            return cexpr_t.type.__str__()
         # TODO CASE 5

    def resolve_def(self, var, def_list=None):
        def_list = def_list or []
        defea = var.defea / 4 * 4
        if defea in def_list or defea not in self.cfunc_t.eamap:
            return
        def_list.append(defea)
        def_ins = self.cfunc_t.eamap[defea][0]
        if def_ins.op is idaapi.cit_expr and 'y' in def_ins.details.operands:
            def_expr_y = def_ins.details.y
            rvalue = self.resolve_cexpr(def_expr_y, defea, usage='def_y')
            if type(rvalue) is ida_hexrays.lvar_t:
                var_type = rvalue.tif.__str__()
                if var_type not in USELESS_TYPES:
                    return var_type
                return self.resolve_def(var=rvalue, def_list=def_list)
            elif type(rvalue) in [long, int]:
                print 'DEF ANALYSIS TEST: ', hex(defea)
            else:
                return rvalue

    def def_analysis(self, start, target_label):
        f_start = idc.get_func_attr(start, idc.FUNCATTR_START)
        f_end = idc.get_func_attr(start, idc.FUNCATTR_END)

        curr_ea = start
        target = target_label

        while curr_ea != idc.BADADDR:
            mnem = idc.GetMnem(curr_ea)
            if mnem == "MOV" or mnem == "LDR":
                if idc.GetOpnd(curr_ea, 0) == target:
                    src = idc.GetOpnd(curr_ea, 1)  # get_operand_value
                    m = re.search('.+#selRef_(?P<sel>.+)@PAGEOFF]', src)
                    if m:
                        sel = m.group('sel').replace('_', ':')
                        return sel
                    m = re.search('.+#classRef_(?P<rec>.+)@PAGEOFF]', src)
                    if m:
                        rec = m.group('rec')
                        return "{}_meta *".format(rec)
                    target = src
            elif mnem == 'BL' and target == 'X0':
                return self.query_ret_at_callsite(curr_ea)
            elif mnem == 'STR':
                if idc.GetOpnd(curr_ea, 1) == target:
                    target = idc.GetOpnd(curr_ea, 0)
            curr_ea = idc.prev_head(curr_ea, f_start)

    def query_ret_at_callsite(self, ea):
        if ea in self.call_and_ret:
            return self.call_and_ret[ea]
        return None

    def resolve_var(self, var_ref_t, _type=None):
        var = self.cfunc_t.get_lvars()[var_ref_t.idx]
        Block.update_var_tif_if_needed(var, self.cfunc_t)
        return var

    def get_var_type(self, var):
        # RETURN TYPE STR
        var_type = var.tif.__str__()
        if var_type not in USELESS_TYPES:
            return var_type
        else:
            return self.resolve_def(var=var) or var_type

    def resolve_obj(self, obj_ea):
        # ret str or long
        segName = idc.SegName(obj_ea)
        if segName == '__stubs':
            return idc.Name(obj_ea)
        elif segName == '__objc_methname':
            return idc.get_bytes(obj_ea, idc.get_item_size(obj_ea) - 1)
        elif segName == '__text':  # code ref
            return idc.GetFunctionName(obj_ea) or idc.Name(obj_ea)
        elif segName == 'UNDEF':
            return "{}_meta *".format(idc.Name(obj_ea).split('_OBJC_CLASS_$_')[-1])
        elif segName == '__cfstring':
            return idc.get_bytes(idc.Qword(obj_ea + 0x10), idc.Qword(obj_ea + 0x18))
        elif segName == '__objc_data':
            return "{}_meta *".format(idc.Name(obj_ea).split('_OBJC_CLASS_$_')[-1])
        elif segName == '__const':
            return obj_ea
        elif segName in ['__bss', '__common']:
            return MachO.query_bss(obj_ea) or 'id'  # TODO  or return id?

    def resolve_args(self, args, start, callsite, type):
        ret = []
        for idx in range(start, len(args)):
            ret.append(self.resolve_cexpr(args[idx], callsite, type))
        return ret

    def resolve_block_var(self, cexpr):
        # cexpr.opname == 'add'
        if self.start_ea in Block.pool:
            if cexpr.x.opname == 'var' and cexpr.y.opname == 'num':
                # TODO check if the var is the first arg
                stkoff = cexpr.y.n._value
                if stkoff % 8 == 0 and stkoff > 31:
                    idx = (stkoff - 32) / 8
                    return Block.pool[self.start_ea].args[idx] if len(Block.pool[self.start_ea].args) > idx else None

    def resolve_memptr(self, ptr):
        obj = None
        offset = None
        if ptr.x:
            if ptr.x.v:
                obj = self.cfunc_t.lvars[ptr.x.v.idx].name
        if ptr.m:
            offset = ptr.m  # TODO
        return obj

    def strip_cexpr(self, cexpr, ops=None):
        ops = ops or []
        if cexpr.opname == 'ptr':
            return self.strip_cexpr(cexpr.x, ops.append('ptr'))
        elif cexpr.opname == 'cast':
            _type = cexpr.type
            return self.strip_cexpr(cexpr.x, ops.append('cast'))
        elif cexpr.opname == 'idx':
            pass

        return cexpr, ops

    def process_asg_in_ctree(self, forced=False):
        if forced or not self.asg_processed:
            self.asg_processed = True

            if not len(self.cfunc_t.treeitems):
                self.cfunc_t.get_pseudocode()

            for item in self.cfunc_t.treeitems:
                op_code = item.cexpr.op
                if op_code != 2:  # asg
                    continue
                lvalue, rvalue = None, None
                if item.cexpr.x.v:
                    lvalue = self.cfunc_t.get_lvars()[item.cexpr.x.v.idx].name
                elif item.cexpr.x.opname == 'memptr':
                    obj = self.resolve_memptr(item.cexpr.x)
                    if obj:
                        lvalue = obj

                if item.cexpr.y.v:
                    rvalue = self.cfunc_t.get_lvars()[item.cexpr.y.v.idx].name
                inner_cexpr, ops = self.strip_cexpr(item.cexpr.y)
                if inner_cexpr.opname == 'add':
                    if self.resolve_block_var(inner_cexpr):
                        rvalue = 'a1'  # need to be more accurate.
                elif inner_cexpr.opname == 'memptr':
                    obj = self.resolve_memptr(inner_cexpr)
                    if obj:
                        rvalue = obj

                if lvalue and rvalue:
                    # print lvalue, rvalue
                    self.asg[rvalue] = self.asg[rvalue] + [lvalue, ] if rvalue in self.asg else [lvalue, ]

    def add_lvar_usage(self, lu):
        if lu.name in self.lvars:
            self.lvars[lu.name].append(lu)
        else:
            self.lvars[lu.name] = [lu, ]

        if lu.ea in self.lvars_used_at_ea:
            self.lvars_used_at_ea[lu.ea].append(lu)
        else:
            self.lvars_used_at_ea[lu.ea] = [lu, ]

    def track_data(self, ea_list, idx_list=None):
        # track the ret value of the call at ea
        src_list = []
        if ea_list[0] == self.start_ea and idx_list:  # taint the arguments
            if self.start_ea in MachO.subroutines:
                # TODO, only taint block for the moment.
                src_list.append(self.cfunc_t.lvars[0].name)
            else:
                for idx in idx_list:
                    src_list.append(self.cfunc_t.lvars[idx].name)
        if ea_list[0] != self.start_ea:
            for ea in ea_list:
                # mark the ret
                lvalue = self.find_lvalue_at_ea(ea)
                if lvalue:
                    src_list.append(lvalue)
                # mark the parameters at callsites
                if idx_list and ea in self.lvars_used_at_ea:
                    for lu in self.lvars_used_at_ea[ea]:
                        if lu.idx in idx_list:
                            src_list.append(lu.name)
        if src_list:
            tainted = set(src_list)
            current_tainted = set(src_list)
            while current_tainted:
                tainted.update(current_tainted)
                new_tainted = set()
                for var in current_tainted:
                    for nv in self.find_new_tainted(var):
                        if nv not in tainted:
                            new_tainted.add(nv)
                current_tainted = new_tainted
                # current_tainted = set()
                # for var in new_tainted:
                #     current_tainted.add(var)
                #     if var in self.asg:
                #         for lvalue in self.asg[var]:
                #             if lvalue not in tainted:
                #                 current_tainted.add(lvalue)
            return tainted
        # clear self.lvars

    def find_lvalue_at_ea(self, ea):
        if ea in self.lvars_used_at_ea:
            for usage in self.lvars_used_at_ea[ea]:
                if usage.idx == -1:
                    return usage.name

    def find_receiver_at_ea(self, ea):
        call_type = CG.sharedCG.edges[ea][0][3]
        if 'MSG' in call_type and ea in self.lvars_used_at_ea:
            for usage in self.lvars_used_at_ea[ea]:
                if usage.idx == 0:
                    return usage.name

    def find_new_tainted(self, var):
        # todo, actually we should taint data according to the invoke details
        news = []
        if var in self.asg:
            news.extend(self.asg[var])
        if var in self.lvars:
            for usage in self.lvars[var]:
                if usage.idx > -1:  # as message argument
                    new = self.find_lvalue_at_ea(usage.ea) or self.find_receiver_at_ea(usage.ea)
                    if new and new != var:
                        news.append(new)
        return news

    @staticmethod
    def clear():
        ida_hexrays.clear_cached_cfuncs()


# ------------------------------TaintResult--------------------------------------
class TR:

    pool = dict()

    def __init__(self, frm_list, to_list=None, idx_list=None):
        if idx_list is None:
            idx_list = []
        if to_list is None:
            to_list = []
        self.frm_list = frm_list
        self.to_list = to_list
        self.idx_list = idx_list
        self.as_ret = False
        self.as_global = []
        id = (tuple(frm_list), tuple(to_list), tuple(idx_list))
        if id not in TR.pool:
            TR.pool[id] = self

    def collect(self, ret_details=False):
        """
        :return: idx
        """
        f = Func.analyze(idaapi.get_func(self.frm_list[0]).startEA)
        if f.cfunc_t:
            f.process_asg_in_ctree()

        if f.lvars_used_at_ea and f.lvars:
            pass
        else:
            for rvalue, lvalues in f.asg.items():
                if type(rvalue) in [long, int]:  # the rvalue may be a call
                    for var in lvalues:
                        lu = lvar_usage(var, rvalue, -1)  # so the lvalue is ret val.
                        f.add_lvar_usage(lu)

            for record in f.calls:
                func, cargs, callsite = record
                for idx in range(0, len(cargs)):
                    arg = cargs[idx]
                    if type(arg) is ida_hexrays.lvar_t:
                        lu = lvar_usage(arg.name, callsite, idx)
                        f.add_lvar_usage(lu)
        Utils.log('Here is TR.collect, frm_list:{}, to_list:{}, idx_list:{}'.format(self.frm_list, self.to_list, self.idx_list))
        tainted = f.track_data(self.frm_list, idx_list=self.idx_list)
        Utils.log("Collect taint data in {}: {}".format(f.start_ea, tainted))
        # todo find global in tainted

        ret = set()
        if tainted:
            # for var in tainted:
            #     if var in f.lvars:
            #         for usage in f.lvars[var]:
            #             if usage.ea in CG.sharedCG.edges:
            #                 des = CG.sharedCG.edges[usage.ea][0][1]
            #                 if type(des) is str:
            #                     print '!!!Test', hex(usage.ea), usage.name, des
            if self.to_list:
                # self.to is the function which the tainted data passed to
                for to in self.to_list:
                    Utils.log('Does taint data pass through {} ?'.format(to))
                    if to in f.lvars_used_at_ea:
                        for arg_lu in f.lvars_used_at_ea[to]:
                            if arg_lu.name in tainted and arg_lu.idx > -1:
                                ret.add(arg_lu.idx)
                                Utils.log('YES, the NO.{} argument.'.format(arg_lu.idx))
            else:
                Utils.log('Does taint data return ?')
                if MachO.query_ret('_objc_msgSend', f.start_ea) == 'void':
                    if 'self' in f.asg:
                        for lvalue in f.asg['self']:
                            if lvalue in tainted:
                                ret.add(0)
                    for rvalue in f.asg:
                        if type(rvalue) is str and rvalue.startswith('a'):
                            for lvalue in f.asg[rvalue]:
                                if lvalue in tainted:
                                    ret.add(int(rvalue.strip('a')))
                    if ret:
                        Utils.log('YES, taint the passed parameters: {}'.format(ret))
                    else:
                        Utils.log('No, this function does not have return value and did not taint passed parameters.')
                    pass  # this function does not have a ret value even.
                else:
                    for var in tainted:
                        if var in f.ret_vars:
                            ret.add(-1)
                            Utils.log('YES.')
                            break
                        if var == 'result':
                            ret.add(-1)
                            Utils.log('YES.')
                            break
                        if var == 'self':
                            var = 'a0'
                        _var = f.cfunc_t.get_lvars()[int(var.strip('av'))]
                        if _var.is_result_var:
                            ret.add(-1)
                            Utils.log('YES.')
                            break
                    for var in tainted:
                        if var in f.lvars:
                            for usage in f.lvars[var]:
                                if usage.ea in f.ret_ea:
                                    ret.add(-1)
                                    Utils.log('YES.')
                                    break
        # f.lvars = {}
        # f.lvars_indexed_by_ea = {}
        return tainted if ret_details else list(ret)


class TA:

    def __init__(self, ss_api):
        self.ss_api = ss_api

    def run(self):
        print '-------------TA Test Start------------------', self.ss_api.node
        self.ss_api.pprint()
        # first, we check if the ss-api does exist taint data.
        get_src_at_path = []
        for path in self.ss_api.to_src:
            src_data_returned = True
            idx_list = []
            for frame in reversed(path.cs[1:]):
                if src_data_returned:
                    result = TR(frame.callsites, idx_list=idx_list).collect()
                    idx_list = []
                    if result:
                        for idx in result:
                            if idx > -1:
                                idx_list.append(idx)  # taint the passed parameters
                    else:
                        src_data_returned = False
                else:
                    break
            if src_data_returned:
                get_src_at_path.append(path)

        if get_src_at_path:
            print 'Src data is successfully obtained.'

        for src_p in get_src_at_path:
            sinked_path = []
            frm_list = src_p.cs[0].callsites
            for sink_p in self.ss_api.to_sink:
                to_list = sink_p.cs[0].callsites
                idx_list = TR(frm_list, to_list=to_list).collect()
                if idx_list:
                    pass_through = True
                    for frame in sink_p.cs[1:]:
                        idx_list = TR([frame.caller, ], to_list=frame.callsites, idx_list=idx_list).collect()
                        if idx_list:
                            continue
                        else:
                            pass_through = False
                            break
                    if pass_through:
                        sinked_path.append(sink_p)
            if sinked_path:
                Utils.log('Find sensitive paths, the details as follows: ')
                print 'SS_API to src: ', src_p.pprint()
                print 'SS_API to sink: ', len(sinked_path)
                for p in sinked_path:
                    p.pprint()
        print '-------------TA Test End------------------'


class NSUserdefaults:

    shared = None

    def __init__(self):
        self.data = dict()
        NSUserdefaults.shared = self

    def add_invoke(self, key, callsite, data=None):
        _type = 'GET' if data is None else 'SET'
        record = (callsite, data)
        if key not in self.data:
            self.data[key] = {'SET': [], 'GET': []}
        self.data[key][_type].append(record)

    def get_data(self, key):
        data_types = set()
        if key in self.data:
            for callsite, _type in self.data[key]['SET']:
                if _type and _type not in USELESS_TYPES:
                    data_types.add(_type)
        if len(list(data_types)) == 1:
            return data_types.pop()

    def pprint(self):
        for key in self.data:
            print 'KEY', key
            print 'GET'
            for record in self.data[key]['GET']:
                print record
            print 'SET'
            for record in self.data[key]['SET']:
                print record



# ------------------------------Utils---------------------------------------------
class Utils:

    def __init__(self):
        pass

    @staticmethod
    def nice_str(str):
        if str:
            if '_meta *' in str:
                return str.split('_meta *')[0]
            return str.strip('*').strip()

    @staticmethod
    def meth_type_parser(string):
        ret_type = string.split('@0:8')[0]
        para_types = string.split('@0:8')[1]
        ret_type = re.split('\d+', ret_type)[0: -1]
        para_types = re.split('\d+', para_types)[0: -1]
        ret_type.extend(para_types)
        func_type = []
        for t in ret_type:
            t = t.replace('"', '')
            if t.startswith('@'):
                t = '{} *'.format(t.strip('@'))
            func_type.append(t)
        return func_type

    @staticmethod
    def find_value(src):
        m = re.search('.+#selRef_(?P<sel>.+)@PAGEOFF]', src)
        if m:
            sel = m.group('sel').replace('_', ':')
            return sel
        m = re.search('.+#classRef_(?P<rec>.+)@PAGEOFF]', src)
        if m:
            rec = m.group('rec')
            return "{}_meta *".format(rec)
        m = re.search('.+#classRef_(?P<rec>.+)@PAGEOFF]', src)


        # '#_OBJC_IVAR_$_AppCommunicateData._dictionaryData@PAGEOFF'

    @staticmethod
    def pprint_type(str):
        return str.strip('@"')

    @staticmethod
    def log(str):
        if log_on:
            print str


class SS_API:

    pool = []

    def __init__(self, node, src=None):
        self.node = node
        self.source = src
        self.to_src = []  # path list
        self.to_sink = []  # path list

    @staticmethod
    def load_from_pkl(fp):
        f = open(fp)
        SS_API.pool = pickle.load(f)
        f.close()

    def pprint(self):
        print 'SS-API: {} ({})'.format(self.node, self.source)
        # print 'to SINKs: '
        # for path in self.to_sink:
        #     path.pprint()
        # print 'to SRCs: '
        # for path in self.to_src:
        #     path.pprint()


class Path:

    def __init__(self):
        self.cs = []  # frame list, in order

    def pprint(self):
        exist_gcd = False
        for frame in self.cs:
            # print '{}->{}({});'.format(frame.caller, frame.callee, frame.callsites),
            if frame.gcd:
                exist_gcd = True
            print '{}, '.format(frame.callsites),
        print 'EXISTS GCD' if exist_gcd else 'REGULAR'
        print


class Frame:

    def __init__(self, frm, to, ea_list):
        self.caller = frm
        self.callee = to
        self.callsites = ea_list
        self.gcd = False


tm = TaskManager()
# SS_API.load_from_pkl(r'E:\0_share\samples\20190513_12882_255317294877_Newsstand\Payload\ss_api.pkl')
# tm.analyze_in_sequence()

# for f in MachO.funcs_need_calc:
#     if len(MachO.func_data[f]) == 2:
#         f = Func.analyze(f)
#         print hex(f.start_ea), idc.GetFunctionName(f.start_ea), 'ret_type, ', f.ret