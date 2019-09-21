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

case_1 = []
ptr_arg = []
INVALID_EA = 0xffffffffffffffffL
execute_block_through_timer = ['scheduledTimerWithTimeInterval:repeats:block:',
                               'timerWithTimeInterval:repeats:block:',
                               'initWithFireDate:interval:repeats:block:', ]

execute_invocation_through_timer = ['scheduledTimerWithTimeInterval:invocation:repeats:',
                                    'timerWithTimeInterval:invocation:repeats:']

dispatch_msg_in_timer = ['scheduledTimerWithTimeInterval:target:selector:userInfo:repeats:',
                         'timerWithTimeInterval:target:selector:userInfo:repeats:',
                         'initWithFireDate:interval:target:selector:userInfo:repeats:', ]

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
    func_data = dict()
    updated_func_ret = dict()
    updated_func_args = dict()
    funcs_need_calc = []
    func_with_no_args = []
    bss_data = dict()

    def __init__(self):
        pass

    @staticmethod
    def build():
        seg = ida_segment.get_segm_by_name('__text')
        for f in Functions(start=seg.startEA, end=seg.endEA):
            name = GetFunctionName(f)
            CG.sharedCG.add_node(f, name)
            if name[0] not in ['-', '+']:
                if name.startswith('sub_'):
                    MachO.subroutines.append(f)
                continue
            cls, sel = name[1:].strip('[]').split()
            func_type = MachO.get_func_type(f)
            if func_type:
                MachO.func_data[f] = func_type
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
        MachO.update_func_data(fi, args, frm=frm, a=a)
        # TODO could we directly use the a (to replace the local vars of cfunc_t)?
        Func.analyze(fi)

    @staticmethod
    def update_func_data(fi, args, frm=None, a=None):
        new_func_type = []
        if fi not in MachO.func_data:
            return  # Failed to get func_type (func_type may be complicated, leave it alone for the moment)
        ori_func_type = MachO.func_data[fi]
        argc = len(ori_func_type) - 2  # the first two are rec and sel
        if argc and len(args) >= argc:
            for idx in range(0, argc):
                ori = ori_func_type[idx+2].type.__str__()
                new = args[idx]
                if new and type(new) is str and Message.is_rec_decidable(new):
                    new_func_type.append(new)
                else:
                    new_func_type.append(0L)
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
                if data_ea in MachO.bss_data:  # asg expr during resolve_cfunc
                    break
                else:
                    val = f.resolve_def(def_ea)
                    if val:
                        MachO.bss_data[data_ea] = val
                        break
            if data_ea not in MachO.bss_data:
                MachO.bss_data[data_ea] = idc.Name(data_ea)  # or id
        return MachO.bss_data[data_ea]

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

        for xref in XrefsTo(ea):
            frm = xref.frm
            if idc.SegName(frm) == '__objc_classrefs':
                self.classref = frm
            if idc.SegName(frm) == '__objc_superrefs':
                self.superref = frm

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

    pool = dict()

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

        for arg in args:
            if type(arg) is long and idc.Name(idc.Qword(arg)) == '__NSConcreteGlobalBlock':
                subroutine = idc.Qword(arg + 0x10)
                break
            elif type(arg) is ida_hexrays.lvar_t and arg.tif.__str__() == 'NSConcreteStackBlock **':
                base = arg.location.stkoff()
                subroutine_var = lvars_t[lvars_t.find_stkvar(base + 0x10, 64)]
                subroutine = f.cfunc_t.eamap[subroutine_var.defea / 4 * 4][
                    0].details.y.obj_ea if subroutine_var.is_stk_var() else None
                for idx in range(0, 3):
                    stkoff = base + 0x20 + idx*8
                    if lvars_t.find_stkvar(stkoff, 64) != -1:
                        block_arg = lvars_t[lvars_t.find_stkvar(stkoff, 64)]
                        if type(block_arg) is ida_hexrays.lvar_t:
                            block_vars.append(block_arg)
                            block_args.append(block_arg.tif.__str__())
                    # TODO v27 = *(_QWORD *)(v4 + 32); sub_10000E1A0, CPUDasher
                break
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
            # f = Func(subroutine)
            # f.decompile()
            # f.resolve_cfunc()
            # Func.analyzed_subroutines.append(subroutine)
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
        self.rec = rec or self.cargs[0]
        self.sel = sel or self.cargs[1]
        self.args = self.cargs[2:]
        self.details = ''

    def resolve_sel_succeed(self):
        if type(self.sel) is ida_hexrays.lvar_t:
            # self.sel = self.f.resolve_def(self.sel.defea) or self.f.def_analysis(self.callsite, 'X1')
            self.sel = self.f.get_var_type(self.sel) or self.f.def_analysis(self.callsite, 'X1')
        if not self.sel or type(self.sel) is not str:
            print 'unidentified sel ', hex(self.callsite), self.sel
            return False

        if self.sel.startswith('performSelector:onTarget:'):
            pass  # TODO CASE 6
        elif self.sel.startswith('performSelector') and self.args:
            # virtual_sel = self.f.resolve_arg(self.args[2], self.callsite, 2, 'sel')
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
            return rec_type
        if self.call == '_objc_msgSendSuper2':
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

        if Message.is_rec_decidable(rec_type):  # simply query
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
                if Message.is_rec_decidable(rec_type):
                    msg_type = 'E_MSG'  # framework message
                else:
                    msg_type = 'U_MSG'  # inferred the ret_val according to the sel, but still don't know the receiver.
            else:
                # void * alloc
                if Message.is_rec_decidable(rec_type):
                    msg_type = 'X_MSG'
                else:
                    msg_type = 'B_MSG'
                    print 'Invalid rec, ', rec_type, self.sel, hex(self.callsite)

            pt_rec = Utils.nice_str(rec_type)
            self.analyze_msg(pt_rec)
            if msg_type:
                CG.sharedCG.add_edge(self.ctx, '[{} {}]'.format(pt_rec, self.sel), self.callsite, msg_type,
                                     details=self.details, message=self)
        # ret_type adjustment
        if self.sel in ['class', 'init']:
            ret_type = rec_type if Message.is_rec_decidable(rec_type) else ret_type
        elif self.sel == 'isKindOfClass:':
            ret_type = 'BOOL'
        elif self.sel == 'alloc' and Message.is_rec_decidable(rec_type):  # the ori ret_type is id
            ret_type = '{} *'.format(rec_type.split('_meta *')[0]) if '_meta *' in rec_type else rec_type

        if ret_type == 'instancetype' and Message.is_rec_decidable(rec_type):
            ret_type = '{} *'.format(Utils.nice_str(rec_type))
        elif ret_type == 'BOOL':
            ret_type = ret_type.lower()

        return target, ret_type

    def analyze_msg(self, rec_type):
        if not rec_type:
            return None
        if 'NSUserDefaults' in rec_type and self.sel == 'objectForKey:':
            self.details += '; key_{}'.format(self.args[0] if len(self.args) > 0 else None)

    # def resolve_nested_message(self):
    #     target = None
    #     # ------------NSTimer----------------------------------
    #     # Add an edge from the callsite to the resolved target.
    #     # Skip this message if failed to resolve the target.
    #     # Target is a block
    #     if self.sel in execute_block_through_timer:
    #         block = self.args[-1]
    #
    #     # Target is a NSInvocation
    #     if self.sel in execute_invocation_through_timer:
    #         invocation = self.args[1]
    #
    #     # Target is a message
    #     if self.sel in dispatch_msg_in_timer:
    #         msg = Message(self.callsite, rec=self.args[1], sel=self.args[2])
    #         msg.resolve_target()
    #
    #     # --------------NSNotification-------------------------
    #     if self.sel is 'addObserverForName:object:queue:usingBlock:':
    #         block = self.args[3]
    #         NSNotificationCenter.add(self.args[0], block=self.args[-1])
    #         return
    #     if self.sel is 'addObserver:selector:name:object:':
    #         msg = Message(self.callsite, rec=self.args[0], sel=self.args[1])
    #         msg.resolve_target()
    #         NSNotificationCenter.add(self.args[2], msg=msg)
    #         return
    #     if self.sel is 'postNotificationName:object:userInfo:' or 'postNotificationName:object:':
    #         name = self.args[0]
    #     elif self.sel is 'postNotification:':
    #         # TODO
    #         pass
    #     target = NSNotificationCenter.retrieve(name)
    #
    #     # ------------------NSOperation---------------------------------
    #     if self.sel is 'addOperation:' or 'addOperations:waitUntilFinished:':
    #         operation = self.args[0]
    #     # TODO: check the type of operation and find target
    #     # non-concurrent operations, main method
    #
    #     # concurrent operations, start method
    #     elif self.sel is 'addOperationWithBlock:':
    #         block = self.args[0]

    @staticmethod
    def is_rec_decidable(rec_type):
        if rec_type:
            nice_str = Utils.nice_str(rec_type)
            if nice_str in OCClass.cls_dict:
                return True
            if nice_str in Frameworks.cls_dict:
                return True
        return False


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
        self.dcl = None  # cfunc.print_dcl()
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
        func.init_state()
        func.resolve_cfunc()
        return func

    @staticmethod
    def decompile_all(count=None):
        print 'START: ', time.asctime(time.localtime(time.time()))
        idx = 0
        for f in Functions():
            if idc.GetFunctionName(f)[0] not in ['-', '+']:
                continue
            Func.analyze(f)
            if count and idx > count:
                break
            idx += 1
        for sub in MachO.subroutines:
            if sub not in Func.analyzed_subroutines:
                Func.analyze(sub)
                idx += 1
        print 'END: ', time.asctime(time.localtime(time.time()))

    def decompile(self):  # wrapper of ida_hexrays.decompile
        try:
            process_arc_calls(self.start_ea)
            self.cfunc_t = ida_hexrays.decompile(self.start_ea)
        except Exception as e:
            Func.decompilation_failed.append(self.start_ea)
            print 'Decompilation Failed: ', hex(self.start_ea)

    def init_state(self):
        # if self.start_ea in Block.pool:
        #     lvars = self.cfunc_t.get_lvars()
        #     lvars[0].tif = ida_hexrays.create_typedef('NSConcreteStackBlock *')
        if self.start_ea in MachO.updated_func_args:
            new_func_data = MachO.updated_func_args[self.start_ea]
            for idx in range(0, len(new_func_data)):
                if new_func_data[idx]:
                    self.cfunc_t.arguments[idx+2].tif = ida_hexrays.create_typedef(new_func_data[idx])

    def resolve_cfunc(self):
        if not self.cfunc_t:
            return
        body = []
        ret = []
        for ea in self.cfunc_t.eamap:
            if idc.GetMnem(ea) in ['BL', 'B']:
                call = idc.GetOpnd(ea, 0)
                if call.startswith('loc'):
                    continue
                if len(list(idautils.CodeRefsFrom(ea, 1))) == 1:
                    ret.append((ea, self.cfunc_t.eamap[ea][0]))
                else:
                    body.append((ea, self.cfunc_t.eamap[ea][0]))
        # cinsnptrvec_t = self.cfunc_t.eamap[ea]  # TODO CASE 2 for cinsn_t in cinsnptrvec_t
        # cinsn = cinsnptrvec_t[0]
        # TODO use cinsn.ea or ea ?
        for cinsn in body:
            self.process_cinsn_t(cinsn[0], cinsn[1])
        for cinsn in ret:
            self.process_cinsn_t(cinsn[0], cinsn[1])
        self.update_funcdata_if_needed()

    def update_funcdata_if_needed(self):
        """
        find possible ret types, put it into self.ret, and update funcdata if needed.
        :return:
        """
        for t in ['id', 'void *']:
            if t in self.ret:
                self.ret.remove(t)
        if self.ret:
            pass  # have been filled during the resolve_cfunc process.(creturn_t)
        else:
            if self.start_ea not in MachO.funcs_need_calc:
                # todo if self is a subroutine, the result of query may be None
                self.ret.append(MachO.query_ori_func_data(self.start_ea))
            # find the return using the ret cinsn
            if not len(self.cfunc_t.treeitems):
                self.cfunc_t.get_pseudocode()
            for item in self.cfunc_t.treeitems:
                if item.cinsn.op == 80 or item.cinsn.op == 83:
                    self.process_ret(item.ea, item.cinsn.details)

        # update Mach-O data
        if self.start_ea in MachO.funcs_need_calc:
            rets = set(self.ret)
            rets.discard(None)
            if rets:
                if len(rets) == 1:
                    pass
                else:
                    print 'ERROR 454, ', hex(self.start_ea),  rets
                MachO.updated_func_ret[self.start_ea] = rets.pop()
            else:
                pass  # failed to calc the ret type

    def process_cinsn_t(self, ea, cinsn_t):
        try:
            if cinsn_t.op is idaapi.cit_expr:
                self.process_expr(ea, cinsn_t.details)
            elif cinsn_t.op is 80:  # return
                self.process_ret(ea, cinsn_t.details)
            elif isinstance(cinsn_t.details, ida_hexrays.ceinsn_t):  # cinsn_t.op is idaapi.cit_if, do, while...
                self.process_ceinsn_t(ea, cinsn_t.details)
            elif isinstance(cinsn_t.details, ida_hexrays.cgoto_t):
                pass
            else:  # very rare
                print 'ERROR 2', hex(ea), cinsn_t.details
        except Exception as e:
            print '!!!', e, hex(ea)

    def process_ret(self, ea, creturn_t):
        self.ret_ea.append(ea)
        cast_type, ret_type, call_expr = None, None, None
        if creturn_t.expr.opname == 'cast':
            cast_type = creturn_t.expr.type
            if creturn_t.expr.x.opname == 'call':
                call_expr = creturn_t.expr.x
        elif creturn_t.expr.opname == 'call':  # dispatch*, do not need cast
            call_expr = creturn_t.expr
        elif creturn_t.expr.opname == 'var':
            var = self.resolve_var(creturn_t.expr.v)
            ret_type = var.tif.__str__()
            self.ret_vars.append(var.name)
        else:
            # ne, add, eq, ult... TODO CASE 1
            case_1.append(ea)
        if call_expr and ea != INVALID_EA:
            ret_type = self.process_call(ea, call_expr)  # TODO CASE 3
        if ret_type:
            self.ret.append(ret_type)

    def process_ceinsn_t(self, ea, ceinsn_t):
        if type(ceinsn_t) is ida_hexrays.cfor_t:
            for attr in ['expr', 'init', 'step']:
                _attr = ceinsn_t.__getattribute__(attr)
                if type(_attr) is ida_hexrays.cexpr_t:
                    self.find_call_fast_and_process(ea, _attr)
        else:
            self.find_call_fast_and_process(ea, ceinsn_t.expr)

    def process_expr(self, ea, cexpr_t):
        if cexpr_t.opname.startswith('asg'):  # asg, asgadd, asgxor ...
            self.process_asg(ea, cexpr_t)
        elif cexpr_t.opname == 'call':
            self.process_call(ea, cexpr_t)
        else:
            print 'ERROR 3: ', hex(ea), cexpr_t.opname

    def process_asg(self, ea, cexpr_t):
        if not cexpr_t.y:
            print 'ERROR 12, NO EXPR FOR ASG', hex(ea)
            return
        cast, ret_type, fast_call = None, None, None
        if cexpr_t.y.opname == 'call':
            ret_type = self.process_call(ea, cexpr_t.y)
        elif cexpr_t.y.opname == 'cast':
            cast = cexpr_t.y.type
            if cexpr_t.y.x.opname == 'call':
                ret_type = self.process_call(ea, cexpr_t.y.x)
            else:
                fast_call = cexpr_t.y.x  # expr is too complicated, just find the call and ignore the assign.
        else:
            fast_call = cexpr_t.y.x
        if type(fast_call) is ida_hexrays.cexpr_t:
            self.find_call_fast_and_process(ea, fast_call)
        # ASG
        lvalue = cexpr_t.x
        if lvalue.opname == 'var':
            lvalue = self.resolve_var(lvalue.v)
            self.asg[ea] = [lvalue.name, ]
            # lu = lvar_usage(lvalue.name, ea, -1)
            # self.add_lvar_usage(lu)
            if ret_type and 'tif' in dir(lvalue) and lvalue.tif.__str__() != ret_type:
                # if cast != struct objc_object *, id, ...
                ret_type = ida_hexrays.create_typedef(ret_type)
                lvalue.tif = ret_type
                cexpr_t.y.tif = ret_type
        elif lvalue.opname == 'obj':
            if idc.SegName(lvalue.obj_ea) == '__bss':
                if lvalue.obj_ea not in MachO.bss_data and ret_type:
                    MachO.bss_data[lvalue.obj_ea] = ret_type
            else:
                print 'TODO case 4', hex(ea)
        elif lvalue.opname in ['memptr', 'ptr', 'idx', 'call']:
            print 'lvalue, ', lvalue.opname, hex(ea)

    def process_call(self, ea, cexpr_t):
        callee = None
        if cexpr_t.x.opname == 'cast':  # the func_type is cast
            callee = cexpr_t.x.x.obj_ea
        elif cexpr_t.x.opname == 'obj':
            callee = cexpr_t.x.obj_ea
        elif cexpr_t.x.opname == 'helper':  # COERCE_DOUBLE(-[DecideViewController rtAngle](v2, "rtAngle"));
            if len(cexpr_t.a) == 1 and type(cexpr_t.a[0]) is ida_hexrays.cexpr_t:
                call = self.find_call_fast(cexpr_t.a[0])
                return self.process_call(ea, call) if call else None
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
            ret_type = self.resolve_arc_val(ea, call, cexpr_t.a)
        elif call.startswith('loc_'):
            pass
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

    def find_call_fast_and_process(self, ea, cexpr_t):
        call = self.find_call_fast(cexpr_t)
        if call:
            self.process_call(ea, call)

    def find_call_fast(self, cexpr_t):
        if cexpr_t.opname == 'call':
            return cexpr_t
        try:
            if cexpr_t.operands:
                for label, operand in cexpr_t.operands.items():
                    if type(operand) is ida_hexrays.cexpr_t:
                        call = self.find_call_fast(operand)
                        if call:
                            return call
        except Exception as e:
            print e

    def resolve_def(self, defea):
        defea = defea / 4 * 4
        if defea in self.cfunc_t.eamap:
            def_ins = self.cfunc_t.eamap[defea][0]
            if def_ins.op is idaapi.cit_expr and 'y' in def_ins.details.operands:
                def_expr_y = def_ins.details.y
                # the rvalue is ea
                if def_expr_y and def_expr_y.opname == 'obj':
                    return idc.get_bytes(def_expr_y.obj_ea, idc.get_item_size(def_expr_y.obj_ea) - 1)
                # the rvalue is var
                elif def_expr_y and def_expr_y.opname == 'var':
                    var = self.cfunc_t.get_lvars()[def_expr_y.v.idx]
                    var_type = var.tif.__str__()
                    if var_type not in ['id', 'void *', 'void **', 'struct objc_object *', '__int64']:
                        return var_type
                    if var.defea/4*4 != defea:
                        return self.resolve_def(var.defea)
                # the rvalue is an expression, when using cast, the ori type may be useful.
                elif def_expr_y and def_expr_y.opname == 'cast':
                    ori_type = def_expr_y.x.type.__str__()
                    if ori_type in ['void *', 'id']:  # invalid, try to find the real
                        if def_expr_y.x.opname == 'var':
                            ori_type = self.resolve_var(def_expr_y.x.v).tif.__str__()
                    return ori_type
                # the rvalue is *(struct objc_object **)(a1 + 32)
                elif def_expr_y and def_expr_y.opname == 'ptr':
                    if def_expr_y.x.opname == 'cast':
                        if def_expr_y.x.x.opname == 'add':
                            return self.resolve_block_var(def_expr_y.x.x)

        else:
            print 'ERROR 11, ', hex(defea)

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
                    target = src
            elif mnem == 'STR':
                if idc.GetOpnd(curr_ea, 1) == target:
                    target = idc.GetOpnd(curr_ea, 0)
            curr_ea = idc.prev_head(curr_ea, f_start)

    def resolve_var(self, var_ref_t, _type=None):
        var = self.cfunc_t.get_lvars()[var_ref_t.idx]
        Block.update_var_tif_if_needed(var, self.cfunc_t)
        if _type == 'def_str':
            pass
        return var

    def get_var_type(self, var):
        var_type = var.tif.__str__()
        if var_type not in ['id', 'void *', 'void **', 'struct objc_object *', '__int64']:
            return var_type
        else:
            return self.resolve_def(var.defea)

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
        elif segName == '__bss':
            return MachO.query_bss(obj_ea) or 'id'  # TODO  or return id?

    def resolve_arc_val(self, ea, call, args):
        # call is a arc call (B *, as ret)
        if idaapi.get_func(ea).startEA not in MachO.funcs_need_calc or not args:
            return  #
        # if len(args) != 1:  we should reset the func's type
        val = self.resolve_arg(args[0], ea, 0, usage='arc')
        if type(val) is str:
            return val
        elif type(val) is ida_hexrays.lvar_t:
            return self.get_var_type(val)
        else:
            print 'ERROR 345, ', hex(ea)
            return None

    def resolve_args(self, args, start, callsite, type):
        ret = []
        for idx in range(start, len(args)):
            ret.append(self.resolve_arg(args[idx], callsite, idx, type))
        return ret

    def resolve_arg(self, carg_t, ea, idx, usage=None):
        if carg_t.v:
            return self.resolve_var(carg_t.v)
            # return self.get_var_type(carg_t.v)
        if carg_t.obj_ea and carg_t.obj_ea != INVALID_EA:
            return self.resolve_obj(carg_t.obj_ea)  # ret str or long
        if carg_t.n:
            return carg_t.n._value
        # if carg_t.opname == 'ptr':
        #     ptr_arg.append([ea, idx])
        #     return 'id'  # TODO
        if carg_t.x:
            if carg_t.x.opname == 'obj':  # &OBJC_CLASS___NSNumber
                return self.resolve_obj(carg_t.x.obj_ea)
            elif carg_t.x.opname == 'var':  # TODO the cast operation fron IDA may be wrong, we use the ori_var_type
                # return self.get_var_type(carg_t.x.v)
                return self.resolve_var(carg_t.x.v)
            elif carg_t.x.opname == 'ptr':
                print 'TODO 7, ', hex(ea), idx, usage
            elif carg_t.x.opname == 'memptr':  # (void *)v5->_locationManager, carg_t.opname == 'cast'
                return carg_t.x.type.__str__()

            # ((id (__cdecl *)(GrayCtl_meta *, SEL))objc_msgSend)((GrayCtl_meta *)&OBJC_CLASS___GrayCtl, "instance");
            # actually, the cast type is right
            elif carg_t.x.opname == 'ref':  # &OBJC_CLASS___GrayCtl
                if carg_t.x.x.opname == 'obj':  # OBJC_CLASS___GrayCtl
                    return self.resolve_obj(carg_t.x.x.obj_ea)

            # objc_msgSend(*(void **)(v4 + 32), "setProPriceStr:", v22);
            elif carg_t.x.opname == 'cast' and carg_t.x.x.opname == 'add':
                # fi = ida_funcs.get_func(ea).startEA
                return self.resolve_block_var(carg_t.x.x)
            # TODO CASE 5

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
                print 'SS_API to src: ', src_p
                print 'SS_API to sink: ', len(sinked_path)
                for p in sinked_path:
                    p.pprint()
        print '-------------TA Test End------------------'


class NSUserdefaults:

    shared = None

    def __init__(self):
        self.data = dict()
        NSUserdefaults.shared = self

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
        print 'to SINKs: '
        for path in self.to_sink:
            path.pprint()
        print 'to SRCs: '
        for path in self.to_src:
            path.pprint()


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