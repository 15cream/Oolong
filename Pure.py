# coding=utf-8
import os
import time
import pickle
import re
import idc
import idaapi
import idautils
import ida_funcs
import ida_bytes
import ida_typeinf
import ida_segment
import ida_hexrays

stop_words = ['NS_AVAILABLE', 'NS_DEPRECATED', 'NS_DESIGNATED_INITIALIZER', '__OSX_AVAILABLE_STARTING',
              'NS_UNAVAILABLE', 'NS_EXTENSION_UNAVAILABLE_IOS']

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

arc_calls = {
    "_objc_copyWeak",  # "MOV X0, X1",  # void objc_copyWeak(id *dest, id *src);
    "_objc_moveWeak",  # "MOV X0, X1",  # void objc_moveWeak(id *dest, id *src);
    "_objc_initWeak",  # "MOV X0, X1",  # id objc_initWeak(id *object, id value);
    "_objc_loadWeak",  # "LDR X0, [X0]",  # id objc_loadWeak(id *object);
    "_objc_loadWeakRetained",  # "LDR X0, [X0]",  # id objc_loadWeakRetained(id *object);
    "_objc_storeStrong",  # "STR X0, X1",  # void objc_storeStrong(id *object, id value);
    "_objc_storeWeak",  # id objc_storeWeak(id *object, id value);
}

basic_types = {
    'B': 'bool',
    'Q': '__int64',  # unsigned __int64
    'I': '__int64',  # unsigned int
    'i': '__int64',  # int
    'q': '__int64',  # signed __int64
}

LOG_ON = False
INST_STEP = 4


class CacheInfo:
    cls_dict = dict()
    proto_dict = dict()
    sel_dict = dict()

    def __init__(self, name=None):
        self.name = name
        self.super = None
        self.methods = dict()  # sel: type
        self.props = dict()  # property: type
        self.protocols = []

    @staticmethod
    def build_from_dir(dir):
        for f in os.listdir(dir):
            CacheInfo.parse_headers(os.path.join(dir, f))
        CacheInfo.build_sel_dict()

    @staticmethod
    def build_from_pkl(fp):
        f = open(fp)
        CacheInfo.cls_dict, CacheInfo.proto_dict = pickle.load(f)
        f.close()
        CacheInfo.build_sel_dict()

    @staticmethod
    def dump():
        f = open(r'E:\0_share\experiments\IDA\analysis\tools\FrameworkHeaders.pkl', 'wb')
        pickle.dump([CacheInfo.cls_dict, CacheInfo.proto_dict], f)
        f.close()

    @staticmethod
    def has_proto(proto_name):
        if proto_name not in CacheInfo.proto_dict:
            CacheInfo.proto_dict[proto_name] = CacheInfo(proto_name)
        return CacheInfo.proto_dict[proto_name]

    @staticmethod
    def has_class(cls_name):
        if cls_name not in CacheInfo.cls_dict:
            CacheInfo.cls_dict[cls_name] = CacheInfo(cls_name)
        return CacheInfo.cls_dict[cls_name]

    @staticmethod
    def build_sel_dict():
        for n, cls in CacheInfo.cls_dict.items():
            for protocol_name in cls.protocols:
                if protocol_name in CacheInfo.proto_dict:
                    protocol = CacheInfo.proto_dict[protocol_name]
                    cls.methods.update(protocol.methods)
                    cls.props.update(protocol.props)

        for cache_info in CacheInfo.cls_dict.values() + CacheInfo.sel_dict.values():
            sel_set = cache_info.methods.keys() + cache_info.props.keys()
            for sel in sel_set:
                sel = sel.strip('*')
                if sel in CacheInfo.sel_dict:
                    CacheInfo.sel_dict[sel].add(cache_info)
                else:
                    CacheInfo.sel_dict[sel] = {cache_info}

    @staticmethod
    def parse_headers(fp):
        file = open(fp)
        current_fs = None

        for line in file.readlines():
            m1 = re.search('@interface\s+(?P<class>[^()\s]\w+)', line)
            if m1:
                current_fs = CacheInfo.has_class(m1.group('class'))
                m2 = re.search('@interface\s+(?P<class>\w+)[\s:]+(?P<superclass>\w+)\s+', line)
                current_fs.super = m2.group('superclass') if m2 else current_fs.super
                m3 = re.search('\<(?P<protocol>.+)\>', line)
                if m3:
                    for p in m3.group('protocol').split(','):
                        current_fs.protocols.append(p.strip())
                continue

            m = re.search('@protocol\s+(?P<proto>[^<>;\s]\w+).*', line)
            if m:
                current_fs = CacheInfo.has_proto(m.group('proto'))
                continue

            if line.startswith('@end'):
                current_fs = None

            if line.startswith(('+', '-')):
                line = CacheInfo.refine_line(line)
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
    def refine_line(line):
        line = line.split(';')[0]
        words = line.split()
        for word in words:
            for sw in stop_words:
                if sw in word:
                    words = words[:words.index(word)]
                    return ' '.join(words)
        return line

    def respond_to_sel(self, sel, message=None):
        """
        :param sel: string
        :param rec: NSObject
        :return:
        """
        if message:
            if sel == 'class':
                return NSObject(message.rec.type, is_meta=True)
            elif sel == 'init':
                return NSObject(message.rec.type)
            elif sel == 'alloc':
                return NSObject(message.rec.type)

        for SEL in self.methods:
            if SEL == sel:
                ret_type = self.methods[SEL][0].strip(' *')
                ret_type = message.rec.type if ret_type == 'instancetype' else ret_type
                return NSObject(ret_type)  # todo, 有可能是_meta吗？
        for property in self.props:
            if property.strip('*') == sel:  # *property -> strip * -> accessor method
                ret_type = self.props[property]
                ret_type = message.rec.type if ret_type == 'instancetype' else ret_type
                return NSObject(ret_type)
        return None


# ------------------------------- Mach-O---------------------------------------------------------


class MachO:
    funcs_index_by_sel, funcs_index_by_rec = dict(), dict()
    subroutines, oc_methods = [], []
    funcs_ret_id, func_has_no_args = [], []  # only oc methods, ret id且为类型缺失
    func_data_frm_ida = dict()
    updated_func_ret = dict()
    global_data = dict()

    def __init__(self):
        pass

    @staticmethod
    def build():
        seg = ida_segment.get_segm_by_name('__text')
        for f in idautils.Functions(start=seg.startEA, end=seg.endEA):
            name = idc.GetFunctionName(f)
            DB.shared.add_node(f, name)
            if name[0] in ['-', '+']:
                MachO.oc_methods.append(f)
            elif name.startswith('sub_'):
                MachO.subroutines.append(f)

            func_type = MachO.get_func_type(f)  # 根据IDA提供的func prototype（可能会失败）
            if func_type:
                MachO.func_data_frm_ida[f] = func_type
                if f in MachO.oc_methods:
                    cls, sel = name[1:].strip('[]').split()
                    rec = func_type[0].type.__str__()
                    if rec not in MachO.funcs_index_by_rec:
                        MachO.funcs_index_by_rec[rec] = {sel: f}
                    else:
                        MachO.funcs_index_by_rec[rec][sel] = f
                    if sel not in MachO.funcs_index_by_sel:
                        MachO.funcs_index_by_sel[sel] = {rec: f}
                    else:
                        MachO.funcs_index_by_sel[sel][rec] = f

                    if len(func_type) == 2:
                        MachO.func_has_no_args.append(f)

                    ret_type = func_type.rettype.__str__()
                    if ret_type == 'id' and cls in OCClass.pool_indexed_by_name:  # TODO category
                        if not OCClass.pool_indexed_by_name[cls].is_method_a_getter(sel, f):
                            MachO.funcs_ret_id.append(f)

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
    def query_ret_from_prototype(ea):
        if ea and ea in MachO.func_data_frm_ida:
            return MachO.func_data_frm_ida[ea].rettype.__str__()

    @staticmethod
    def query_data_at_ea(data_ea):
        if data_ea not in MachO.global_data:
            store_ops = []
            for xref in idautils.XrefsTo(data_ea):
                if idc.GetMnem(xref.frm) == 'STR':
                    store_ops.append(xref.frm)
            for def_ea in store_ops:
                val = Utils.def_analysis_ps(def_ea, reg=idc.GetOpnd(def_ea, 0))[0]
                if val.type != 'id':
                    MachO.global_data[data_ea] = val
                    break
            if data_ea not in MachO.global_data:  # 如果通过解析仍然没有获得有效的 bss_data 值
                MachO.global_data[data_ea] = NSObject('id', ea=data_ea)
        return MachO.global_data[data_ea]

    @staticmethod
    def update_func_data(fi, types, frm=None, a=None):
        if fi in MachO.func_data_frm_ida:
            func_data = MachO.func_data_frm_ida[fi]
            ret_type = types[0]
            para_types = types[1:]
            if func_data.rettype.__str__() == 'id':
                func_data.rettype = ida_hexrays.create_typedef(ret_type)
            for i in range(len(para_types)):
                new_t = para_types[i]
                ori_t = func_data[i + 2] if len(func_data) > i + 2 else None
                if ori_t and ori_t.type.__str__() == 'id':
                    ori_t.type = ida_hexrays.create_typedef(new_t)


# -----------------------------Protocol----------------------------------------------------

class Protocol:
    pool_indexed_by_ea = dict()
    pool_indexed_by_name = dict()

    def __init__(self, data_ea):
        self.ea = data_ea  # ea in __data
        self.name = idc.get_bytes(idc.Qword(self.ea + 0x8), idc.get_item_size(idc.Qword(self.ea + 0x8)) - 1)
        self.implementing_classes = []
        self.prots = []
        self.meths = {}  # selector: meth_type_Str

    def extract_info_from_IDA(self):
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
            meth_list = ida_bytes.get_qword(self.ea + 0x18 + idx * 8)
            if meth_list:
                entrysize = ida_bytes.get_dword(meth_list)
                count = ida_bytes.get_dword(meth_list + 4)
                ea = meth_list + 8
                for i in range(0, count):
                    sel = idc.get_bytes(idc.Qword(ea), idc.get_item_size(idc.Qword(ea)) - 1)
                    meth_type = idc.get_bytes(idc.Qword(type_info), idc.get_item_size(idc.Qword(type_info)) - 1)
                    self.meths[sel] = meth_type
                    ea += entrysize
                    type_info += 8

    @staticmethod
    def build_from_IDA():
        seg = ida_segment.get_segm_by_name('__objc_protolist')
        for ea in range(seg.startEA, seg.endEA, 8):
            p = Protocol(ida_bytes.get_qword(ea))
            p.extract_info_from_IDA()
            Protocol.pool_indexed_by_ea[p.ea] = p
            Protocol.pool_indexed_by_name[p.name] = Protocol.pool_indexed_by_name[p.name] + [
                p, ] if p.name in Protocol.pool_indexed_by_name else [p, ]

    @staticmethod
    def add_implementing_class(p, c):
        if p in Protocol.pool_indexed_by_ea:
            Protocol.pool_indexed_by_ea[p].implementing_classes.append(c)


# -----------------------------OCClass-----------------------------------------------------

class OCClass:
    pool_indexed_by_name = dict()
    pool_indexed_by_ea = dict()

    def __init__(self, ea):
        self.ea = ea  # ea: objc_data address
        self.info = ida_bytes.get_qword(ea + 0x20)
        self.superclass = ida_bytes.get_qword(
            ida_bytes.get_qword(ea) + 0x08)  # idc.Name(self.superclass): _OBJC_METACLASS_$_UIView
        self.name = idc.get_bytes(idc.Qword(self.info + 0x18), idc.get_item_size(idc.Qword(self.info + 0x18)) - 1)
        self.classref = None
        self.superref = None
        self.prots = []
        self.ivars = dict()
        self.props = dict()

    def extract_info_from_IDA(self):
        for xref in idautils.XrefsTo(self.ea):
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
                _name = idc.get_bytes(idc.Qword(ea + 0X08), idc.get_item_size(idc.Qword(ea + 0X08)) - 1)
                # self.ivars[offset] = _type
                self.ivars[_name] = _type
                ea += entrysize

        base_props = ida_bytes.get_qword(self.info + 0x40)
        if base_props and idc.SegName(base_props) == '__objc_const':
            entrysize = ida_bytes.get_dword(base_props)
            count = ida_bytes.get_dword(base_props + 4)
            ea = base_props + 8
            for i in range(count):
                _type = idc.get_bytes(idc.Qword(ea + 0X08), idc.get_item_size(idc.Qword(ea + 0X08)) - 1)
                _name = idc.get_bytes(idc.Qword(ea), idc.get_item_size(idc.Qword(ea)) - 1)
                self.props[_name] = _type
                ea += entrysize

        base_prots = ida_bytes.get_qword(self.info + 0x28)
        if base_prots and idc.SegName(base_prots) == '__objc_const':
            count = ida_bytes.get_qword(base_prots)
            entrysize = 0x8
            p_ea = base_prots + 8
            for i in range(count):
                proto_ea = idc.get_qword(p_ea)
                self.prots.append(proto_ea)
                Protocol.add_implementing_class(proto_ea, self.ea)
                p_ea += entrysize

    @staticmethod
    def build_from_IDA():
        seg = ida_segment.get_segm_by_name('__objc_classlist')
        for class_ea in range(seg.startEA, seg.endEA, 8):
            objc_data = ida_bytes.get_qword(class_ea)
            cls = OCClass(objc_data)
            cls.extract_info_from_IDA()
            OCClass.pool_indexed_by_name[cls.name] = cls if cls.name not in OCClass.pool_indexed_by_name else \
                OCClass.pool_indexed_by_name[cls.name]
            OCClass.pool_indexed_by_ea[cls.ea] = cls

    def is_method_a_getter(self, sel, f=None):
        base_props = ida_bytes.get_qword(self.info + 0x40)
        if not base_props:
            return False
        entrysize = ida_bytes.get_dword(base_props)
        count = ida_bytes.get_dword(base_props + 4)
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


# 将分析结果存入DB，某种意义上算运行时数据？
class DB:
    shared = None

    def __init__(self):
        self.nodes = dict()
        self.edges = dict()
        self.messages_target_at_f = dict()

    def add_node(self, f, name):
        self.nodes[f] = name

    def add_edge(self, call):
        self.edges[call.callsite] = self.edges[call.callsite] + [call, ] if call.callsite in self.edges else [call, ]
        if isinstance(call, Message) and call.target:
            self.messages_target_at_f[call.target] = self.messages_target_at_f[call.target] + [
                call] if call.target in self.messages_target_at_f else [call, ]

    # 在定值分析时可能出现target为“调用返回值”的情况，在此进行查询库中是否有可用的信息
    def query_ret_at_ea(self, ea):
        """
        :param ea:
        :return: 返回ea处所有message的返回值类型
        """
        log('Query possible return values at {} in database'.format(hex(ea)))
        if ea not in self.edges:
            Message.analyze_messages_at_ea(ea)
        if ea in self.edges:
            possible_calls = self.edges[ea]
            ret_types = set()
            for call in possible_calls:
                if not call.ret:
                    OCRuntime.query_ret(call)
                if call.ret:
                    ret_types.add(call.ret.type)
            ret_types = list(ret_types)
            ret = []
            if ret_types:
                for _type in ret_types:
                    ret.append(NSObject(_type))
                return ret
            else:
                return [NSObject('id')]

    def clear(self):
        self.nodes = dict()
        self.edges = dict()
        self.messages_target_at_f = dict()


class Path:
    def __init__(self):
        self.branches = dict()  # 因为是用于backward slicing，所以value为key的prev_head
        self.def_value = None


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
        """
        :param string:
        :return: 返回一个列表，第一项为ret type，其余为参数的类型（没有包括rec与sel）
        """
        ret_type = string.split('@0:8')[0]
        para_types = string.split('@0:8')[1]
        ret_type = re.split('\d+', ret_type)[0: -1]
        para_types = re.split('\d+', para_types)[0: -1]
        types = ret_type + para_types
        func_type = []
        for t in types:
            t = t.replace('"', '')
            if t.startswith('@'):
                t = '{} *'.format(t.strip('@'))
            func_type.append(t)
        return func_type

    @staticmethod
    def prop_type_parser(s):
        _type = s.split(',')[0].strip('T')
        return _type.strip('@"')

    @staticmethod
    def def_analysis_ps(current_ea, target_phrase=None, reg_idx=None, reg=None, path=None, steps=None):
        t_base_reg, t_index_reg, t_displ = reg or 'X{}'.format(reg_idx), None, None
        if t_base_reg:
            log('start def_analysis: {} at {}'.format(t_base_reg, hex(current_ea)))
        else:
            return [NSObject('id')]

        f_start, f_end = idc.get_func_attr(current_ea, idc.FUNCATTR_START), idc.get_func_attr(current_ea,
                                                                                              idc.FUNCATTR_END)
        steps = steps or []
        while current_ea != idc.BADADDR:
            log('Analyze {} at {}'.format((t_base_reg, t_index_reg, t_displ), hex(current_ea)))
            mnem = idc.GetMnem(current_ea)
            # steps.append(current_ea)
            # MOV
            if mnem == "MOV" and idc.GetOpnd(current_ea, 0) == t_base_reg:
                src_type = idc.get_operand_type(current_ea, 1)
                if src_type == idc.o_imm:
                    return [NSObject('Q', value=idc.get_operand_value(current_ea, 1))]
                elif src_type == idc.o_reg:
                    t_base_reg = idc.GetOpnd(current_ea, 1)
                else:
                    log('ERROR MOV AT {}'.format(hex(current_ea)))
                    return [NSObject('id')]
            # ADD
            elif mnem == 'ADD' and idc.GetOpnd(current_ea, 0) == t_base_reg:
                base = idc.GetOpnd(current_ea, 1)
                offset = idc.GetOpnd(current_ea, 2)
                if idc.get_operand_type(current_ea, 2) == idc.o_imm:
                    result = Utils.resolve_displ(current_ea, base, offset_str=offset, displ=idc.get_operand_value(current_ea, 2), steps=steps)
                elif idc.get_operand_type(current_ea, 2) in [1, 8]:
                    result = Utils.resolve_phrase(current_ea, base, offset, steps=steps)
                else:
                    log('ERROR, ADD, {}'.format(hex(current_ea)))
                    result = None
                return [result] if result else [NSObject('id')]
            # ADR
            elif mnem == 'ADR' and idc.GetOpnd(current_ea, 0) == t_base_reg:
                src_type = idc.get_operand_type(current_ea, 1)
                if src_type == idc.o_imm:
                    return [NSObject('Q', value=idc.get_operand_value(current_ea, 1))]
                else:
                    log('ERROR ADR AT {}'.format(hex(current_ea)))
                    return [NSObject('id')]
            # LDR
            elif mnem in ['LDR', 'LDRSW', 'LDUR'] and idc.GetOpnd(current_ea, 0) == t_base_reg:  # LDR, LDUR, LDRSW
                src_type = idc.get_operand_type(current_ea, 1)
                if src_type == idc.o_displ:  # [X8,#classRef_BookshelfS@PAGEOFF]; [X8]; [SP,#0x5A0+var_4A0]
                    base_reg, displ = (idc.GetOpnd(current_ea, 1).strip('[]').split(',')+[0])[0:2]
                    if displ:
                        result = Utils.resolve_displ(current_ea, base_reg, offset_str=displ, displ=idc.get_operand_value(current_ea, 1), steps=steps)
                        if result:
                            return [result]
                        else:
                            t_base_reg, t_displ = base_reg, idc.get_operand_value(current_ea, 1)
                    else:
                        t_base_reg = base_reg
                elif src_type == idc.o_phrase:  # [X8,X20,LSL#3]; # [X0,X8]
                    base_reg, index_reg = idc.GetOpnd(current_ea, 1).strip('[]').split(',')[0:2]
                    return [Utils.resolve_phrase(current_ea, base_reg, index_reg, steps=steps)]
                else:
                    log('ERROR LDR AT {}'.format(hex(current_ea)))
                    return [NSObject('id')]
            # STR
            elif mnem in ['STR', 'STUR', ] and t_base_reg in idc.GetOpnd(current_ea, 1):
                des_type = idc.get_operand_type(current_ea, 1)
                if des_type == idc.o_phrase:
                    base_reg, index_reg = idc.GetOpnd(current_ea, 1).strip('[]').split(',')[0:2]
                    if base_reg == t_base_reg and index_reg == t_index_reg:
                        t_base_reg = idc.GetOpnd(current_ea, 0)
                        t_displ = None
                elif des_type == idc.o_displ:
                    base_reg = idc.GetOpnd(current_ea, 1).strip('[]').split(',')[0]
                    if base_reg == t_base_reg:
                        displ = idc.get_operand_value(current_ea, 1)
                        if displ == t_displ:
                            t_base_reg = idc.GetOpnd(current_ea, 0)
                            t_displ = None
                else:
                    log('ERROR STR AT {}'.format(hex(current_ea)))
                    return NSObject('id')
            # LDP
            elif mnem == 'LDP':
                des1 = idc.GetOpnd(current_ea, 0)
                des2 = idc.GetOpnd(current_ea, 1)
                if t_base_reg in [des1, des2]:
                    if t_base_reg == des1:
                        t_index_reg = 0
                    else:
                        t_index_reg = 1
                    t_base_reg = idc.GetOpnd(current_ea, 2)  # 这里的情况太复杂了
            # STP
            elif mnem == 'STP' and idc.GetOpnd(current_ea, 2) == t_base_reg:
                t_base_reg = idc.GetOpnd(current_ea, t_index_reg)
            # BL
            elif mnem == 'BL':
                call = idc.GetOpnd(current_ea, 0)
                if call in arc_calls_as_nop:
                    pass
                elif call in arc_calls:
                    if call in ["_objc_copyWeak", "_objc_moveWeak",
                                "_objc_initWeak"] and t_base_reg == 'X0':  # "MOV X0, X1",  # void objc_copyWeak(id *dest, id *src);
                        t_base_reg = 'X1'
                    elif call in ["_objc_loadWeak",
                                  "_objc_loadWeakRetained"] and t_base_reg == 'X0':  # "LDR X0, [X0]",  # id objc_loadWeak(id *object);
                        t_base_reg = 'X0'  # 其实这里应该写作 *X0
                    elif call in ["_objc_storeStrong",
                                  "_objc_storeWeak"] and t_base_reg == 'X0':  # void objc_storeStrong(id *object, id value);
                        t_base_reg = 'X1'
                elif call.startswith('_objc_msgSend') and t_base_reg == 'X0':
                    return DB.shared.query_ret_at_ea(current_ea)
                elif call.startswith('_dispatch'):
                    pass  # 是否需要考虑block中的imported ivars
                elif t_base_reg == 'X0':  # external c function calls
                    return [NSObject('id')]

            current_ea = idc.prev_head(current_ea, f_start)
            # prev_heads = list(idautils.CodeRefsTo(current_ea, 1))
            # current_ea = None
            # for ea in sorted(prev_heads):
            #     if ea in range(f_start, f_end) and ea not in steps:
            #         current_ea = ea
            #         break
            #     else:
            #         current_ea = None
            # if not current_ea:
            #     break

            # prev_heads = list(idautils.CodeRefsTo(current_ea, 1))
            # if len(prev_heads) == 1 and prev_heads[0] in range(f_start, f_end):
            #     current_ea = prev_heads.pop()
            # else:
            #     defs = []
            #     for prev_head in prev_heads:
            #         if prev_head in range(f_start, f_end):
            #             result = Utils.def_analysis(prev_head, target_label=target)
            #             if type(result) is list: defs.extend(result)
            #             else: defs.append(result)
            #     return defs
        # TODO 当最终定值为传入参数
        # 有两处信息可以用，一是ida给出的func_data（根据protocol信息更新后），二是DB中对当前function的实时调用信息
        m = re.search('X(?P<reg_idx>\d)', t_base_reg or '')
        if m:
            reg_idx = int(m.group('reg_idx'))
            func_data = MachO.func_data_frm_ida[f_start] if f_start in MachO.func_data_frm_ida else None
            if func_data and reg_idx < len(func_data):
                reg_type = func_data[reg_idx].type.__str__()
                is_meta = True if '_meta *' in reg_type else False
                # todo，prototype中的类型可能无效，因此还需要进一步处理
                return [NSObject(reg_type.split('_meta *')[0].strip(' *'), is_meta=is_meta)]
        log('Utils.def_analysis_ps, result: {}'.format((t_base_reg, t_index_reg, t_displ)))
        return [NSObject('id', dp=(t_base_reg, t_index_reg, t_displ))]

    @staticmethod
    def resolve_displ(ea, base, offset_str=None, displ=None, steps=None):
        if offset_str and '@PAGEOFF' in offset_str:
            m = re.search('.*#selRef_(?P<sel>.+)@PAGEOFF', offset_str)
            if m:
                sel = m.group('sel').replace('_', ':')
                return NSObject('SEL', value=sel)
            m = re.search('.*#classRef_(?P<rec>.+)@PAGEOFF', offset_str)
            if m:
                rec = m.group('rec')
                return NSObject(rec, is_meta=True)
            m = re.search('.*#_OBJC_IVAR_\$_(?P<ivar>.+)@PAGEOFF', offset_str)
            if m:
                cls, ivar_name = m.group('ivar').split('.')  # POPAnimationEvent._time
                if cls in OCClass.pool_indexed_by_name and ivar_name in OCClass.pool_indexed_by_name[cls].ivars:
                    # 注意格式，IDA给出的 type 为Q、I、@NSString...格式
                    ivar_type = OCClass.pool_indexed_by_name[cls].ivars[ivar_name].strip('"@')
                    return NSObject(ivar_type)
            m = re.search('.*#qword_(?P<ea>.+)@PAGEOFF', offset_str)
            if m:
                ea = int(m.group('ea'), 16)
                return MachO.query_data_at_ea(ea)
            # #unk_1004463A8@PAGEOFF
            m = re.search('.*#unk_(?P<ea>.+)@PAGEOFF', offset_str)
            if m:
                ea = int(m.group('ea'), 16)
                if idc.SegName(ea) == '__const':
                    return NSObject('NSString', ea=ea)
        if displ:
            # 如果 base reg 是一个block
            base = Utils.def_analysis_ps(ea - INST_STEP, reg=base, steps=steps)[0]
            # 表明这是一个参数，且类型未知，我们查询该参数是否为一个Block
            if isinstance(base, NSObject) and base.type == 'id' and base.dp:
                f_start = idc.get_func_attr(ea, idc.FUNCATTR_START)
                if f_start in NSBlock.pool_indexed_by_sub:
                    block = NSBlock.pool_indexed_by_sub[f_start]
                    var_idx = (displ - 0x20) / 8
                    if len(block.imported_vars) > var_idx:
                        # notice， 这里注意，是直接返回block中的nsobject，而非新建，这就意味着类型会随时更新、关联
                        return block.imported_vars[var_idx]

        # m = re.search('\[(?P<opnd1>.+),(?P<opnd2>.+)\]', idc.GetOpnd(current_ea, 1))
        # if m:
        #     result = Utils.process_add(current_ea, m.group('opnd1'), m.group('opnd2'))
        #     if result:
        #         return [result]

    @staticmethod
    def resolve_phrase(ea, base_reg, index_reg, steps=None):
        result = Utils.def_analysis_ps(ea - INST_STEP, reg=index_reg, steps=steps)[0]
        if isinstance(result, NSObject):
            return result
        else:
            # todo, 检查是否有必要检查 base_reg
            return NSObject('id')


# 尽量将 Mach-O中的对象标识为NSObject，其type属性表示真正的类型；当type为'id'时表示在二进制中识别类型失败。
class NSObject:

    def __init__(self, t, ea=None, is_meta=False, value=None, dp=None):
        self.type = t
        self.is_meta = is_meta
        self.ea = ea
        self.val = value
        self.dp = dp

    @staticmethod
    def construct(str=None, ea=None, ret_frm=None):
        if str:
            m = re.search('.+#classRef_(?P<rec>.+)@PAGEOFF]', str)
            if m:
                return NSObject(m.group('rec'), is_meta=True)
        if ea:
            pass  # bss data
        if ret_frm:
            pass  # 方法调用的返回值
        return NSObject('id')  # 其实应该是unknown的，还可能是int之类的基本类型

    def get_super(self):
        super_type = 'id'
        if self.type in OCClass.pool_indexed_by_name:
            super_type = OCClass.pool_indexed_by_name[self.type].get_superclass()
        elif self.type in CacheInfo.cls_dict:
            super_type = CacheInfo.cls_dict[self.type].super or super_type
        return NSObject(super_type, is_meta=self.is_meta)


class NSBlock:
    pool = dict()
    pool_indexed_by_sub = dict()

    def __init__(self, ea):
        self.ea = ea  # 构造处的ea
        self.invoke = None
        self.signature = None
        self.imported_vars = []

    @staticmethod
    def construct(ea):
        # LDR X8, [X8,#__NSConcreteStackBlock_ptr@PAGEOFF]
        current_ea = ea
        f_start, f_end = idc.get_func_attr(current_ea, idc.FUNCATTR_START), idc.get_func_attr(current_ea,
                                                                                              idc.FUNCATTR_END)
        block_reg = idc.GetOpnd(current_ea, 0)
        block_stack_offset = None
        block = NSBlock(ea)
        offset_and_regs = dict()
        while current_ea != idc.BADADDR:
            mnem = idc.GetMnem(current_ea)
            if mnem == 'STR' and '[SP,' in idc.GetOpnd(current_ea, 1):
                if not block_stack_offset:
                    if idc.GetOpnd(current_ea, 0) == block_reg:
                        block_stack_offset = idc.get_operand_value(current_ea, 1)
                else:
                    offset_and_regs[idc.get_operand_value(current_ea, 1) - block_stack_offset] = \
                    Utils.def_analysis_ps(current_ea, reg=idc.GetOpnd(current_ea, 0))[0]

            elif block_stack_offset and mnem == 'STP' and '[SP,' in idc.GetOpnd(current_ea, 2):
                offset = idc.get_operand_value(current_ea, 2) - block_stack_offset
                offset_and_regs[offset] = Utils.def_analysis_ps(current_ea, reg=idc.GetOpnd(current_ea, 0))[0]
                offset_and_regs[offset + 0x08] = Utils.def_analysis_ps(current_ea, reg=idc.GetOpnd(current_ea, 1))[0]

            # 当block被用作参数时，block的信息收集结束（这样并不准确，但block import的参数又不确定）
            elif mnem == 'ADD' and idc.GetOpnd(current_ea, 1) == 'SP' and idc.get_operand_value(current_ea,
                                                                                                2) == block_stack_offset:
                break
            current_ea = idc.next_head(current_ea, f_end)

        for offset in sorted(offset_and_regs.keys()):
            if offset == 0x10:
                block.invoke = offset_and_regs[offset]
            elif offset == 0x18:
                block.signature = offset_and_regs[offset]
            elif offset >= 0x20:
                block.imported_vars.append(offset_and_regs[offset])
        return block

    @staticmethod
    def query_block_at(ea):
        if ea not in NSBlock.pool:
            block = NSBlock.construct(ea)
            NSBlock.pool[ea] = block
            if block.invoke:
                NSBlock.pool_indexed_by_sub[block.invoke] = block
        return NSBlock.pool[ea]


class OCRuntime:

    def __init__(self):
        pass

    @staticmethod
    def query_msg_handler(message):
        # 如果rec类型为基本类型，可否将其转换为NSObject
        if (not isinstance(message, Message)) or message.success:
            return
        sel, rec = message.sel.val if isinstance(message.sel, NSObject) else '', message.actual_responder or message.rec
        if not isinstance(rec, NSObject):
            return  # todo，rec可能是基本类型

        log('OCRuntime.query_handler, Message at {}, rec:{}, sel:{}'.format(hex(message.callsite), rec.type, sel))

        # receiver类型可识别
        if rec.type in OCClass.pool_indexed_by_name or rec.type in CacheInfo.cls_dict:
            receiver = '{}_meta *'.format(rec.type) if rec.is_meta else '{} *'.format(rec.type)
            # 首先尝试 handler 是否为二进制中的方法
            if receiver in MachO.funcs_index_by_rec and sel in MachO.funcs_index_by_rec[receiver]:
                message.success = True
                message.target = MachO.funcs_index_by_rec[receiver][sel]
            # 其次尝试 handler 是否为框架方法
            elif rec.type in CacheInfo.cls_dict:
                result = CacheInfo.cls_dict[rec.type].respond_to_sel(sel, message=message)
                if result:
                    message.success = True
                    message.ret = result
            if not message.success:
                message.actual_responder = rec.get_super()
                OCRuntime.query_msg_handler(message)

        # rec类型未知，根据selector进行猜测
        else:
            first_attempt = CacheInfo.cls_dict['NSProxy'].respond_to_sel(sel, message=message)
            if first_attempt:
                message.success = False  # ? 是否要将其归为成功？
                message.ret = first_attempt

            second_attempt = CacheInfo.cls_dict['NSObject'].respond_to_sel(sel, message=message)
            if second_attempt:
                message.success = False
                message.ret = second_attempt

            third_attempt = CacheInfo.cls_dict['NSString'].respond_to_sel(sel, message=message)
            if third_attempt:
                message.success = True
                message.ret = third_attempt
                rec.type = 'NSString'
                # 推测rec类型为'NSString'

            if sel in MachO.funcs_index_by_sel and sel not in CacheInfo.sel_dict:
                fuzzy_receivers = MachO.funcs_index_by_sel[sel]
                if len(fuzzy_receivers) == 1:
                    inferred_rec = fuzzy_receivers.keys()[0]
                    target = fuzzy_receivers[inferred_rec]
                    rec.is_meta = True if '_meta *' in inferred_rec else False
                    rec.type = inferred_rec.split('_meta *')[0].strip('*')
                    message.success = True
                    message.target = target
                else:
                    pass  # 对所有可能的message handler进行返回值求解有点太麻烦了，如果是framework method则相对简单

            if sel not in MachO.funcs_index_by_sel and sel in CacheInfo.sel_dict:
                fuzzy_receivers = CacheInfo.sel_dict[sel]
                if len(fuzzy_receivers) == 1:
                    inferred_rec = list(fuzzy_receivers)[0]
                    message.rec = NSObject(inferred_rec.name)  # todo，是否为Meta怎么判定
                    message.ret = inferred_rec.respond_to_sel(sel, message=message)
                    message.success = True
                else:
                    # 当无法确认handler时，对返回值的类型进行推断：当根据selector推测的所有handler返回值一致时，返回该类型。
                    fuzzy_ret = set()
                    for inferred_rec in fuzzy_receivers:
                        fuzzy_ret.add(inferred_rec.respond_to_sel(sel, message=message))
                    if len(fuzzy_ret) == 1:
                        message.ret = NSObject(fuzzy_ret.pop())

    # prototype中返回值类型为id，有两种可能：1）类型被抛弃 2）动态类型，返回值类型可能根据实时运行变化，因此使用id
    @staticmethod
    def query_ret(call):
        if isinstance(call, Message):
            log('OCRuntime.query_ret, Message at {}, handler: {}'.format(hex(call.callsite), call.target))
            if call.success:
                if call.target and call.target in MachO.oc_methods:
                    if call.ret is None and call.target in MachO.funcs_ret_id:  # 有必要求解 ret, ret未知且prototype中给出的无效
                        func = Func.analyze(call.target)
                        if func.rets:
                            call.ret = func.rets[0]  # todo, 一个message的返回值只能有一个，但一个message handler的返回值可能有多个
                    if call.ret is None:  # backward slicing失败(只能使用prototype)或者call的prototype有效
                        _ret_type = MachO.query_ret_from_prototype(call.target)
                        is_meta = True if '_meta *' in _ret_type else False  # todo，这句可能是冗余的
                        call.ret = NSObject(_ret_type.split('_meta *')[0].strip(' *'),
                                            is_meta=is_meta)  # todo 这里也可能出现void
                    return call.ret  # binary message， 已知 ret
                else:
                    return call.ret  # framework message，已知 ret
            else:
                return NSObject('id')  # message 解析失败, 但message的返回值又被需要，因此返回id
        elif isinstance(call, Call):  # C method, such as _NSStringFromClass
            pass
        else:
            return None


class Func:
    pool = dict()  # functions which have been analyzed

    def __init__(self, start_ea):
        self.start_ea = start_ea
        self.rets = []
        if self.start_ea in Func.pool:
            print 'AGAIN? WHY?'
        Func.pool[self.start_ea] = self

    @staticmethod
    def analyze(f, forced=False):
        if f in Func.pool and not forced:
            return Func.pool[f]
        func = Func(f)
        log('Analyze function at {}'.format(hex(func.start_ea)))
        func.run()
        return func

    def func_items(self):
        func = idaapi.get_func(self.start_ea)
        if not func:
            return
        fii = idaapi.func_item_iterator_t()
        ok = fii.set(func)
        while ok:
            yield fii.current()
            ok = fii.next_code()

    def run(self):
        for ea in list(self.func_items()):
            mnem = idc.GetMnem(ea)
            if mnem == 'BL':
                call = idc.GetOpnd(ea, 0)
                if call.startswith('_objc_msgSend'):
                    Message.analyze_messages_at_ea(ea)
                elif call.startswith('_dispatch'):
                    pass
            elif mnem == 'BR':
                pass
                # case 1: Newsstand 0x100005ECC, BR X8 ; switch jump
                # case 2: BR block_subroutine
            elif mnem == 'B':  # 可能是返回值语句
                if idc.GetOpnd(ea, 0) in ['_objc_autoreleaseReturnValue'] and self.start_ea in MachO.funcs_ret_id:
                    self.rets = Utils.def_analysis_ps(ea, reg_idx=0)
            elif mnem == 'RET' and self.start_ea in MachO.funcs_ret_id:
                self.rets = Utils.def_analysis_ps(ea, reg_idx=0)


class Call:

    def __init__(self, callsite, call):
        self.callsite = callsite
        self.func_name = call
        self.ctx = ida_funcs.get_func(self.callsite).startEA
        self.target = None
        self.ret = None  # this is a NSObject
        self.success = False


class Message(Call):

    def __init__(self, callsite, call, rec, sel, msg_args):
        Call.__init__(self, callsite, call)
        self.rec, self.sel, self.msg_args = rec, sel, msg_args
        self.actual_responder = None

    @staticmethod
    def analyze_messages_at_ea(ea):
        # message receiver、selector、arguments的解析最好还是路径敏感
        if ea not in DB.shared.edges:
            log('Analyze message(s) at {}'.format(hex(ea)))
            call = idc.GetOpnd(ea, 0)
            rec = Utils.def_analysis_ps(ea - INST_STEP, reg_idx=0)[0]
            sel = Utils.def_analysis_ps(ea - INST_STEP, reg_idx=1)[0]

            message = Message.construct_aMessage(ea, call, rec, sel)
            OCRuntime.query_msg_handler(message)
            message.resolve_msg()
            DB.shared.add_edge(message)
        message = DB.shared.edges[ea][0]
        print 'Message at ea: ', hex(ea), message.success, message.pprint()

    @staticmethod
    def construct_aMessage(ea, call, rec, sel):
        arg_offset, argc, args = 2, 0, []
        if isinstance(sel, NSObject) and sel.type == 'SEL':
            sel_string = sel.val or ''
            if sel_string.startswith('performSelector:onTarget:'):
                rec = Utils.def_analysis_ps(ea - INST_STEP, reg_idx=3)[0]
                sel = Utils.def_analysis_ps(ea - INST_STEP, reg_idx=2)[0]
            elif sel_string.startswith('performSelector'):
                sel = Utils.def_analysis_ps(ea - INST_STEP, reg_idx=2)[0]
                sel_string = sel.val or ''
                argc = sel_string.count('withObject:')
                arg_offset = 3
            else:
                argc = sel_string.count(':')

            # for idx in range(arg_offset, arg_offset + argc):
            #     args.append(Utils.def_analysis(ea - INST_STEP, reg_idx=idx))

            if call == '_objc_msgSendSuper2':
                pass

        return Message(ea, call, rec, sel, args)

    def resolve_msg(self):
        pass
        # if type(self.rec) is not NSObject:
        #     return
        #
        # if self.rec.type == 'NSUserDefaults *':
        #     self.ret = NSUserDefaults.handle_msg(self) or self.ret
        #
        # elif self.rec.type == 'NSNotificationCenter *':
        #     self.target = NSNotification.handle_msg(self) or self.target
        #
        # elif 'NSTimer' in self.rec.type:
        #     self.target = NSTimer.handle_msg(self) or self.target

        # 在以上特殊的message之外，如果message为framework method存在参数为Block，那么Block大概率是handler

    def pprint(self):
        return '{}[{} {}]'.format('+' if self.rec.is_meta else '-', self.rec.type, self.sel.val)


def run():
    prepared_pool = []
    # CacheInfo.build_from_pkl(r'E:\0_share\experiments\IDA\analysis\tools\FrameworkHeaders.pkl')
    DB.shared = DB()
    CacheInfo.build_from_dir(r'E:\0_share\experiments\IDA\analysis\headers')
    Protocol.build_from_IDA()
    OCClass.build_from_IDA()
    MachO.build()

    # 1: UIApplicationDelegate 方法
    if 'UIApplicationDelegate' in Protocol.pool_indexed_by_name:
        for p in Protocol.pool_indexed_by_name['UIApplicationDelegate']:
            for c in p.implementing_classes:
                app_delegate = OCClass.pool_indexed_by_ea[c]
                prepared_pool.extend(app_delegate.get_class_meths().values())
                prepared_pool.extend(app_delegate.get_instance_meths().values())
    # 2: init 方法
    prepared_pool.extend(MachO.funcs_index_by_sel['init'].values())
    # 3: 协议方法（根据协议中的方法原型更新func_data
    for ea, p in Protocol.pool_indexed_by_ea.items():
        cls = []
        for c in p.implementing_classes:
            cls.append(OCClass.pool_indexed_by_ea[c].name)
        for sel, func_type in p.meths.items():
            if sel in MachO.funcs_index_by_sel:
                for rec, f in MachO.funcs_index_by_sel[sel].items():
                    if Utils.nice_str(rec) in cls:
                        MachO.update_func_data(f, Utils.meth_type_parser(func_type))
                        prepared_pool.append(f)
    # 4: 没有参数的方法
    prepared_pool.extend(MachO.func_has_no_args)

    # print 'START: ', time.asctime(time.localtime(time.time()))
    while prepared_pool:
        Func.analyze(prepared_pool.pop(0))
    for f in MachO.oc_methods + MachO.subroutines:  # 在此前的分析过程中没有触发的方法，先OC后subroutine
        Func.analyze(f)
    print 'END: ', time.asctime(time.localtime(time.time()))

    # f = open(r'cg.pkl', 'wb')
    # pickle.dump([DB.shared.nodes, DB.shared.edges], f)
    # f.close()


def log(str):
    if LOG_ON:
        print '>>>', str
