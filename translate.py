class BaseTranslator():
    def __init__(self, base) -> None:
        self.base = base
    
    def read_1(self, mem: bytearray, addr: int):
        return self.read_n(mem, addr, 1)
    
    def read_2(self, mem: bytearray, addr: int):
        return self.read_n(mem, addr, 2)
    
    def read_4(self, mem: bytearray, addr: int):
        return self.read_n(mem, addr, 4)
    
    def read_8(self, mem: bytearray, addr: int):
        return self.read_n(mem, addr, 8)

    def read_n(self, mem: bytearray, addr: int, size: int):
        if size > 8:
            return 0
        offset = addr - self.base
        byte_val = mem[offset:offset+size]
        data = int.from_bytes(byte_val, "little")
        return data
    
    def pack(self, mem: bytearray, addr: int, size: int):
        offset = addr - self.base
        a = str(bytes(mem[offset:offset+size]))
        a = a[2:-1]
        return a
    
class NetlinkTranslator(BaseTranslator):
    def __init__(self, base, start):
        super().__init__(base)
        self.msg_addr = start
        self.msg = {}
        self.iov = {}
        self.nlh = {}
        self.nmsg = {}
        self.attr = {}
        
    def readbytes(self, file) -> bytearray:
        res = bytearray()
        with open(file, "rb") as f:
            while (byte := f.read(1)):
                res.append(ord(byte))
        return res

    def struct_assign(self, struct_name, field_name, data) -> str:
        s = getattr(self, struct_name)
        s[field_name] = data
        return "{}->{} = {};\n".format(struct_name, field_name, hex(data))

    def msghdr_assign(self, field_name, data) -> str:# -> Any:
        return self.struct_assign("msg", field_name, data)

    def iovec_assign(self, field_name, data) -> str:
        return self.struct_assign("iov", field_name, data)

    def nlmsghdr_assign(self, field_name, data) -> str:
        return self.struct_assign("nlh", field_name, data)
    
    def nmsg_assign(self, field_name, data) -> str:
        return self.struct_assign("nmsg", field_name, data)
    
    def attr_assign(self, field_name, data) -> str:
        return self.struct_assign("attr", field_name, data)

    def code_new_line(self, line):
        return line + '\n'

    def build_msghdr(self, mem) -> str:
        """
        msg->msg_name u64
        msg->msg_namelen u16
        msg->msg_iov = iov u64
        msg->msg_iovlen u64
        msg->msg_control u64
        msg->msg_controllen u64
        msg->msg_flags u32
        """

        code = "struct msghdr *msg = (struct msghdr *){};\n".format(hex(self.msg_addr))
        code += self.msghdr_assign("msg_name", self.read_8(mem, self.msg_addr))
        code += self.msghdr_assign("msg_namelen", self.read_4(mem, self.msg_addr + 8))
        self.msghdr_assign("msg_pad1", self.read_4(mem, self.msg_addr + 12))
        code += self.msghdr_assign("msg_iov", self.read_8(mem, self.msg_addr + 16))
        code += self.msghdr_assign("msg_iovlen", self.read_8(mem, self.msg_addr + 24))
        code += self.msghdr_assign("msg_control", self.read_8(mem, self.msg_addr + 32))
        code += self.msghdr_assign("msg_controllen", self.read_8(mem, self.msg_addr + 40))
        code += self.msghdr_assign("msg_flags", self.read_4(mem, self.msg_addr + 48))
        return code + '\n'

    def build_iovec(self, mem) -> str:
        """
        iov->iov_base u64
        iov->iov_len u64
        """
        
        code = "struct iovec *iov = (struct iovec *){};\n".format(hex(self.msg["msg_iov"]))
        code += self.iovec_assign("iov_base", self.read_8(mem, self.msg["msg_iov"]))
        code += self.iovec_assign("iov_len", self.read_8(mem, self.msg["msg_iov"] + 8))
        return code + '\n'

    def build_nlmsghdr(self, mem) -> str:
        """
        nlh->nlmsg_len u32
        nlh->nlmsg_type u16
        nlh->nlmsg_flags u16
        nlh->nlmsg_seq u32
        nlh->nlmsg_pid u32
        """
        code = "struct nlmsghdr *nlh = (struct nlmsghdr *){};\n".format(hex(self.iov["iov_base"]))
        code += self.nlmsghdr_assign("nlmsg_len", self.read_4(mem, self.iov["iov_base"]))
        code += self.nlmsghdr_assign("nlmsg_type", self.read_2(mem, self.iov["iov_base"] + 4))
        code += self.nlmsghdr_assign("nlmsg_flags", self.read_2(mem, self.iov["iov_base"] + 6))
        code += self.nlmsghdr_assign("nlmsg_seq", self.read_4(mem, self.iov["iov_base"] + 8))
        code += self.nlmsghdr_assign("nlmsg_pid", self.read_4(mem, self.iov["iov_base"] + 12))
        return code + '\n'

    def build_nmsg(self, mem) -> str:
        if self.nlh["nlmsg_type"] == 44:
            code = self._build_tcmsg(mem)
            self.nmsg_size = 20 # 4 bytes padding
            self.attr_addr = self.nmsg_addr + self.nmsg_size # 4 bytes padding
            self.attr_len = self.nlh["nlmsg_len"] - 16 - self.nmsg_size
            return code + '\n'
            
    def build_attr(self, mem) -> str:
        """
        len u16
        type u16
        --------
        appending data
        """
        n = 0
        code = "struct rtattr *rta{} = (struct rtattr*)(NLMSG_DATA(nlh)+{});\n".format(n, self.nmsg_size)
        
        while (self.attr_len > 0):
            code += self.attr_assign("rta_len", self.read_2(mem, self.attr_addr))
            code += self.attr_assign("rta_type", self.read_2(mem, self.attr_addr+2))
            self.attr_addr += 4
            payload_len = self.attr["rta_len"] - 4
            code += "memcpy(&rta{}[1], \"{}\", {});\n".format(n, self.pack(mem, self.attr_addr, payload_len), payload_len)
            code += "struct rtattr *rta{0} = (struct rtattr*)((char*)rta{1}+rta{1}->rta_len);\n".format(n+1, n)
            self.attr_len -= self._rta_align(self.attr["rta_len"])
            self.attr_addr += self._rta_align(payload_len)
            n += 1
        return code + '\n'

    def translate(self, file):
        code = ""
        mem = self.readbytes(file)
        code += self.build_msghdr(mem)
        code += self.build_iovec(mem)
        code += self.build_nlmsghdr(mem)
        code += self.build_nmsg(mem)
        code += self.build_attr(mem)
        return code

    def _build_tcmsg(self, mem) -> str:
        """
        u8    tcm_family;
        u8                tcm__pad1
	    u16              tcm__pad2
        u32              tcm_ifindex;
        u32            tcm_handle;
        u32            tcm_parent;
        u32            tcm_info;
        """
        self.nmsg_addr =  self.iov["iov_base"] + 16
        code = "struct tcmsg *nmsg = (struct tcmsg*)NLMSG_DATA(nlh);\n"
        code += self.nmsg_assign("tcm_family", self.read_1(mem, self.nmsg_addr))
        code += self.nmsg_assign("tcm__pad1", self.read_1(mem, self.nmsg_addr + 1))
        code += self.nmsg_assign("tcm__pad2", self.read_2(mem, self.nmsg_addr + 2))
        code += self.nmsg_assign("tcm_ifindex", self.read_4(mem, self.nmsg_addr + 4))
        code += self.nmsg_assign("tcm_handle", self.read_4(mem, self.nmsg_addr + 8))
        code += self.nmsg_assign("tcm_parent", self.read_4(mem, self.nmsg_addr + 12))
        code += self.nmsg_assign("tcm_info", self.read_4(mem, self.nmsg_addr + 16))
        return code
    
    def _rta_align(self, size):
        if size // 4 * 4 < size:
            return (size // 4 + 1) * 4
        return size