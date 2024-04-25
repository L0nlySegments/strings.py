import c_string
from dataclasses import dataclass

MH_MAGIC = 0xfeedface
MH_CIGAM = 0xcefaedfe
MH_MAGIC_64 = 0xfeedfacf
MH_CIGAM_64 = 0xcffaedfe

MH_CIGAM_MULTI = 0xcafebabe

SIZE_HEADER = 32
SIZE_FILE_ENTRIES_MULTIARCH = 20
SIZE_LOAD_CMD = 8
SIZE_SEGMENT_STRUCT = 64

UINT_32 = 4
UINT_64 = 8

@dataclass
class File_Entries_Multiarch:
    CPU_Type: int
    CPU_Subtype: int
    File_offset: int
    Size: int
    Segment_align: int

@dataclass
class Header:
    Magic: int
    CPU_Type: int
    CPU_Subtype: int
    Type: int
    Num_of_load_cmds: int
    Size_of_load_cmds: int
    Flags: int
    Reserved: int


@dataclass
class Load_CMD:
    cmd_type: int
    cmd_size: int

@dataclass
class Load_CMD_Segement:
    name: str
    addr: int
    addr_size: int
    file_offset: int
    size: int
    max_vm_prot: int
    init_vm_prot: int
    num_of_sections: int
    flag32: int


@dataclass
class Segment:
    section_name: str
    segment_name: str
    section_addr: int
    section_size: int
    section_file_offset: int
    align: int
    relo_file_offset: int
    num_of_relo: int
    flag: int
    res_1: int
    res_2: int
    res_3: int


class Mach_Loader:
    def __init__(self, file):
        self.file = file
        self.file_idx = 0
        self.file_size = 0
        self.num_of_binaries = 0
        self.file_entries_multiarch = []
        self.headers = []
        self.load_cmds = []
        self.segments = []

    def read_struct(self, struct_size, type_size, byteorder):
        params = []
        for _ in range(0, struct_size, type_size):
            self.file.seek(self.file_idx)
            params.append(int.from_bytes(self.file.read(type_size), byteorder=byteorder))
            self.file_idx += type_size

        return params

    def read_load_segment_cmd_struct(self):
        params = []
        self.file.seek(self.file_idx)

        #read segment name (16 bytes)
        seg_name = c_string.read_c_string(self.file, self.file_idx, 16)
        params.append(seg_name)
        self.file_idx += 16
        self.file.seek(self.file_idx) #Make sure we and up at the right position, regardless of str length

        #read the next parameters (4 x uint64 and 4 x uint32)
        part_uint64 = self.read_struct(32, UINT_64, 'little')
        params += part_uint64

        part_uint32 = self.read_struct(16, UINT_32, 'little')
        params += part_uint32

        return params

    def read_segment_struct(self):
        params = []
        self.file.seek(self.file_idx)

        #read section name (16 bytes)
        sect_name = c_string.read_c_string(self.file, self.file_idx, 16)
        params.append(sect_name)
        self.file_idx += 16
        self.file.seek(self.file_idx) #Make sure we and up at the right position, regardless of str length

        #read segment name (16 bytes)
        seg_name = c_string.read_c_string(self.file, self.file_idx, 16)
        params.append(seg_name)
        self.file_idx += 16
        self.file.seek(self.file_idx) #Make sure we and up at the right position, regardless of str length

        #read the next parameters (2 x uint64 and 32 x uint32)
        part_uint64 = self.read_struct(16, UINT_64, 'little')
        params += part_uint64

        part_uint32 = self.read_struct(32, UINT_32, 'little')
        params += part_uint32

        return params
  
    def load_single_binary(self, bin_size):
        _file_idx = self.file_idx

        #read header
        header_params = self.read_struct(SIZE_HEADER, UINT_32, 'little')
        header = Header(*header_params)
        self.headers.append(header)

        lc_sublist = []
        seg_sublist = []
        #read load commands
        for _ in range(header.Num_of_load_cmds):
            lc_params = self.read_struct(SIZE_LOAD_CMD, UINT_32, 'little')
            lc_struct = Load_CMD(*lc_params)

            #load segment cmd
            if lc_struct.cmd_type == 0x19:
                lc_segment_params = self.read_load_segment_cmd_struct()
                lc_segment_struct = Load_CMD_Segement(*lc_segment_params)
                lc_sublist.append(lc_segment_struct)

                for _ in range(lc_segment_struct.num_of_sections):
                    segment_params = self.read_segment_struct()
                    segment_struct = Segment(*segment_params)
                    seg_sublist.append(segment_struct)
            else:
                self.file_idx += (lc_struct.cmd_size - SIZE_LOAD_CMD)
                self.file.seek(self.file_idx)

        self.load_cmds.append(lc_sublist)
        self.segments.append(seg_sublist)

        if bin_size != None:
            end_location = _file_idx + bin_size
            self.file.seek(end_location)
            self.file_idx = end_location

    def load(self): 
        self.file.seek(self.file_idx)
        magic_num = int.from_bytes(self.file.read(4), byteorder="big")

        if magic_num == MH_CIGAM:
            print("[!] 32 Bit Mach-O files are not supported")
            return

        if magic_num == MH_CIGAM_MULTI:
            self.file_idx += 4 #No need to save the magic num
            self.num_of_binaries = int.from_bytes(self.file.read(4), byteorder="big")

            self.file_idx += 4
            for _ in range(self.num_of_binaries):
                file_entries_multiarch_params = self.read_struct(SIZE_FILE_ENTRIES_MULTIARCH, UINT_32, 'big')
                file_entries_multiarch = File_Entries_Multiarch(*file_entries_multiarch_params)
                self.file_entries_multiarch.append(file_entries_multiarch)
            
            for entry in self.file_entries_multiarch:
                curr_byte = 0x0
                seek_inc = 0
                while curr_byte == 0x0:
                    curr_byte = int.from_bytes(self.file.read(4), byteorder="little")
                    seek_inc += 4

                self.file_idx += (seek_inc - 4)
                self.file.seek(self.file_idx)
                self.load_single_binary(entry.Size)
        else:
            if magic_num != MH_CIGAM_64:
                print("[!] File format not supported")
                return

            self.num_of_binaries = 1
            self.file.seek(self.file_idx) #reset this, since we are reading a normal header right away
            self.load_single_binary(None)

    def describe(self):
        if len(self.headers) == 0:
            print("[!] No Mach-O file loaded!")
            return
        
        print("\n=== Binaries ===")
        
        for binary_idx in range(self.num_of_binaries):
            print(f"\n=== BIN {binary_idx} ===")
            
            print("\n\t=== Headers ===")
            for header_idx, header in enumerate(self.headers):
                print(f'\n\t\tHEADER {header_idx}\n')
                header_info = vars(header)
                for key in header_info:
                    print(f'\t\t\t{key} : {hex(int(header_info[key]))}')

            print("\n\t=== Load CMDs ===")
            for lc_count, load_cmd in enumerate(self.load_cmds[binary_idx]):
                print(f"\n\t\t LOAD CMD {lc_count}")
                lc_info = vars(load_cmd)
                for key in lc_info:
                    if key == "name":
                        print(f"\t\t\t {key} : {lc_info[key]}")
                    else:
                        print(f"\t\t\t {key} : {hex(int(lc_info[key]))}")


            print("\n\t=== Sections ===")

            for seg_count, segment in enumerate(self.segments[binary_idx]):
                print(f"\n\t\t SEGMENT {seg_count}")
                seg_info = vars(segment)
                for key in seg_info:
                    if key == "section_name" or key == "segment_name":
                        print(f"\t\t\t {key} : {seg_info[key]}")
                    else:
                        print(f"\t\t\t {key} : {hex(int(seg_info[key]))}")

            print("\n")