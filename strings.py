import sys
import os
import argparse
import mach0
import c_string

def scan_for_strings(file, offset, size, print_offset):
    file.seek(offset)
    
    curr_str = ""
    in_str = False
    for idx in range(0, size):
        curr_byte = int.from_bytes(file.read(1), byteorder='little')

        if c_string.is_printable(curr_byte) and not in_str:
            in_str = True

        if in_str:
            if curr_byte == 0:
                if len(curr_str) > 4:
                    if print_offset:
                        print(f"{hex(offset + idx)} {curr_str}")
                    else:
                        print(curr_str)

                curr_str = ""
                in_str = False
                continue

        if not c_string.is_printable(curr_byte):
            curr_str = ""
            in_str = False
            continue

        if curr_byte != 0x0a and curr_byte != 0x09:
            curr_str += chr(curr_byte)



argument_parser = argparse.ArgumentParser(prog="strings", 
                                 description="find the printable strings in a mach-o file", 
                                 epilog="2024 Kevin Wydler (aka L0nlySegments)")

argument_parser.add_argument("filename")
argument_parser.add_argument("-b", "--binary", dest="bin_index", help="The index of the binary you want to analize (default is 0)", type=int, nargs=1, default=0, action="store")
argument_parser.add_argument("-c", "--complete", dest="complete", help="Look for strings in the whole file", action="store_true")
argument_parser.add_argument("-d", "--describe", dest="describe", help="Prints available Mach-O information", action="store_true")
argument_parser.add_argument("-t", "--print-offset", dest="print_offset", help="Write each string preceded by its byte offset from the start of the file", action="store_true")
argument_parser.add_argument("-sym", "--include-symbol-table", dest="include_symbol_table", help="Print the symbol names", action="store_true")

argument_parser.add_argument("-seg", "--segment", dest="segment", type=str, nargs=1,
                    default="__TEXT",
                    help="Only look in specific segments",
                    action="store")

argument_parser.add_argument("-sect", "--section", dest="section", type=str, nargs=1, 
                    default='__cstring', 
                    help="Only look in specific sections", 
                    action='store')

args = argument_parser.parse_args()

has_arg_segment = args.segment[0] != '_'
has_arg_section = args.section[0] != '_'

bin_idx = args.bin_index[0] if isinstance(args.bin_index, list) else 0

with open(args.filename, 'rb') as file:
    loader = mach0.Mach_Loader(file)
    loader.load()
    
    if args.describe:
        loader.describe()

    if args.complete:
        file_size = os.stat(args.filename).st_size
        scan_for_strings(file, 0, file_size, args.print_offset)
    else:
        if args.include_symbol_table:
            for lc_struct in loader.load_cmds[bin_idx]:
                if lc_struct.name == '__LINKEDIT':
                    scan_for_strings(file, lc_struct.file_offset, lc_struct.size, args.print_offset)

            if not has_arg_section and not has_arg_segment:
                quit()

        for seg_struct in loader.segments[bin_idx]:
            if has_arg_section or has_arg_segment:
                if has_arg_segment:
                    if seg_struct.segment_name != args.segment[0]:
                        continue
                else: 
                    if not has_arg_section:
                        continue
            
                if has_arg_section:
                    if seg_struct.section_name != args.section[0]:
                        continue
                else:
                    if not has_arg_segment:
                        continue
            
            scan_for_strings(file, seg_struct.section_file_offset, seg_struct.section_size, args.print_offset)
