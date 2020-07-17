meta:
  id: pml
  title: Process Monitor Log
  file-extension: PML
  endian: le
  ks-opaque-types: true
doc-ref: https://github.com/eronnen/procmon-parser/blob/master/docs/PML%20Format.md
seq:
  - id: header
    type: pml_header
instances:
  events_offsets_table:
    pos: header.events_offsets_array_offset
    type: pml_event_offset
    repeat: expr
    repeat-expr: header.number_of_events
  strings_table:
    pos: header.strings_table_offset
    type: pml_strings_table
  process_table:
    pos: header.process_table_offset
    type: pml_process_table
  network_tables:
    pos: header.hosts_and_ports_tables_offset
    type: pml_network_tables

types:
  pml_header:
    seq:
      - id: signature
        contents: PML_
      - id: version
        type: u4
      - id: is_64bit
        type: u4
      - id: desktop_name
        type: str
        size: 0x20
        encoding: UTF-16LE
      - id: system_root
        type: str
        size: 0x208
        encoding: UTF-16LE
      - id: number_of_events
        type: u4
      - id: reserved1
        type: u8
      - id: events_offset
        type: u8
      - id: events_offsets_array_offset
        type: u8
      - id: process_table_offset
        type: u8
      - id: strings_table_offset
        type: u8
      - id: unknown_table_offset
        type: u8
      - id: reserved2
        type: u8
      - id: reserved3
        type: u4
      - id: windows_major_number
        type: u4
      - id: windows_minor_number
        type: u4
      - id: windows_build_number
        type: u4
      - id: windows_build_number_after_decimal_point
        type: u4
      - id: service_pack_name
        type: str
        size: 0x32
        encoding: UTF-16LE
      - id: reserved4
        size: 0xd6
      - id: number_of_logical_processors
        type: u4
      - id: ram_memory_size
        type: u8
      - id: header_size
        type: u8
      - id: hosts_and_ports_tables_offset
        type: u8

  pvoid:
    seq:
      - id: value
        type:
          switch-on: _root.header.is_64bit
          cases:
            0:  u4
            1:  u8

  sized_utf16_cstring:
    seq:
      - id: len
        type: u4
      - id: string
        type: utf16_string(len)

  pml_event_offset:
    seq:
      - id: offset
        type: u4
      - id: flags
        type: u1

  pml_strings_table:
    seq:
      - id: number_of_strings
        type: u4
      - id: string_offsets  
        type: u4
        repeat: expr
        repeat-expr: number_of_strings
      - id: strings
        type: sized_utf16_cstring
        repeat: expr
        repeat-expr: number_of_strings  # TODO: use string_offsets instead of this array?

  pml_module:
    seq:
      - id: reserved1
        type: pvoid
      - id: base_address
        type: pvoid
      - id: size
        type: u4
      - id: path_string_index
        type: u4
      - id: version_string_index
        type: u4
      - id: company_string_index
        type: u4
      - id: description_string_index
        type: u4
      - id: timestamp
        type: u4
      - id: reserved2
        type: u8
      - id: reserved3
        type: u8
      - id: reserved4
        type: u8

  pml_process:
    seq:
      - id: process_index
        type: u4
      - id: process_id
        type: u4
      - id: parent_process_id
        type: u4
      - id: reserved1
        type: u4
      - id: authentication_id
        type: u8
      - id: session
        type: u4
      - id: reserved3
        type: u4
      - id: start_time
        type: u8
      - id: end_time
        type: u8
      - id: virtualized
        type: u4
      - id: is_process_64bit
        type: u4
      - id: integrity_string_index
        type: u4
      - id: user_string_index
        type: u4
      - id: process_name_string_index
        type: u4
      - id: image_path_string_index
        type: u4
      - id: command_line_string_index
        type: u4
      - id: company_string_index
        type: u4
      - id: version_string_index
        type: u4
      - id: description_string_index
        type: u4
      - id: reserved4
        type: pvoid
      - id: reserved5
        type: u8
      - id: number_of_modules
        type: u4
      - id: modules
        type: pml_module
        repeat: expr
        repeat-expr: number_of_modules

  pml_process_table:
    seq:
      - id: number_of_processes
        type: u4
      - id: process_indexes
        type: u4
        repeat: expr
        repeat-expr: number_of_processes
      - id: process_offsets  
        type: u4
        repeat: expr
        repeat-expr: number_of_processes
      - id: processes
        type: pml_process
        repeat: expr
        repeat-expr: number_of_processes

  pml_hostname:
    seq:
      - id: ip
        size: 16
      - id: name
        type: sized_utf16_cstring

  pml_port:
    seq:
      - id: port
        type: u2
      - id: is_tcp
        type: u2
      - id: name
        type: sized_utf16_cstring

  pml_hostnames_table:
    seq:
      - id: number_of_hostnames
        type: u4
      - id: hostnames
        type: pml_hostname
        repeat: expr
        repeat-expr: number_of_hostnames

  pml_ports_table:
    seq:
      - id: number_of_ports
        type: u4
      - id: ports
        type: pml_port
        repeat: expr
        repeat-expr: number_of_ports

  pml_network_tables:
    seq:
      - id: hostnames_table
        type: pml_hostnames_table
      - id: ports_table
        type: pml_ports_table
