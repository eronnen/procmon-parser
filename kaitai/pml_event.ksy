meta:
  id: pml_event
  title: Process Monitor Log Event
  endian: le
  ks-opaque-types: true
doc-ref: https://github.com/eronnen/procmon-parser/blob/master/docs/PML%20Format.md
params:
  - id: is_64bit
    type: u4
seq:
  - id: process_index
    type: u4
  - id: thread_id
    type: u4
  - id: event_class
    type: u4
    enum: pml_event_class
  - id: operation
    type: u2
  - id: reserved1
    type: u2
  - id: reserved2
    type: u4
  - id: duration
    type: u8
  - id: date
    type: u8
  - id: result
    type: u4
  - id: stacktrace_depth
    type: u2
  - id: reserved3
    type: u2
  - id: details_size
    type: u4
  - id: reserved4
    type: u4
  - id: stacktrace
    type: pvoid(is_64bit)
    repeat: expr
    repeat-expr: stacktrace_depth
  - id: details
    type:
      switch-on: event_class
      cases:
        pml_event_class::process: pml_process_details
        pml_event_class::registry: pml_registry_details
        pml_event_class::network: pml_network_details
        pml_event_class::profiling: pml_profiling_details
        pml_event_class::filesystem: pml_filesystem_details


############## Event Details ##################
types:
  dummy: {}
  pvoid:
    params:
      - id: is_64bit
        type: u4
    seq:
      - id: value
        type:
          switch-on: is_64bit
          cases:
            0:  u4
            1:  u8

  detail_string_info:
    seq:
      - id: info
        type: u2
    instances:
      is_ascii:
        value: info >> 15
      char_count:
        value: info & 32767  # low 15 bits

  detail_string:
    params:  # TODO: get only one detail_string_info parameter...
      - id: is_ascii
        type: u2
      - id: char_count
        type: u2
    seq:
      - id: string
        type:
          switch-on: is_ascii
          cases:
            0: utf16_string(char_count * 2)
            1: ascii_string(char_count)

  pml_network_flags:
    seq:
      - id: flags
        type: u2
    instances:
      is_source_ipv4:
        value: (flags & 1) != 0
      is_dest_ipv4:
        value: (flags & 2) != 0
      is_tcp:
        value: (flags & 4) != 0

  pml_network_details:
    seq:
      - id: flags
        type: pml_network_flags
      - id: reserved2
        type: u2
      - id: packet_length
        type: u4
      - id: source_host_ip
        size: 16
      - id: dest_host_ip
        size: 16
      - id: source_port
        type: u2
      - id: dest_port
        type: u2
      - id: extra_details
        type: utf16_multisz

  pml_registry_details_load_rename:
    seq:
      - id: reserved
        size: 2

  pml_registry_details_open_create:
    seq:
      - id: reserved
        size: 6

  pml_registry_details_query:
    seq:
      - id: reserved
        size: 10

  pml_registry_details_set_enum:
    seq:
      - id: reserved
        size: 14

  pml_registry_details:
    seq:
      - id: path_info
        type: detail_string_info
      - id: extra_details
        type:
          switch-on: _parent.operation
          cases:
            pml_registry_operation::reg_load_key.to_i: pml_registry_details_load_rename
            pml_registry_operation::reg_rename_key.to_i: pml_registry_details_load_rename
            pml_registry_operation::reg_open_key.to_i: pml_registry_details_open_create
            pml_registry_operation::reg_create_key.to_i: pml_registry_details_open_create
            pml_registry_operation::reg_query_key.to_i: pml_registry_details_query
            pml_registry_operation::reg_query_value.to_i: pml_registry_details_query
            pml_registry_operation::reg_set_value.to_i: pml_registry_details_set_enum
            pml_registry_operation::reg_set_info_key.to_i: pml_registry_details_set_enum
            pml_registry_operation::reg_enum_value.to_i: pml_registry_details_set_enum
            pml_registry_operation::reg_enum_key.to_i: pml_registry_details_set_enum
            _: dummy
      - id: path
        type: detail_string(path_info.is_ascii, path_info.char_count)

  pml_filesystem_query_directory_details:
    seq:
      - id: directory_name_info
        type: detail_string_info
      - id: directory_name
        type: detail_string(directory_name_info.is_ascii, directory_name_info.char_count)

  pml_filesystem_directory_control_details:
    seq:
      - id: sub_operation_details
        type:
          switch-on: _parent.sub_operation
          cases:
            pml_filesystem_directory_control_operation::query_directory.to_i: pml_filesystem_query_directory_details
            _: dummy


  pml_filesystem_details:
    seq:
      - id: sub_operation
        type: u1
      - id: reserved1
        type: u1
      - id: reserved2
        type: pvoid(_root.is_64bit)
        repeat: expr
        repeat-expr: 5
      - id: reserved3
        size: 0x16
      - id: path_info
        type: detail_string_info
      - id: reserved4
        type: u2
      - id: path
        type: detail_string(path_info.is_ascii, path_info.char_count)
      - id: extra_details
        type:
          switch-on: _parent.operation
          cases:
            pml_filesystem_operation::directory_control.to_i: pml_filesystem_directory_control_details
            _: dummy

  pml_process_created_details:
    seq:
      - id: reserved1
        type: u4
      - id: created_pid
        type: u4
      - id: reserved2
        size: 0x24
      - id: size1
        type: u1
      - id: size2
        type: u1
      - id: path_info
        type: detail_string_info
      - id: command_line_info
        type: detail_string_info
      - id: reserved3
        type: u2
      - id: reserved4
        size: size1 + size2
      - id: path
        type: detail_string(path_info.is_ascii, path_info.char_count)
      - id: command_line
        type: detail_string(command_line_info.is_ascii, command_line_info.char_count)

  pml_process_started_details:
    seq:
      - id: parent_pid
        type: u4
      - id: command_line_info
        type: detail_string_info
      - id: current_directory_info
        type: detail_string_info
      - id: environment_size
        type: u4
      - id: command_line
        type: detail_string(command_line_info.is_ascii, command_line_info.char_count)
      - id: current_directory
        type: detail_string(current_directory_info.is_ascii, current_directory_info.char_count)
      - id: environment
        type: sized_utf16_multisz(environment_size * 2)

  pml_load_image_details:
    seq:
      - id: image_base
        type: pvoid(_root.is_64bit)
      - id: image_size
        type: u4
      - id: path_info
        type: detail_string_info
      - id: reserved1
        type: u2
      - id: path
        type: detail_string(path_info.is_ascii, path_info.char_count)

  pml_thread_exit_details:
    seq:
      - id: reserved1
        type: u4
      - id: kernel_time
        type: u8
      - id: user_time
        type: u8

  pml_process_details:
    seq:
      - id: extra_details
        type:
          switch-on: _parent.operation
          cases:
            pml_process_operation::process_defined.to_i: pml_process_created_details
            pml_process_operation::process_create.to_i: pml_process_created_details
            pml_process_operation::process_exit.to_i: dummy
            pml_process_operation::thread_create.to_i: dummy
            pml_process_operation::thread_exit.to_i: pml_thread_exit_details
            pml_process_operation::load_image.to_i: pml_load_image_details
            pml_process_operation::thread_profile.to_i: dummy
            pml_process_operation::process_start.to_i: pml_process_started_details
            pml_process_operation::process_statistics.to_i: dummy
            pml_process_operation::system_statistics.to_i: dummy
            _: dummy

  pml_profiling_details:
    seq:
      - id: bytes
        size: _parent.details_size


############## Enumeration ##################
enums:
  pml_event_class:
    0: unknown
    1: process
    2: registry
    3: filesystem
    4: profiling
    5: network

  pml_process_operation:
    0: process_defined
    1: process_create
    2: process_exit
    3: thread_create
    4: thread_exit
    5: load_image
    6: thread_profile
    7: process_start
    8: process_statistics
    9: system_statistics

  pml_registry_operation:
    0: reg_open_key
    1: reg_create_key
    2: reg_close_key
    3: reg_query_key
    4: reg_set_value
    5: reg_query_value
    6: reg_enum_value
    7: reg_enum_key
    8: reg_set_info_key
    9: reg_delete_key
    10: reg_delete_value
    11: reg_flush_key
    12: reg_load_key
    13: reg_unload_key
    14: reg_rename_key
    15: reg_query_multiple_value_key
    16: reg_set_key_security
    17: reg_query_key_security

  pml_network_operation:
    0: unknown
    1: other
    2: send
    3: receive
    4: accept
    5: connect
    6: disconnect
    7: reconnect
    8: retransmit
    9: tcp_copy

  pml_profiling_operation:
    0: thread_profiling
    1: process_profiling
    2: debug_output_profiling

  pml_filesystem_operation:
    0: volume_dismount
    1: volume_mount
    2: fastio_mdl_write_complete
    3: write_file2
    4: fastio_mdl_read_complete
    5: read_file2
    6: query_open
    7: fastio_check_if_possible
    8: irp_mj_12
    9: irp_mj_11
    10: irp_mj_10
    11: irp_mj_9
    12: irp_mj_8
    13: fastio_notify_stream_fo_creation
    14: fastio_release_for_cc_flush
    15: fastio_acquire_for_cc_flush
    16: fastio_release_for_mod_write
    17: fastio_acquire_for_mod_write
    18: fastio_release_for_section_synchronization
    19: create_file_mapping
    20: create_file
    21: create_pipe
    22: irp_mj_close
    23: read_file
    24: write_file
    25: query_information_file
    26: set_information_file
    27: query_e_a_file
    28: set_e_a_file
    29: flush_buffers_file
    30: query_volume_information
    31: set_volume_information
    32: directory_control
    33: file_system_control
    34: device_io_control
    35: internal_device_io_control
    36: shutdown
    37: lock_unlock_file
    38: close_file
    39: create_mail_slot
    40: query_security_file
    41: set_security_file
    42: power
    43: system_control
    44: device_change
    45: query_file_quota
    46: set_file_quota
    47: plug_and_play

  pml_filesystem_query_volume_information_operation:
    1: query_information_volume
    2: query_label_information_volume
    3: query_size_information_volume
    4: query_device_information_volume
    5: query_attribute_information_volume
    6: query_control_information_volume
    7: query_full_size_information_volume
    8: query_object_id_information_volume

  pml_filesystem_set_volume_information_operation:
    1: set_control_information_volume
    2: set_label_information_volume
    8: set_object_id_information_volume

  pml_filesystem_query_file_information_operation:
    4: query_basic_information_file
    5: query_standard_information_file
    6: query_file_internal_information_file
    7: query_ea_information_file
    9: query_name_information_file
    14: query_position_information_file
    18: query_all_information_file
    20: query_end_of_file
    22: query_stream_information_file
    28: query_compression_information_file
    29: query_id
    31: query_move_cluster_information_file
    34: query_network_open_information_file
    35: query_attribute_tag_file
    37: query_id_both_directory
    39: query_valid_data_length
    40: query_short_name_information_file
    43: query_io_piority_hint
    46: query_links
    48: query_normalized_name_information_file
    49: query_network_physical_name_information_file
    50: query_id_global_tx_directory_information
    51: query_is_remote_device_information
    52: query_attribute_cache_information
    53: query_numa_node_information
    54: query_standard_link_information
    55: query_remote_protocol_information
    56: query_rename_information_bypass_access_check
    57: query_link_information_bypass_access_check
    58: query_volume_name_information
    59: query_id_information
    60: query_id_extd_directory_information
    62: query_hard_link_full_id_information
    63: query_id_extd_both_directory_information
    67: query_desired_storage_class_information
    68: query_stat_information
    69: query_memory_partition_information

  pml_filesystem_set_file_information_operation:
    4: set_basic_information_file
    10: set_rename_information_file
    11: set_link_information_file
    13: set_disposition_information_file
    14: set_position_information_file
    19: set_allocation_information_file
    20: set_end_of_file_information_file
    22: set_file_stream_information
    23: set_pipe_information
    39: set_valid_data_length_information_file
    40: set_short_name_information
    61: set_replace_completion_information
    64: set_disposition_information_ex
    65: set_rename_information_ex
    66: set_rename_information_ex_bypass_access_check

  pml_filesystem_directory_control_operation:
    1: query_directory
    2: notify_change_directory

  pml_filesystem_pnp_operation:
    0: start_device
    1: query_remove_device
    2: remove_device
    3: cancel_remove_device
    4: stop_device
    5: query_stop_device
    6: cancel_stop_device
    7: query_device_relations
    8: query_interface
    9: query_capabilities
    10: query_resources
    11: query_resource_requirements
    12: query_device_text
    13: filter_resource_requirements
    15: read_config
    16: write_config
    17: eject
    18: set_lock
    19: query_id2
    20: query_pnp_device_state
    21: query_bus_information
    22: device_usage_notification
    23: surprise_removal
    24: query_legacy_bus_information

  pml_filesystem_lock_unlock_operation:
    1: lock_file
    2: unlock_file_single
    3: unlock_file_all
    4: unlock_file_by_key