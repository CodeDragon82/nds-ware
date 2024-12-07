meta:
  id: nds
  endian: le
  encoding: ascii
  file-extension: nds

enums:
  unit_code_enum:
    0: nds
    2: nds_dsi
    3: dsi

types:
  header:
    seq:
      - id: game_title
        type: str
        size: 12
      - id: game_code
        size: 4
      - id: maker_code
        type: str
        size: 2
      - id: unit_code
        type: u1
        enum: unit_code_enum
      - id: encryption_seed
        type: u1
      - id: device_capcity
        type: u1
      - id: reserved
        size: 7
      - id: game_revision
        size: 2
      - id: rom_version
        type: u1
      - id: internal_flags
        type: u1
      - id: arm9
        type: code_section_info
      - id: arm7
        type: code_section_info
      - id: fnt_info
        type: section_info
      - id: fat_info
        type: section_info
      - id: arm9_overlay
        type: section_info
      - id: arm7_overlay
        type: section_info
      - id: normal_card_control_register_settings
        size: 4
      - id: secure_card_control_register_settings
        size: 4
      - id: icon_banner_offset
        type: u4
      - id: secure_area_crc
        type: u2
      - id: secure_transfer_timeout
        type: u2
      - id: arm9_autoload
        type: u4
      - id: arm7_autoload
        type: u4
      - id: secure_disable
        type: u8
      - id: ntr_region_rom_size
        type: u4
      - id: header_size
        type: u4
      - id: reserved2
        size: 56
      - id: nintendo_logo
        size: 156
      - id: nintendo_logo_crc
        type: u2
      - id: header_crc
        type: u2
      - id: debugger_reserved
        size: 32
  
  extended_header:
    seq:
      - id: global_mbk1_5_settings
        size: 20
      - id: local_mbk6_8_settings_for_arm9
        size: 12
      - id: local_mbk6_8_settings_for_arm7
        size: 12
      - id: global_mdk9_setting
        size: 4
      - id: region_flags
        size: 4
      - id: access_control
        size: 4
      - id: arm7_scrg_ext_mask
        size: 4
      - id: reserved
        size: 4
      - id: arm9i
        type: code_section_info
      - id: arm7i
        type: code_section_info
      - id: digest_ntr_region
        type: section_info
      - id: digest_twl_region
        type: section_info
      - id: digest_sector_hashtable
        type: section_info
      - id: digest_block_hashtable
        type: section_info
      - id: digest_section_size
        type: u4
      - id: digest_block_sectorcount
        type: u4
      - id: icon_banner_size
        type: u4
      - id: un1
        type: u4
      - id: ntr_twl_region_rom_size
        type: u4
      - id: un2
        size: 12
      - id: modcrypt_area_1
        type: section_info
      - id: modcrypt_area_2
        type: section_info
      - id: tital_id
        type: u8

  code_section_info:
    -webide-representation: '{offset} {size:dec}B'
    seq:
      - id: offset
        type: u4
      - id: entry_address
        type: u4
      - id: load_address
        type: u4
      - id: size
        type: u4
  
  section_info:
    -webide-representation: '{offset} {size:dec}B'
    seq:
      - id: offset
        type: u4
      - id: size
        type: u4
        
  code_section:
    -webide-representation: '{info}'
    params:
      - id: info
        type: code_section_info
    instances:
      data:
        pos: info.offset
        size: info.size
  
  ### File Name Table ###      
  
  file_name_table:
    seq:
      - id: magic
        type: u4
      - id: section_size
        type: u2
      - id: directory_count
        type: u2
      - id: directory_table
        type: directory_entry(_index + 1)
        repeat: expr
        repeat-expr: directory_count - 1
      - id: directories
        type: directory
        repeat: expr
        repeat-expr: directory_count
        
  directory_entry:
    -webide-representation: 'id:{id} parent_id:{parent_directory}'
    params:
      - id: id
        type: u4
    seq:
      - id: directory_offset
        type: u4
      - id: first_file_position
        type: u2
      - id: parent_directory
        type: u2
        
  directory:
    -webide-representation: '{content}'
    seq:
      - id: content
        type: directory_content
        terminator: 0
  
  directory_content:
    -webide-representation: '{files}'
    seq:
      - id: files
        type: file_entry
        repeat: eos
        
  file_entry: 
    -webide-representation: '{name}:{directory_id}'
    seq:
      - id: flag
        type: file_flag
      - id: name
        type: str
        size: flag.name_length
      - id: directory_id
        type: u2
        if: flag.is_directory
        
  file_flag:
    seq:
      - id: is_directory
        type: b1
      - id: name_length
        type: b7
  
  ##### #####
  
  ### File Allocation Table ###
        
  fat_entry:
    -webide-representation: '{start_offset}-{end_offset}'
    seq:
      - id: start_offset
        type: u4
      - id: end_offset
        type: u4
  
  ##### #####
  
  string:
    -webide-representation: '{value}'
    seq:
      - id: length
        type: u1
      - id: value
        size: length
        type: str
  
  ### Overlay Table ###      
  
  overlay_table:
    seq:
      - id: entries
        type: overlay_entry
        repeat: eos
        
  overlay_entry:
    -webide-representation: 'index: {index:dec}'
    seq:
      - id: index
        type: u4
      - id: base_address
        type: u4
      - id: length
        type: u4
      - id: bss_size
        type: u4
      - id: start_address
        type: u4
      - id: end_address
        type: u4
      - id: file_id
        type: u4
      - id: reserved
        type: u4
        
   ##### #####
  
  file:
    -webide-representation: '{info}'
    params:
      - id: info
        type: fat_entry
    instances:
      data:
        pos: info.start_offset
        size: info.end_offset - info.start_offset
        
  overlay:
    params:
      - id: info
        type: overlay_entry
    instances:
      data:
        pos: info.start_address
        size: info.length

seq:
  - id: header
    type: header
  - id: extended_header
    type: extended_header
  - id: files
    type: file(file_allocation_table[_index])
    repeat: expr
    repeat-expr: file_allocation_table.size
  - id: arm9
    type: code_section(header.arm9)
  - id: arm7
    type: code_section(header.arm7)
  - id: arm9i
    type: code_section(extended_header.arm9i)
  - id: arm7i
    type: code_section(extended_header.arm7i)
  - id: arm9_overlays
    type: overlay(arm9_overlay_table.entries[_index])
    repeat: expr
    repeat-expr: arm9_overlay_table.entries.size
  - id: arm7_overlays
    type: overlay(arm7_overlay_table.entries[_index])
    repeat: expr
    repeat-expr: arm7_overlay_table.entries.size
  
instances:
  file_name_table:
    pos: header.fnt_info.offset
    size: header.fnt_info.size
    type: file_name_table
  file_allocation_table:
    pos: header.fat_info.offset
    type: fat_entry
    repeat: expr
    repeat-expr: header.fat_info.size / 8
  arm9_overlay_table:
    pos: header.arm9_overlay.offset
    size: header.arm9_overlay.size
    type: overlay_table
  arm7_overlay_table:
    pos: header.arm7_overlay.offset
    size: header.arm7_overlay.size
    type: overlay_table