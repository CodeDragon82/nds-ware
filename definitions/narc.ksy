meta:
  id: narc
  endian: le
  encoding: ascii
  file-extension: narc
  
seq:
  - id: header
    type: generic_header
  - id: file_allocation_table
    type: btaf
  - id: file_name_table
    type: btnf
  - id: file_section
    type: gmif
    
types:
  generic_header:
    seq:
      - id: magic
        contents: "NARC"
      - id: blob
        type: u4
      - id: section_size
        type: u4
      - id: header_size
        type: u2
      - id: section_count
        type: u2
  
  # File Allocation Table 
  btaf:
    seq:
      - id: magic
        contents: "BTAF"
      - id: section_size
        type: u4
      - id: file_count
        type: u4
      - id: entries
        type: btaf_entry
        repeat: expr
        repeat-expr: file_count
        
  btaf_entry:
    -webide-representation: '{start_offset}-{end_offset}'
    seq:
      - id: start_offset
        type: u4
      - id: end_offset
        type: u4
        
  # File Name Table
  btnf:
    seq:
      - id: magic
        contents: "BTNF"
      - id: section_size
        type: u4
      - id: directory_table
        type: directory_entry
        
  directory_entry:
    seq:
      - id: directory_start_offset
        type: u4
      - id: first_file_position
        type: u2
      - id: parent_directory
        type: u2
        
  # File Section
  gmif:
    seq:
      - id: magic
        contents: "GMIF"
      - id: section_size
        type: u4
      - id: files
        type: file(_root.file_allocation_table.entries[_index])
        repeat: expr
        repeat-expr: _root.file_allocation_table.file_count
        
  file:
    params:
      - id: info
        type: btaf_entry
    instances:
      data:
        pos: _io.pos + info.start_offset
        size: info.end_offset - info.start_offset
