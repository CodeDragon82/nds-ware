meta:
  id: narc
  endian: le
  encoding: ascii
  file-extension: narc
  
seq:
  - id: header
    type: generic_header
  - id: file_allocation_table
    type: section
  - id: file_name_table
    type: section
  - id: file_section
    type: section
    
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
        
  section:
    seq:
      - id: magic
        type: str
        size: 4
      - id: size
        type: u4
      - id: data
        type:
          switch-on: magic
          cases:
            '"BTAF"': btaf
            '"BTNF"': btnf
            '"GMIF"': gmif
        size: size - 8
  
  ### File Allocation Table ###
  
  btaf:
    seq:
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
        
  ### File Name Table ###
  
  btnf:
    seq:
      - id: directory_table
        type: directory_table
      - id: directories
        type: directory
        repeat: expr
        repeat-expr: directory_table.count
        if: _parent.size > 16
        
  directory_table:
    -webide-representation: 'count: {root.directory_count}'
    instances:
      count:
        value: root.directory_count
    seq:
      - id: root
        type: root_entry
      - id: directories
        type: directory_entry((_index + 1) | 0xF000)
        repeat: expr
        repeat-expr: root.directory_count - 1
        
  root_entry:
    seq:
      - id: start_offset
        type: u4
      - id: first_file_position
        type: u2
      - id: directory_count
        type: u2
    
  directory_entry:
    -webide-representation: 'id: {directory_id}, parent: {parent_directory}'
    params:
      - id: directory_id
        type: u4
    seq:
      - id: start_offset
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
        
  ### File Section ###
  
  gmif:
    instances:
      fat:
        value: _root.file_allocation_table.data.as<btaf>
    seq:
      - id: files
        type: file(fat.entries[_index])
        repeat: expr
        repeat-expr: fat.file_count
        
  file:
    params:
      - id: info
        type: btaf_entry
    instances:
      data:
        pos: _io.pos + info.start_offset
        size: info.end_offset - info.start_offset
