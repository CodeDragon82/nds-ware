meta:
  id: g2d
  endian: le
  encoding: utf-8

seq:
  - id: header
    type: header
  - id: blocks
    type: block
    repeat: expr
    repeat-expr: header.block_count
    
types:
  header:
    -webide-representation: '{magic}'
    seq:
      - id: magic
        type: str
        size: 4
      - id: byte_order
        type: u2
      - id: version
        type: u2
      - id: file_size
        type: u4
      - id: header_size
        type: u2
      - id: block_count
        type: u2

  block:
    -webide-representation: '{magic}'
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
            '"TTLP"': pltt_block
            '"RAHC"': char_block
            
  #####################
  #### NCLR Blocks ####
  #####################
        
  pltt_block:
    seq:
      - id: colour_format
        type: u4
      - id: extended_palette
        type: u4
      - id: palette_data_size
        type: u4
      - id: palette_data_offset
        type: u4
    
    instances:
      palette_data:
        pos: _io.pos - 16 + palette_data_offset
        size: palette_data_size
        
  #####################
  #### NCGR Blocks ####
  #####################
  
  char_block:
    seq:
      - id: width
        type: u2
      - id: height
        type: u2
      - id: colour_format
        type: u4
      - id: mapping_mode
        type: u4
      - id: graphics_type
        type: u4
      - id: graphics_data_size
        type: u4
      - id: graphics_data_offset
        type: u4
      - id: graphics_data
        type: graphics_data
        size: graphics_data_size
        
  graphics_data:
    seq:
      - id: tiles
        size: 32
        repeat: eos