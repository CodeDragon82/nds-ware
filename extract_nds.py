from parsers.nds import Nds
import argparse
import os

CODE_FOLDER = "code"
FILES_FOLDER = "files"
FILE_EXTENSIONS = {
    b"SDAT": ".sdat",
    b"NARC": ".narc"
}

file_index = 0

def setup_arguments():
    parser = argparse.ArgumentParser(description="Extracts data from key sections of the NDS ROM such as game code and files.")
    parser.add_argument("nds_file")
    parser.add_argument("output_dir")
    
    return parser

def extract_directory(nds, directory, output_dir):
    global file_index
    
    for file in reversed(directory.content.files):
        print(file.name)
        if file.flag.is_directory:
            new_output_dir = os.path.join(output_dir, file.name)
            os.makedirs(new_output_dir, exist_ok=True)
            
            next_directory_index = file.directory_id & 0xFF
            next_directory = nds.file_name_table.directories[next_directory_index]
            extract_directory(nds, next_directory, new_output_dir)
        else:
            file_path = os.path.join(output_dir, file.name)
            file_data = nds.files[file_index].data
            open(file_path, "wb").write(file_data)
            file_index += 1

def extract_files(nds, output_dir):
    global file_index
    file_index = 0
    
    root = nds.file_name_table.directories[0]
    extract_directory(nds, root, output_dir)
        
def extract_code(nds, output_dir):
    code_files = [
        ("arm7", nds.arm7),
        ("arm7i", nds.arm7i),
        ("arm9", nds.arm9),
        ("arm9i", nds.arm9i)
    ]
    
    for file_name, code in code_files:
        file_path = os.path.join(output_dir, file_name)
        open(file_path, "wb").write(code.data)
        
    extract_overlays(nds.arm7_overlays, os.path.join(output_dir, "arm7_overlays"))
    extract_overlays(nds.arm9_overlays, os.path.join(output_dir, "arm9_overlays"))
        
def extract_overlays(overlays, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    
    for i in range(len(overlays)):
        overlay_code = overlays[i].data
        file_name = str(i)
        file_path = os.path.join(output_dir, file_name)
        open(file_path, "wb").write(overlay_code)

def main():
    parser = setup_arguments()
    args = parser.parse_args()

    nds = Nds.from_file(args.nds_file)

    code_dir = os.path.join(args.output_dir, CODE_FOLDER)
    files_dir = os.path.join(args.output_dir, FILES_FOLDER)
    
    os.makedirs(code_dir, exist_ok=True)
    os.makedirs(files_dir, exist_ok=True)
    
    extract_files(nds, files_dir)
    extract_code(nds, code_dir)
    
if __name__ == "__main__":
    main()
