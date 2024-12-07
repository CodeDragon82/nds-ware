from parsers.nds import Nds
import argparse
import os

CODE_FOLDER = "code"
FILES_FOLDER = "files"

def setup_arguments():
    parser = argparse.ArgumentParser(description="Extracts data from key sections of the NDS ROM such as game code and files.")
    parser.add_argument("nds_file")
    parser.add_argument("output_dir")
    
    return parser

def extract_files(nds, output_dir):
    for i in range(len(nds.files)):
        file_data = nds.files[i].data
        file_name = str(i)
        file_path = os.path.join(output_dir, file_name)
        open(file_path, "wb").write(file_data)

def main():
    parser = setup_arguments()
    args = parser.parse_args()

    nds = Nds.from_file(args.nds_file)

    code_dir = os.path.join(args.output_dir, CODE_FOLDER)
    files_dir = os.path.join(args.output_dir, FILES_FOLDER)
    
    os.makedirs(code_dir, exist_ok=True)
    os.makedirs(files_dir, exist_ok=True)
    
    extract_files(nds, files_dir)
    
if __name__ == "__main__":
    main()
