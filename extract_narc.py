import os
from argparse import ArgumentParser, Namespace

from parsers.narc import Narc

TOOL_DESCRIPTION = "Extracts files for a Nintendo Archive (NARC)."


def parse_arguments() -> Namespace:
    parser = ArgumentParser(description=TOOL_DESCRIPTION)
    parser.add_argument(
        "narc_file", type=str, help="File path to the NARC file to extract."
    )
    parser.add_argument(
        "output_dir",
        type=str,
        help="Directory that files are extracted to.",
    )

    return parser.parse_args()


def main() -> None:
    args = parse_arguments()

    narc = Narc.from_file(args.narc_file)

    os.makedirs(args.output_dir, exist_ok=True)

    i = 0
    for file in narc.file_section.files:
        file_path = os.path.join(args.output_dir, str(i))
        open(file_path, "wb").write(file.data)
        i += 1


if __name__ == "__main__":
    main()
