import click
from ndsware.parsers.g2d import G2d
from PIL import Image

TILE_WIDTH = 8
TILE_HEIGHT = 8
GREY_SCALE = [(i * 17, i * 17, i * 17, 255) for i in range(16)]


def decode_4bpp_tile(tile: bytes) -> list[tuple[int, int, int, int]]:
    pixels = []

    for byte in tile:
        low_nibble = byte & 0x0F
        high_nibble = (byte >> 4) & 0x0F
        pixels.append(GREY_SCALE[low_nibble])
        pixels.append(GREY_SCALE[high_nibble])

    return pixels


def generate_tile_image(tile: bytes) -> Image.Image:
    pixels = decode_4bpp_tile(tile)

    tile_image = Image.new("RGBA", (TILE_WIDTH, TILE_HEIGHT))
    tile_image.putdata(pixels)

    return tile_image


def get_char_block(ncgr: G2d) -> G2d.CharBlock:
    block: G2d.Block
    for block in ncgr.blocks:
        if block.magic == "RAHC":
            return block.data

    raise KeyError("Missing CHAR block.")


@click.group()
def cli() -> None:
    """
    Extracts images stored using the G2D binary format.
    """


@cli.command()
@click.argument("ncgr_file", type=str)
@click.argument("nclr_file", type=str)
@click.argument("tiles_per_row", type=int)
@click.argument("output_image_file", type=click.Path(exists=False))
def extract(ncgr_file: str, nclr_file: str, tiles_per_row: int, output_image_file: str) -> None:
    if not output_image_file.lower().endswith((".png", ".bmp")):
        raise click.BadParameter("Output file must be a valid image type (PNG or BMP).")

    ncgr = G2d.from_file(ncgr_file)
    nclr = G2d.from_file(nclr_file)

    tiles = get_char_block(ncgr).graphics_data.tiles

    tile_count = len(tiles)
    rows = (tile_count + tiles_per_row - 1) // tiles_per_row

    image = Image.new("RGBA", (tiles_per_row * TILE_WIDTH, rows * TILE_HEIGHT))

    for i, tile in enumerate(tiles):
        tile_image = generate_tile_image(tile)

        # Calculate tile position in image.
        x = (i % tiles_per_row) * TILE_WIDTH
        y = (i // tiles_per_row) * TILE_HEIGHT

        # Paste tile into final image.
        image.paste(tile_image, (x, y))

    image.save(output_image_file)


if __name__ == "__main__":
    cli()
