import click
from ndsware.parsers.g2d import G2d
from PIL import Image

Pixel = tuple[int, int, int, int]

TILE_WIDTH = 8
TILE_HEIGHT = 8
GREY_SCALE = [(i * 17, i * 17, i * 17, 255) for i in range(16)]


def bgr555_to_rgb(colour: int) -> Pixel:
    """Converts from BGR555 2-byte format to RGB tuple format."""

    r = (colour & 0x1F) << 3
    g = ((colour >> 5) & 0x1F) << 3
    b = ((colour >> 10) & 0x1F) << 3
    return (r, g, b, 255)


def decode_palette(pltt_block: G2d.PlttBlock) -> list[Pixel]:
    """Decodes the raw palette data into a list of colour pixels."""

    palette_data = pltt_block.palette_data
    palette = []

    for i in range(0, len(palette_data), 2):
        colour_bytes = int.from_bytes(palette_data[i : i + 2], "little")
        colour = bgr555_to_rgb(colour_bytes)
        palette.append(colour)

    return palette


def decode_4bpp_tile(tile: bytes, palette: list[Pixel]) -> list[Pixel]:
    """
    Decodes the raw tile data into a list of coloured pixels.

    Each byte contains 2 pixels, one pixel per 4-bits. The 4-bits is integer
    that represents an index in the colour palette.
    """
    pixels = []

    for byte in tile:
        low_nibble = byte & 0x0F
        high_nibble = (byte >> 4) & 0x0F
        pixels.append(palette[low_nibble])
        pixels.append(palette[high_nibble])

    return pixels


def generate_tile_image(tile: bytes, palette: list[Pixel]) -> Image.Image:
    pixels = decode_4bpp_tile(tile, palette)

    tile_image = Image.new("RGBA", (TILE_WIDTH, TILE_HEIGHT))
    tile_image.putdata(pixels)

    return tile_image


def get_block(g2d: G2d, block_type: str) -> G2d.CharBlock | G2d.PlttBlock:
    """Get a block of a specific type from a parsed G2D file."""

    block: G2d.Block
    for block in g2d.blocks:
        if block.magic == block_type[::-1]:
            return block.data

    raise KeyError(f"Missing {block_type} block.")


@click.group()
def cli() -> None:
    """
    Extracts images stored using the G2D binary format.
    """


@cli.command()
@click.argument("ncgr_file", type=str)
@click.option("-p", "--nclr-file", type=str, help="Colour palette (.nclr) file path.")
@click.argument("tiles_per_row", type=int)
@click.argument("output_image_file", type=click.Path(exists=False))
def extract(ncgr_file: str, nclr_file: str, tiles_per_row: int, output_image_file: str) -> None:
    if not output_image_file.lower().endswith((".png", ".bmp")):
        raise click.BadParameter("Output file must be a valid image type (PNG or BMP).")

    if nclr_file:
        nclr = G2d.from_file(nclr_file)
        pltt_block: G2d.PlttBlock = get_block(nclr, "PLTT")
        palette = decode_palette(pltt_block)
    else:
        palette = GREY_SCALE

    ncgr = G2d.from_file(ncgr_file)
    char_block: G2d.CharBlock = get_block(ncgr, "CHAR")

    tiles = char_block.graphics_data.tiles
    tile_count = len(tiles)
    rows = (tile_count + tiles_per_row - 1) // tiles_per_row

    image = Image.new("RGBA", (tiles_per_row * TILE_WIDTH, rows * TILE_HEIGHT))

    for i, tile in enumerate(tiles):
        tile_image = generate_tile_image(tile, palette)

        # Calculate tile position in image.
        x = (i % tiles_per_row) * TILE_WIDTH
        y = (i // tiles_per_row) * TILE_HEIGHT

        # Paste tile into final image.
        image.paste(tile_image, (x, y))

    image.save(output_image_file)


if __name__ == "__main__":
    cli()
