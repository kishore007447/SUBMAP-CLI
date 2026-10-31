"""Banner module for SUBMAP."""
from rich.console import Console
from rich.text import Text
from submap import __version__, __author__, __author_handle__


BANNER = r"""
  ____  _   _ ____  __  __    _    ____
 / ___|| | | | __ )|  \/  |  / \  |  _ \
 \___ \| | | |  _ \| |\/| | / _ \ | |_) |
  ___) | |_| | |_) | |  | |/ ___ \|  __/
 |____/ \___/|____/|_|  |_/_/   \_\_|
"""


def print_banner(console: Console | None = None) -> None:
    """Print the SUBMAP ASCII banner with version info."""
    if console is None:
        console = Console()

    banner_text = Text(BANNER, style="bold cyan")
    console.print(banner_text)
    console.print(
        f"  [bold white]advanced subdomain discovery & attack surface mapping[/]\n"
        f"  [dim]created by[/] [bold yellow]{__author__}[/] [dim]([/][bold green]{__author_handle__}[/][dim])[/]"
        f"  [dim]v{__version__}[/]\n",
        highlight=False,
    )
