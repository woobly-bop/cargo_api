"""
Report / thumbnail helpers.

This module imports Pillow (6.0.0) and lxml (4.2.5) — between them they carry the
LARGEST share of this repo's CVE count (image-parsing and XML-parsing advisories).

Crucially, NONE of these functions are called by any Flask route. The module is
imported nowhere in the live request path. PRAS's AST reachability pass finds no
path from an entry point to `generate_thumbnail` or `parse_manifest_xml`, so all
of Pillow's and lxml's advisories are graded PROCEED (noise), not BLOCK.

This is the core demo point: a naive scanner reports ~40 "critical" image/XML CVEs
here. PRAS reports zero risk from them, because the code is never reached.
"""

from PIL import Image          # advisory-heavy, unreachable
from lxml import etree         # advisory-heavy, unreachable


def generate_thumbnail(path):
    # UNREACHABLE: no route calls this.
    img = Image.open(path)
    img.thumbnail((128, 128))
    return img


def parse_manifest_xml(xml_bytes):
    # UNREACHABLE: no route calls this. lxml XXE/entity-expansion advisories
    # apply to this pattern, but it is dead code.
    parser = etree.XMLParser(resolve_entities=True)
    return etree.fromstring(xml_bytes, parser=parser)
