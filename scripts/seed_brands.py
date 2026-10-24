#!/usr/bin/env python3
"""Validate brands.json and print a summary."""

import json
from pathlib import Path

BRANDS_FILE = Path(__file__).parent.parent / "tridetect" / "data" / "brands.json"


def main():
    if not BRANDS_FILE.exists():
        print(f"ERROR: {BRANDS_FILE} not found")
        return

    with open(BRANDS_FILE, encoding="utf-8") as f:
        brands = json.load(f)

    total_aliases = sum(len(v) for v in brands.values())
    print(f"Brands loaded: {len(brands)}")
    print(f"Total aliases: {total_aliases}")
    print()
    for brand, aliases in brands.items():
        print(f"  {brand:20s}: {', '.join(aliases)}")


if __name__ == "__main__":
    main()
