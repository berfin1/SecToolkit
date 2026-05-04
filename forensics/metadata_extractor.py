#!/usr/bin/env python3
"""
SecToolkit - Metadata Extractor
Extracts EXIF and metadata information from image files.
WARNING: Use only on systems you are authorized to access.
Requirement: pip install Pillow
"""

import os
import sys
import json
import argparse
from datetime import datetime

try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
except ImportError:
    print("[!] Pillow is not installed. Run: pip install Pillow")
    sys.exit(1)

SUPPORTED_FORMATS = {'.jpg', '.jpeg', '.png', '.tiff', '.tif', '.webp', '.bmp', '.gif'}


def banner():
    print("""
╔══════════════════════════════════════════╗
║     SecToolkit - Metadata Extractor      ║
║   Extracts EXIF data from image files    ║
╚══════════════════════════════════════════╝
    """)


def get_gps_coordinates(gps_info):
    """Converts raw GPS data to decimal coordinates."""
    def to_decimal(values):
        d = float(values[0])
        m = float(values[1])
        s = float(values[2])
        return d + (m / 60.0) + (s / 3600.0)

    try:
        lat = to_decimal(gps_info.get('GPSLatitude', (0, 0, 0)))
        lat_ref = gps_info.get('GPSLatitudeRef', 'N')
        lon = to_decimal(gps_info.get('GPSLongitude', (0, 0, 0)))
        lon_ref = gps_info.get('GPSLongitudeRef', 'E')

        if lat_ref == 'S':
            lat = -lat
        if lon_ref == 'W':
            lon = -lon

        return lat, lon
    except Exception:
        return None, None


def extract_exif(filepath):
    """Extracts EXIF data from an image file."""
    result = {
        'file': filepath,
        'file_size': os.path.getsize(filepath),
        'basic_info': {},
        'exif_data': {},
        'gps_info': {},
        'thumbnail': False,
        'warnings': []
    }

    ext = os.path.splitext(filepath)[1].lower()
    if ext not in SUPPORTED_FORMATS:
        result['warnings'].append(f"Unsupported format: {ext}")
        return result

    try:
        img = Image.open(filepath)

        # Basic image info
        result['basic_info'] = {
            'Format'    : img.format or 'Unknown',
            'Mode'      : img.mode,
            'Width'     : img.size[0],
            'Height'    : img.size[1],
            'Pixels'    : f"{img.size[0] * img.size[1]:,}",
        }

        # EXIF data
        exif_raw = img._getexif() if hasattr(img, '_getexif') else None
        if exif_raw:
            gps_raw = {}
            for tag_id, value in exif_raw.items():
                tag = TAGS.get(tag_id, str(tag_id))

                # Handle GPS data separately
                if tag == 'GPSInfo':
                    for gps_tag_id, gps_val in value.items():
                        gps_tag = GPSTAGS.get(gps_tag_id, str(gps_tag_id))
                        gps_raw[gps_tag] = gps_val
                    continue

                # Skip thumbnail
                if tag == 'JPEGThumbnail':
                    result['thumbnail'] = True
                    continue

                # Convert bytes to string
                if isinstance(value, bytes):
                    try:
                        value = value.decode('utf-8', errors='replace').strip()
                    except Exception:
                        value = str(value)

                result['exif_data'][tag] = str(value)

            # Process GPS coordinates
            if gps_raw:
                lat, lon = get_gps_coordinates(gps_raw)
                result['gps_info'] = {
                    'raw': {k: str(v) for k, v in gps_raw.items()},
                    'coordinates': f"{lat:.6f}, {lon:.6f}" if lat and lon else None,
                    'google_maps': f"https://maps.google.com/?q={lat},{lon}" if lat and lon else None
                }
        else:
            result['warnings'].append("No EXIF data found (PNG, GIF, or file without EXIF).")

    except Exception as e:
        result['warnings'].append(f"Read error: {str(e)}")

    return result


def print_result(result, json_output=False):
    """Prints the extraction results."""
    if json_output:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return

    print(f"\n{'='*50}")
    print(f"  FILE: {os.path.basename(result['file'])}")
    print(f"  Size: {result['file_size']:,} bytes")
    print(f"{'='*50}")

    if result['basic_info']:
        print("\n[*] BASIC INFO")
        for k, v in result['basic_info'].items():
            print(f"  {k:<15}: {v}")

    if result['exif_data']:
        print(f"\n[*] EXIF DATA ({len(result['exif_data'])} fields)")
        priority = ['Make', 'Model', 'Software', 'DateTime', 'DateTimeOriginal',
                    'ExifImageWidth', 'ExifImageHeight', 'Flash', 'FocalLength',
                    'ISOSpeedRatings', 'ExposureTime', 'FNumber', 'WhiteBalance',
                    'Artist', 'Copyright', 'ImageDescription']
        shown = set()
        for key in priority:
            if key in result['exif_data']:
                print(f"  {key:<25}: {result['exif_data'][key]}")
                shown.add(key)
        for k, v in result['exif_data'].items():
            if k not in shown:
                print(f"  {k:<25}: {v}")
    else:
        print("\n[i] No EXIF data found.")

    if result['gps_info']:
        print("\n[!] GPS LOCATION FOUND (Privacy risk!)")
        if result['gps_info'].get('coordinates'):
            print(f"  Coordinates  : {result['gps_info']['coordinates']}")
            print(f"  Google Maps  : {result['gps_info']['google_maps']}")
        for k, v in result['gps_info'].get('raw', {}).items():
            print(f"  {k:<20}: {v}")
    else:
        print("\n[OK] No GPS data found.")

    if result['thumbnail']:
        print("\n[i] Embedded thumbnail found in file.")

    if result['warnings']:
        print("\n[!] WARNINGS")
        for w in result['warnings']:
            print(f"  - {w}")

    print(f"\n{'='*50}\n")


def scan_directory(directory):
    """Scans all supported image files in a directory."""
    results = []
    for root, _, files in os.walk(directory):
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext in SUPPORTED_FORMATS:
                fpath = os.path.join(root, fname)
                print(f"[*] Processing: {fpath}")
                results.append(extract_exif(fpath))
    return results


def main():
    parser = argparse.ArgumentParser(
        description="SecToolkit Metadata Extractor",
        epilog=(
            "Examples:\n"
            "  python metadata_extractor.py -f photo.jpg\n"
            "  python metadata_extractor.py -d ./images\n"
            "  python metadata_extractor.py -f photo.jpg --json\n"
            "  python metadata_extractor.py -f photo.jpg -o result.json --json"
        )
    )
    parser.add_argument("-f", "--file", help="Single file analysis")
    parser.add_argument("-d", "--dir", help="Scan all images in a directory")
    parser.add_argument("--json", action="store_true", help="Output in JSON format")
    parser.add_argument("-o", "--output", help="Save result to file")

    args = parser.parse_args()

    if not args.file and not args.dir:
        parser.print_help()
        sys.exit(1)

    banner()

    if args.file:
        result = extract_exif(args.file)
        print_result(result, args.json)
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(result, f, ensure_ascii=False, indent=2)
            print(f"[OK] Saved: {args.output}")

    elif args.dir:
        results = scan_directory(args.dir)
        print(f"\n[OK] Processed {len(results)} files.")
        for r in results:
            print_result(r, args.json)
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(results, f, ensure_ascii=False, indent=2)
            print(f"[OK] Bulk result saved: {args.output}")


if __name__ == "__main__":
    main()