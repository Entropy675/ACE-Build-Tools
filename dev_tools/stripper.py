#!/usr/bin/env python3
import sys
import os

def strip_comments(filepath):
    print(f"Processing: {filepath}")
    
    if not os.path.exists(filepath):
        print(f"  ERROR: File not found!")
        return

    with open(filepath, 'r') as f:
        lines = f.readlines()

    print(f"  Read {len(lines)} lines")

    stripped = []
    for line in lines:
        if line.lstrip().startswith('//'):
            continue
        stripped.append(line)

    base, ext = os.path.splitext(filepath)
    outpath = f"{base}.stripped{ext}"

    print(f"  Writing to: {outpath}")

    try:
        with open(outpath, 'w') as f:
            f.writelines(stripped)
        print(f"  Success! Removed {len(lines) - len(stripped)} comment lines")
    except Exception as e:
        print(f"  ERROR writing file: {e}")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <file.h> [file2.cc ...]")
        sys.exit(1)

    for filepath in sys.argv[1:]:
        strip_comments(filepath)
