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
    comments_only = []
    
    # This tracks the line number the comment *would* have had in the final stripped file
    stripped_line_number = 1 

    for line in lines:
        if line.lstrip().startswith('//'):
            # Extract the newline removal outside the f-string for older Python compatibility
            clean_comment = line.rstrip('\n')
            comments_only.append(f"{stripped_line_number}: {clean_comment}")
        else:
            stripped.append(line)
            stripped_line_number += 1

    base, ext = os.path.splitext(filepath)
    stripped_path = f"{base}.stripped{ext}"
    comments_path = f"{base}.comments{ext}"

    print(f"  Writing stripped code to: {stripped_path}")
    print(f"  Writing extracted comments to: {comments_path}")

    try:
        with open(stripped_path, 'w') as f:
            f.writelines(stripped)
            
        with open(comments_path, 'w') as f:
            # Join the formatted comments with newlines
            f.write('\n'.join(comments_only))
            # Add a final newline if there were any comments
            if comments_only:
                f.write('\n')
                
        print(f"  Success! Separated {len(comments_only)} comment lines")
    except Exception as e:
        print(f"  ERROR writing file: {e}")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <file.h> [file2.cc ...]")
        sys.exit(1)

    for filepath in sys.argv[1:]:
        strip_comments(filepath)
