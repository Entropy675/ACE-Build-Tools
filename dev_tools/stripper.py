#!/usr/bin/env python3
import sys
import os
import re
import json

# Regex explanation:
# Group 1: Matches strings ("..." or '...') to ignore them.
# Group 2: Matches block comments /* ... */ or contiguous // lines
PATTERN = re.compile(
    r'("(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\')|'  # Group 1: Strings (ignores them)
    r'(/\*.*?\*/|//[^\r\n]*(?:\r?\n[ \t]*//[^\r\n]*)*)', # Group 2: Block comments OR contiguous // lines
    re.DOTALL
)

def do_strip(filepath):
    print(f"[STRIP] Processing: {filepath}")
    
    if not os.path.exists(filepath):
        print("  FATAL ERROR: File not found!")
        sys.exit(1)

    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    comments_db = {}
    counter = 1

    def replacer(match):
        nonlocal counter
        string_literal = match.group(1)
        comment = match.group(2)

        # If it's a string, leave it completely untouched
        if string_literal:
            return string_literal

        # If it's a comment, process and tokenize it
        if comment:
            # Transform contiguous // into block comments
            if comment.startswith('//'):
                lines = comment.split('\n')
                # Strip leading whitespace, '//', and an optional single space
                cleaned_lines = [re.sub(r'^[ \t]*//[ \t]?', '', line) for line in lines]
                cleaned_lines = [
                    line.replace('\u2014', '-')  # Em dash
                        .replace('\u2013', '-')  # En dash
                        .replace('\u2500', '-')  # En dash
                        .replace('\u2192', '-->') # Rightwards arrow
                    for line in cleaned_lines
                ]

                if len(cleaned_lines) == 1:
                    # Single-line comment becomes an inline block
                    formatted_comment = [f"// {cleaned_lines[0]}"]
                else:
                    # Multi-line comment becomes a formatted C-style block
                    formatted_comment = ["/*"] + [f" * {line}" if line else " *" for line in cleaned_lines] + [" */"]
            else:
                # It's already a block comment (/* ... */), just split it for JSON formatting
                formatted_comment = comment.split('\n')

            token = f"/*@C{counter}@*/"
            # Storing as a list makes json.dump format it cleanly on separate lines
            comments_db[token] = formatted_comment
            counter += 1
            return token

    # Apply the regex replacement
    stripped_content = PATTERN.sub(replacer, content)

    base, ext = os.path.splitext(filepath)
    stripped_path = f"{base}.stripped{ext}"
    db_path = f"{base}.comments.json"

    # Write the stripped code
    with open(stripped_path, 'w', encoding='utf-8') as f:
        f.write(stripped_content)

    # Write the comments database
    with open(db_path, 'w', encoding='utf-8') as f:
        json.dump(comments_db, f, indent=2)

    print(f"  Saved {len(comments_db)} comment blocks to {db_path}")
    print(f"  Stripped code saved to {stripped_path}\n")


def apply_tokens(content, comments_db):
    """Helper to inject tokens back into content."""
    for token, comment_data in comments_db.items():
        # Join the list of strings back into a single multi-line string
        if isinstance(comment_data, list):
            original_comment = '\n'.join(comment_data)
        else:
            original_comment = comment_data
            
        content = content.replace(token, original_comment)
    return content


def do_merge_from_source(db_path, source_path):
    """Merge tokens into a source file and output a .merged. version"""
    print(f"[MERGE] Processing: {db_path} + {source_path}")
    
    if not os.path.exists(db_path):
        print(f"  FATAL ERROR: Missing comments JSON file ({db_path}).")
        sys.exit(1)
        
    if not os.path.exists(source_path):
        print(f"  FATAL ERROR: Missing source file ({source_path}).")
        sys.exit(1)

    with open(db_path, 'r', encoding='utf-8') as f:
        comments_db = json.load(f)

    with open(source_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Check if the original file actually contains any of our tokens
    tokens_found = any(token in content for token in comments_db.keys())

    if tokens_found:
        content = apply_tokens(content, comments_db)
        
        # Generate the .merged. version
        base_no_ext, ext = os.path.splitext(source_path)
        merged_path = f"{base_no_ext}.merged{ext}"
        
        with open(merged_path, 'w', encoding='utf-8') as f:
            f.write(content)

        print(f"  Successfully restored {len(comments_db)} comment blocks into {merged_path}\n")
    else:
        print("  WARNING: No comment tokens found in the source file. Nothing to merge.\n")


def do_merge(filepath):
    """Standard merge from a .stripped. file back to the original file"""
    print(f"[MERGE] Processing: {filepath}")
    
    if '.stripped.' not in filepath:
        print("  FATAL ERROR: Invalid file passed to standard merge. Expecting .stripped. file.")
        sys.exit(1)

    stripped_path = filepath
    base_path = filepath.replace('.stripped.', '.', 1)
    db_path = os.path.splitext(base_path)[0] + '.comments.json'

    if not os.path.exists(stripped_path) or not os.path.exists(db_path):
        print("  FATAL ERROR: Missing stripped code or comments JSON file.")
        sys.exit(1)

    with open(db_path, 'r', encoding='utf-8') as f:
        comments_db = json.load(f)

    with open(stripped_path, 'r', encoding='utf-8') as f:
        content = f.read()

    content = apply_tokens(content, comments_db)

    # Overwrite the original file with the restored codebase
    with open(base_path, 'w', encoding='utf-8') as f:
        f.write(content)

    print(f"  Successfully restored {len(comments_db)} comment blocks into {base_path}\n")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <file.ext | file.stripped.ext | file.comments.json source.ext | .> [...]")
        sys.exit(1)

    # SPECIAL CASE: If exactly two files are passed, and one is .comments.json, 
    # trigger the explicit source-merge mode.
    if len(sys.argv) == 3:
        arg1, arg2 = sys.argv[1], sys.argv[2]
        if arg1.endswith('.comments.json') and not arg2.endswith('.comments.json'):
            do_merge_from_source(arg1, arg2)
            sys.exit(0)
        elif arg2.endswith('.comments.json') and not arg1.endswith('.comments.json'):
            do_merge_from_source(arg2, arg1)
            sys.exit(0)

    # NORMAL PROCESSING LOOP
    files_to_process = set()
    script_path = os.path.abspath(sys.argv[0])

    for arg in sys.argv[1:]:
        if arg == '.':
            # Target every file in the local directory
            for item in os.listdir('.'):
                if os.path.isfile(item) and os.path.abspath(item) != script_path:
                    # Ignore generated files in bulk mode to avoid a strip/merge loop
                    if ".stripped." not in item and ".comments.json" not in item:
                        files_to_process.add(item)
        elif os.path.isdir(arg):
            # Extend functionality to any provided directory path
            for item in os.listdir(arg):
                full_path = os.path.join(arg, item)
                if os.path.isfile(full_path) and os.path.abspath(full_path) != script_path:
                    if ".stripped." not in full_path and ".comments.json" not in full_path:
                        files_to_process.add(full_path)
        else:
            # It's a specific file passed as an argument
            files_to_process.add(arg)

    for filepath in sorted(files_to_process):
        if ".stripped." in filepath:
            do_merge(filepath)
        elif ".comments." in filepath:
             print(f"  WARNING: Skipping {filepath}. (Pass both the JSON and the source file to trigger a source merge).\n")
        else:
            do_strip(filepath)