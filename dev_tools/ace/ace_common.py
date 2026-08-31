"""Shared constants for the ace dev tool: ANSI colours used across every
subsystem. Kept in one place so a colour tweak is a single edit, not a
scattered one."""

CYAN   = "\033[36m"
YELLOW = "\033[33m"
GREEN  = "\033[32m"
RED    = "\033[31m"
PURPLE = "\033[38;5;135m"   # concrete types (ace abi tag names)
ORANGE = "\033[38;5;208m"   # ontology families / tag-bases
RESET  = "\033[0m"
DIM    = "\033[2m"

