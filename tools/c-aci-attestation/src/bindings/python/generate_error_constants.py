#!/usr/bin/env python3
"""
Generate Python error constants from C header file.
This script parses attestation_errors.h to extract error codes and generates
the corresponding Python constants and error messages.
"""
import os
import re
import subprocess
import sys
from typing import Dict, List, Tuple


def parse_header_file(header_path: str) -> List[Tuple[str, int]]:
    """
    Parse the C header file to extract error code definitions.
    
    Returns:
        List of (constant_name, value) tuples
    """
    constants = []
    
    with open(header_path, 'r') as f:
        content = f.read()
    
    # Find #define statements for error codes
    # Pattern matches: #define CONSTANT_NAME value
    pattern = r'#define\s+(ATTESTATION_\w+)\s+(\d+)'
    matches = re.findall(pattern, content)
    
    for name, value in matches:
        constants.append((name, int(value)))
    
    return sorted(constants, key=lambda x: x[1])  # Sort by error code value


def get_error_message(error_code: int, verify_executable: str) -> str:
    """
    Get error message for a specific error code by calling the C executable.
    We'll add a --get-error-message option to the C executable for this.
    For now, we'll extract messages from the C source file.
    """
    # For now, we'll parse the C source file to get error messages
    # This is a temporary solution until we add the --get-error-message option
    return f"Error code {error_code}"


def get_error_messages_from_source(source_path: str) -> Dict[int, str]:
    """
    Parse the C source file to extract error messages.
    """
    messages = {}
    
    with open(source_path, 'r') as f:
        content = f.read()
    
    # Find the switch statement in attestation_error_message function
    # Extract case statements and their return values
    pattern = r'case\s+ATTESTATION_\w+:\s*return\s+"([^"]+)";'
    matches = re.findall(pattern, content)
    
    # Also extract the constant values to map messages to codes
    with open(os.path.join(os.path.dirname(source_path), '../lib/attestation_errors.h'), 'r') as f:
        header_content = f.read()
    
    # Get constant definitions
    const_pattern = r'#define\s+(ATTESTATION_\w+)\s+(\d+)'
    const_matches = re.findall(const_pattern, header_content)
    const_map = {name: int(value) for name, value in const_matches}
    
    # Map messages to error codes by parsing the switch statement more carefully
    switch_pattern = r'case\s+(ATTESTATION_\w+):\s*return\s+"([^"]+)";'
    switch_matches = re.findall(switch_pattern, content)
    
    for const_name, message in switch_matches:
        if const_name in const_map:
            messages[const_map[const_name]] = message
    
    return messages


def generate_python_constants(constants: List[Tuple[str, int]], messages: Dict[int, str]) -> str:
    """
    Generate Python code for error constants and messages.
    """
    lines = [
        "# Auto-generated error constants from C header file",
        "# Do not edit manually - regenerate with generate_error_constants.py",
        "",
    ]
    
    # Generate constants
    lines.append("# Error codes")
    for name, value in constants:
        lines.append(f"{name} = {value}")
    
    lines.append("")
    lines.append("# Error messages")
    lines.append("_ERROR_MESSAGES = {")
    for name, value in constants:
        message = messages.get(value, f"Unknown error (code {value})")
        lines.append(f'    {name}: "{message}",')
    lines.append("}")
    
    lines.append("")
    lines.append("# Export all constants")
    lines.append("__all__ = [")
    for name, _ in constants:
        lines.append(f'    "{name}",')
    lines.append("]")
    
    return "\n".join(lines)


def main():
    """Main function to generate error constants."""
    if len(sys.argv) != 4:
        print("Usage: generate_error_constants.py <header_path> <source_path> <output_path>")
        sys.exit(1)
    
    header_path = sys.argv[1]
    source_path = sys.argv[2]
    output_path = sys.argv[3]
    
    # Parse header file to get constants
    constants = parse_header_file(header_path)
    
    # Get error messages from source file
    messages = get_error_messages_from_source(source_path)
    
    # Generate Python code
    python_code = generate_python_constants(constants, messages)
    
    # Write to output file
    with open(output_path, 'w') as f:
        f.write(python_code)
    
    print(f"Generated {len(constants)} error constants in {output_path}")


if __name__ == "__main__":
    main()