#!/usr/bin/env python3
"""
Himmelblau Configuration Parameter Code Generator

This script parses XML parameter definitions from docs-xml/himmelblauconf/
and generates:
1. Rust code (config_gen.rs) with getter functions and constants
2. Man page (himmelblau.conf.5) in troff format
3. NixOS module options (himmelblau-options.nix) with typed settings

Usage:
    gen_param_code.py --gen-rust --rust-output <path>
    gen_param_code.py --gen-man --man-output <path>
    gen_param_code.py --gen-nix --nix-output <path>
    gen_param_code.py --gen-rust --gen-man --gen-nix --rust-output <path> --man-output <path> --nix-output <path>

This mirrors Samba's approach of generating code from XML parameter definitions.
"""

import argparse
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Optional, List, Dict
from pathlib import Path
import datetime


@dataclass
class EnumValue:
    """Represents an enum value mapping."""
    config_value: str  # Value in config file (e.g., "name")
    rust_value: str    # Rust enum variant (e.g., "IdAttr::Name")


@dataclass
class Parameter:
    """Represents a configuration parameter."""
    name: str
    section: str
    param_type: str
    rust_type: str
    documented: bool
    domain_specific: bool
    order: int
    description: str
    default: str
    default_const: Optional[str]
    example: str
    required: bool
    handler: Optional[str]  # Custom handler function name
    enum_values: List[EnumValue]
    env_override: Optional[str]


@dataclass
class Section:
    """Represents a configuration section."""
    name: str
    title: str
    preamble: str
    subsection_intro: str


def parse_xml_file(filepath: str) -> tuple[List[Parameter], List[Section]]:
    """Parse an XML parameter definition file."""
    tree = ET.parse(filepath)
    root = tree.getroot()

    parameters = []
    sections = []

    # Check if root is a section definition
    if root.tag == 'section':
        section = Section(
            name=root.get('name', ''),
            title=root.findtext('title', ''),
            preamble=root.findtext('preamble', '').strip(),
            subsection_intro=root.findtext('subsection_intro', '').strip()
        )
        sections.append(section)
        return parameters, sections

    # Check if root is a parameter (one file per parameter)
    if root.tag == 'parameter':
        param_elem = root
        # Parse enum values if present
        enum_values = []
        enum_elem = param_elem.find('enum_values')
        if enum_elem is not None:
            for value_elem in enum_elem.findall('value'):
                enum_values.append(EnumValue(
                    config_value=value_elem.text or '',
                    rust_value=value_elem.get('rust', '')
                ))

        param = Parameter(
            name=param_elem.get('name', ''),
            section=param_elem.get('section', 'global'),
            param_type=param_elem.get('type', 'string'),
            rust_type=param_elem.get('rust_type', 'String'),
            documented=param_elem.get('documented', 'true').lower() == 'true',
            domain_specific=param_elem.get('domain_specific', 'false').lower() == 'true',
            order=int(param_elem.get('order', '999')),
            description=param_elem.findtext('description', '').strip(),
            default=param_elem.findtext('default', ''),
            default_const=param_elem.findtext('default_const'),
            example=param_elem.findtext('example', ''),
            required=param_elem.findtext('required', 'false').lower() == 'true',
            handler=param_elem.findtext('handler'),
            enum_values=enum_values,
            env_override=param_elem.findtext('env_override')
        )
        parameters.append(param)
        return parameters, sections

    return parameters, sections


def load_all_parameters(xml_dir: str) -> tuple[List[Parameter], Dict[str, Section]]:
    """Load all parameters from XML files in the given directory.

    Directory structure (mirrors Samba):
      docs-xml/himmelblauconf/
        base/              - [global] section parameters
        offline_breakglass/ - [offline_breakglass] section parameters
        <section>/         - other section parameters
    """
    all_params = []
    all_sections = {}

    xml_path = Path(xml_dir)

    # Process each subdirectory as a section
    for subdir in sorted(xml_path.iterdir()):
        if not subdir.is_dir():
            continue
        try:
            # Load all XML files in this section directory
            for xml_file in sorted(subdir.glob('*.xml')):
                params, sections = parse_xml_file(str(xml_file))
                all_params.extend(params)
                for section in sections:
                    all_sections[section.name] = section
        except OSError as e:
            print(f"Error: Could not read directory {subdir}: {e}", file=sys.stderr)
            sys.exit(1)

    return all_params, all_sections


def generate_rust_code(params: List[Parameter], sections: Dict[str, Section]) -> str:
    """Generate Rust code for configuration getters.

    The generated code contains its own impl block and should be included
    at the module level in config.rs (not inside an existing impl block).
    """
    lines = []

    # Header
    lines.append('// Auto-generated by gen_param_code.py - DO NOT EDIT')
    lines.append('// Generated from XML parameter definitions in docs-xml/himmelblauconf/')
    lines.append('//')
    lines.append('// Include this file at the module level in config.rs')
    lines.append('')

    # Generate constants for parameters that don't have default_const defined
    lines.append('// Generated default constants')
    for param in sorted(params, key=lambda p: p.name):
        # Skip if using existing constant or has custom handler or no default
        if param.default_const or param.handler:
            continue
        if not param.default and param.param_type not in ('bool',):
            continue

        const_name = f'DEFAULT_{param.name.upper()}'

        if param.param_type == 'bool':
            val = 'true' if param.default and param.default.lower() == 'true' else 'false'
            lines.append(f'const {const_name}: bool = {val};')
        elif param.param_type in ('u64', 'u32', 'usize'):
            val = param.default if param.default else '0'
            lines.append(f'const {const_name}: {param.param_type} = {val};')
        elif param.param_type == 'string':
            lines.append(f'const {const_name}: &str = "{param.default}";')
        elif param.param_type == 'string_list':
            lines.append(f'const {const_name}: &str = "{param.default}";')

    lines.append('')
    lines.append('impl HimmelblauConfig {')
    lines.append('')

    for param in sorted(params, key=lambda p: (p.section, p.order, p.name)):
        # Skip parameters with custom handlers
        if param.handler:
            continue

        # Generate doc comment
        if param.description:
            # Take first line/sentence for brief doc
            brief = param.description.split('\n')[0].strip()
            brief = brief.replace('.B ', '').replace('.I ', '')
            if brief:
                lines.append(f'    /// {brief}')

        # Generate function signature
        # For non-global sections, prefix the section name
        if param.section not in ('global', 'domain'):
            fn_name = f'get_{param.section}_{param.name}'
        else:
            fn_name = f'get_{param.name}'

        # Handle domain-specific parameters
        if param.domain_specific and param.section == 'global':
            lines.append(f'    pub fn {fn_name}(&self, domain: Option<&str>) -> {param.rust_type} {{')
        elif param.section == 'domain':
            lines.append(f'    pub fn {fn_name}(&self, domain: &str) -> {param.rust_type} {{')
        else:
            lines.append(f'    pub fn {fn_name}(&self) -> {param.rust_type} {{')

        # Generate function body based on type
        section = param.section if param.section != 'domain' else 'domain'

        if param.env_override:
            lines.append(f'        if let Ok(val) = std::env::var("{param.env_override}") {{')
            lines.append(f'            return val;')
            lines.append('        }')

        if param.param_type == 'bool':
            default_expr = param.default_const if param.default_const else f'DEFAULT_{param.name.upper()}'
            if param.domain_specific:
                lines.append(_gen_domain_specific_bool(param, default_expr))
            else:
                lines.append(f'        match_bool(self.config.get("{section}", "{param.name}"), {default_expr})')

        elif param.param_type in ('u64', 'u32', 'usize'):
            default_expr = param.default_const if param.default_const else f'DEFAULT_{param.name.upper()}'
            if param.domain_specific:
                lines.append(_gen_domain_specific_number(param, default_expr))
            else:
                lines.append(f'        match self.config.get("{section}", "{param.name}") {{')
                lines.append(f'            Some(val) => val.parse::<{param.param_type}>().unwrap_or_else(|_| {{')
                lines.append(f'                error!("Failed parsing {param.name} from config: {{}}", val);')
                lines.append(f'                {default_expr}')
                lines.append('            }),')
                lines.append(f'            None => {default_expr},')
                lines.append('        }')

        elif param.param_type == 'string' and param.rust_type == 'String':
            default_expr = param.default_const if param.default_const else f'DEFAULT_{param.name.upper()}'
            if param.domain_specific:
                lines.append(_gen_domain_specific_string(param, default_expr))
            else:
                lines.append(f'        match self.config.get("{section}", "{param.name}") {{')
                lines.append(f'            Some(val) => val,')
                lines.append(f'            None => {default_expr}.to_string(),')
                lines.append('        }')

        elif param.param_type == 'string' and 'Option' in param.rust_type:
            if param.domain_specific:
                lines.append(_gen_domain_specific_option_string(param))
            else:
                lines.append(f'        self.config.get("{section}", "{param.name}")')

        elif param.param_type == 'string_list':
            default_expr = param.default_const if param.default_const else f'DEFAULT_{param.name.upper()}'
            lines.append(f'        match self.config.get("{section}", "{param.name}") {{')
            lines.append(f'            Some(val) => val.split(\',\').map(|s| s.trim().to_string()).collect(),')
            if param.default:
                lines.append(f'            None => {default_expr}.split(\',\').map(|s| s.trim().to_string()).collect(),')
            else:
                lines.append('            None => vec![],')
            lines.append('        }')

        elif param.param_type == 'enum':
            lines.append(_gen_enum_getter(param))

        elif param.param_type == 'range':
            lines.append(_gen_range_getter(param))

        elif param.param_type == 'ttl':
            default_expr = param.default_const if param.default_const else f'DEFAULT_{param.name.upper()}'
            lines.append(f'        match self.config.get("{section}", "{param.name}") {{')
            lines.append(f'            Some(val) => parse_ttl_to_seconds(&val).unwrap_or({default_expr}),')
            lines.append(f'            None => {default_expr},')
            lines.append('        }')

        lines.append('    }')
        lines.append('')

    lines.append('}')
    return '\n'.join(lines)


def _gen_domain_specific_bool(param: Parameter, default_expr: str) -> str:
    """Generate code for a domain-specific boolean parameter."""
    return f'''        match domain {{
            Some(domain) => match self.config.get(domain, "{param.name}") {{
                Some(val) => match_bool(Some(val), {default_expr}),
                None => match_bool(self.config.get("global", "{param.name}"), {default_expr}),
            }},
            None => match_bool(self.config.get("global", "{param.name}"), {default_expr}),
        }}'''


def _gen_domain_specific_number(param: Parameter, default_expr: str) -> str:
    """Generate code for a domain-specific numeric parameter."""
    return f'''        match domain {{
            Some(domain) => match self.config.get(domain, "{param.name}") {{
                Some(val) => val.parse::<{param.param_type}>().unwrap_or_else(|_| {{
                    error!("Failed parsing {param.name} from config: {{}}", val);
                    {default_expr}
                }}),
                None => match self.config.get("global", "{param.name}") {{
                    Some(val) => val.parse::<{param.param_type}>().unwrap_or_else(|_| {{
                        error!("Failed parsing {param.name} from config: {{}}", val);
                        {default_expr}
                    }}),
                    None => {default_expr},
                }},
            }},
            None => match self.config.get("global", "{param.name}") {{
                Some(val) => val.parse::<{param.param_type}>().unwrap_or_else(|_| {{
                    error!("Failed parsing {param.name} from config: {{}}", val);
                    {default_expr}
                }}),
                None => {default_expr},
            }},
        }}'''


def _gen_domain_specific_string(param: Parameter, default_expr: str) -> str:
    """Generate code for a domain-specific string parameter."""
    return f'''        match domain {{
            Some(domain) => match self.config.get(domain, "{param.name}") {{
                Some(val) => val,
                None => match self.config.get("global", "{param.name}") {{
                    Some(val) => val,
                    None => String::from({default_expr}),
                }},
            }},
            None => match self.config.get("global", "{param.name}") {{
                Some(val) => val,
                None => String::from({default_expr}),
            }},
        }}'''


def _gen_domain_specific_option_string(param: Parameter) -> str:
    """Generate code for a domain-specific Option<String> parameter."""
    return f'''        match domain {{
            Some(domain) => match self.config.get(domain, "{param.name}") {{
                Some(val) => Some(val),
                None => self.config.get("global", "{param.name}"),
            }},
            None => self.config.get("global", "{param.name}"),
        }}'''


def _gen_enum_getter(param: Parameter) -> str:
    """Generate code for an enum parameter getter."""
    section = param.section if param.section != 'domain' else 'domain'
    is_optional = 'Option<' in param.rust_type

    lines = [f'        match self.config.get("{section}", "{param.name}") {{']
    lines.append('            Some(val) => match val.to_lowercase().as_str() {')

    for ev in param.enum_values:
        if is_optional:
            lines.append(f'                "{ev.config_value}" => Some({ev.rust_value}),')
        else:
            lines.append(f'                "{ev.config_value}" => {ev.rust_value},')

    if is_optional:
        # For optional enums, return None for unrecognized values
        lines.append('                _ => None,')
        lines.append('            },')
        lines.append('            None => None,')
    else:
        default_expr = param.default_const if param.default_const else f'DEFAULT_{param.name.upper()}'
        lines.append('                _ => {')
        lines.append(f'                    error!("Unrecognized {param.name} choice: {{}}", val);')
        lines.append(f'                    {default_expr}')
        lines.append('                }')
        lines.append('            },')
        lines.append(f'            None => {default_expr},')
    lines.append('        }')

    return '\n'.join(lines)


def _gen_range_getter(param: Parameter) -> str:
    """Generate code for a range parameter getter (e.g., idmap_range)."""
    default_expr = param.default_const if param.default_const else f'DEFAULT_{param.name.upper()}'

    return f'''        let default_range = {default_expr};
        match self.config.get("domain", "{param.name}") {{
            Some(val) => {{
                let vals: Vec<u32> = val
                    .split('-')
                    .map(|m| m.parse())
                    .collect::<Result<Vec<u32>, _>>()
                    .unwrap_or_else(|_| vec![default_range.0, default_range.1]);
                match vals.as_slice() {{
                    [min, max] => (*min, *max),
                    _ => {{
                        error!("Invalid range specified: {param.name} = {{}}", val);
                        default_range
                    }}
                }}
            }}
            None => match self.config.get("global", "{param.name}") {{
                Some(val) => {{
                    let vals: Vec<u32> = val
                        .split('-')
                        .map(|m| m.parse())
                        .collect::<Result<Vec<u32>, _>>()
                        .unwrap_or_else(|_| vec![default_range.0, default_range.1]);
                    match vals.as_slice() {{
                        [min, max] => (*min, *max),
                        _ => {{
                            error!("Invalid range specified [global] {param.name} = {{}}", val);
                            default_range
                        }}
                    }}
                }}
                None => default_range,
            }},
        }}'''


def normalize_troff_text(text: str) -> str:
    """Normalize troff text for consistent output.

    Handles escape sequences and ensures consistent formatting.
    """
    # Remove zero-width escape (used before periods) - not needed in modern troff
    text = text.replace('\\&', '')
    return text


def generate_man_page(params: List[Parameter], sections: Dict[str, Section]) -> str:
    """Generate troff-formatted man page."""
    lines = []

    # Header
    current_date = datetime.datetime.now().strftime("%B %Y")
    lines.append(f'.TH HIMMELBLAU.CONF "5" "{current_date}" "Himmelblau Configuration" "File Formats"')
    lines.append('.SH NAME')
    lines.append('himmelblau.conf \\- Configuration file for Himmelblau, enabling Azure Entra ID authentication on Linux.')
    lines.append('')
    lines.append('.SH SYNOPSIS')
    lines.append('.B /etc/himmelblau/himmelblau.conf')
    lines.append('')

    # How configuration changes are applied
    lines.append('.SH HOW CONFIGURATION CHANGES ARE APPLIED')
    lines.append('Changes to the configuration file')
    lines.append('.B /etc/himmelblau/himmelblau.conf')
    lines.append('only take effect after restarting the Himmelblau daemons. This includes the')
    lines.append('.B himmelblaud')
    lines.append('daemon, which handles authentication, and the')
    lines.append('.B himmelblaud-tasks')
    lines.append('daemon, which processes related tasks.')
    lines.append('')
    lines.append('.TP')
    lines.append('.B Restarting the Daemons')
    lines.append('To apply changes, restart the Himmelblau services using the following systemd commands:')
    lines.append('')
    lines.append('.nf')
    lines.append('.RS')
    lines.append('.IP')
    lines.append('sudo systemctl restart himmelblaud')
    lines.append('.IP')
    lines.append('sudo systemctl restart himmelblaud-tasks')
    lines.append('.RE')
    lines.append('.fi')
    lines.append('')

    # Description
    lines.append('.SH DESCRIPTION')
    lines.append('The')
    lines.append('.B himmelblau.conf')
    lines.append('file is the primary configuration file for the Himmelblau authentication module. It defines global and optional settings required for Azure Entra ID-based authentication and device management.')
    lines.append('')
    lines.append('.P')
    lines.append('While Himmelblau is designed to be highly configurable, it can normally be used without any custom configuration. For desktop authentication with Azure Entra ID, all that is required is for Himmelblau to be installed and for a user to log in. The domain will be automatically extracted from the first user\'s UPN and looked up in Entra ID.')
    lines.append('')
    lines.append('.P')
    lines.append('Himmelblau has many capabilities, but most are enabled by default and configured automatically at install time. The options documented below allow administrators to customize behavior for specific environments or requirements.')
    lines.append('')

    # File format
    lines.append('.SH FILE FORMAT')
    lines.append('The file consists of sections headed by a name enclosed in square brackets. Each section contains parameters and their values in the format:')
    lines.append('.RS 4')
    lines.append('parameter = value')
    lines.append('.RE')
    lines.append('')
    lines.append("Lines beginning with a '#' are comments and are ignored by the parser.")
    lines.append('')

    # Parameters section
    lines.append('.SH PARAMETERS')
    lines.append('')

    # [global] section
    lines.append('.SS [global]')
    lines.append('This section contains settings that apply globally to all operations of Himmelblau.')
    lines.append('')

    # Get global documented parameters, sorted by order
    global_params = [p for p in params if p.section == 'global' and p.documented]
    global_params.sort(key=lambda p: p.order)

    for param in global_params:
        lines.append('.TP')
        lines.append(f'.B {param.name}')
        lines.append('.RE')

        # Add description (already in troff format from XML)
        lines.append(normalize_troff_text(param.description))
        lines.append('')

        # Add default value if present
        if param.default:
            lines.append('.P')
            lines.append(f'Default: {param.default}')
            lines.append('')

        # Add example if present
        if param.example:
            lines.append('.P')
            lines.append(f'Example: {param.example}')
            lines.append('')

    # [offline_breakglass] section
    if 'offline_breakglass' in sections:
        section = sections['offline_breakglass']

        lines.append(f'.SH {section.title}')
        lines.append(normalize_troff_text(section.preamble))
        lines.append('')
        lines.append('.SS [offline_breakglass]')
        lines.append(normalize_troff_text(section.subsection_intro))
        lines.append('')

        # Get offline_breakglass documented parameters
        breakglass_params = [p for p in params if p.section == 'offline_breakglass' and p.documented]
        breakglass_params.sort(key=lambda p: p.order)

        for param in breakglass_params:
            lines.append('.TP')
            lines.append(f'.B {param.name}')
            lines.append('.RE')
            lines.append(normalize_troff_text(param.description))
            lines.append('')

            # Add default value if present
            if param.default:
                lines.append('.P')
                lines.append(f'Default: {param.default}')
                lines.append('')

            if param.example:
                lines.append('.P')
                lines.append(f'Example: {param.example}')
                lines.append('')

    # See also
    lines.append('.SH SEE ALSO')
    lines.append('.BR himmelblaud(8),')
    lines.append('.BR himmelblaud-tasks(8)')
    lines.append('')

    return '\n'.join(lines)


def clean_troff_description(text: str) -> str:
    """Clean troff formatting from description text for use in Nix.

    Removes troff macros and converts to plain text suitable for Nix descriptions.
    """
    import re

    # Remove common troff macros
    text = re.sub(r'\.B\s+', '', text)  # Bold macro
    text = re.sub(r'\.I\s+', '', text)  # Italic macro
    text = re.sub(r'\.P\s*\n?', '\n\n', text)  # Paragraph
    text = re.sub(r'\.RS\s*\n?', '', text)  # Right shift start
    text = re.sub(r'\.RE\s*\n?', '', text)  # Right shift end
    text = re.sub(r'\.IP\s*\n?', '\n  ', text)  # Indented paragraph
    text = re.sub(r'\.br\s*\n?', '\n', text)  # Line break
    text = re.sub(r'\.BR\s+(\S+)\s*\((\d+)\)', r'\1(\2)', text)  # Man page references
    text = re.sub(r'\.nf\s*\n?', '', text)  # No-fill start
    text = re.sub(r'\.fi\s*\n?', '', text)  # No-fill end

    # Clean up multiple newlines and whitespace
    text = re.sub(r'\n{3,}', '\n\n', text)
    text = text.strip()

    return text


def xml_type_to_nix_type(param: Parameter) -> tuple[str, bool]:
    """Convert XML parameter type to NixOS types expression.

    Returns a tuple of (nix_type, is_already_optional).
    If is_already_optional is True, the caller should not wrap in nullOr.
    """
    param_type = param.param_type
    rust_type = param.rust_type

    if param_type == 'bool':
        return 'types.bool', False

    elif param_type in ('u64', 'u32', 'usize'):
        return 'types.ints.unsigned', False

    elif param_type == 'string':
        # Check if it's a list type based on rust_type
        if 'Vec<' in rust_type:
            return 'types.listOf types.str', False
        elif 'Option<' in rust_type:
            # Already optional in Rust, return str without extra nullOr
            return 'types.str', False
        else:
            return 'types.str', False

    elif param_type == 'string_list':
        return 'types.listOf types.str', False

    elif param_type == 'enum':
        # Generate types.enum with the valid values
        values = [f'"{ev.config_value}"' for ev in param.enum_values]
        return f'types.enum [ {" ".join(values)} ]', False

    elif param_type == 'range':
        # Range is specified as "min-max" string
        return 'types.str', False

    elif param_type == 'ttl':
        # TTL can have suffixes like "2h", "1d", so keep as string
        return 'types.str', False

    else:
        # Default to string for unknown types
        return 'types.str', False


def format_nix_default(param: Parameter) -> Optional[str]:
    """Format the default value for Nix.

    Returns None if there's no sensible default, or the Nix expression for the default.
    """
    if not param.default:
        return None

    param_type = param.param_type
    rust_type = param.rust_type
    default = param.default

    # Skip defaults that are descriptive text rather than actual values
    descriptive_defaults = [
        'Extracted from',
        'All users permitted',
        'Not set',
        'None',
    ]
    for desc in descriptive_defaults:
        if desc.lower() in default.lower():
            return None

    if param_type == 'bool':
        return 'true' if default.lower() == 'true' else 'false'

    elif param_type in ('u64', 'u32', 'usize'):
        try:
            return str(int(default))
        except ValueError:
            return None

    elif param_type == 'string':
        if 'Vec<' in rust_type:
            # List type - return as Nix list
            return f'[ "{default}" ]'
        elif 'Option<' in rust_type:
            return 'null'
        else:
            return f'"{default}"'

    elif param_type == 'string_list':
        return '[ ]'

    elif param_type == 'enum':
        return f'"{default}"'

    elif param_type == 'range':
        return f'"{default}"'

    elif param_type == 'ttl':
        return f'"{default}"'

    else:
        return f'"{default}"'


def format_nix_example(param: Parameter) -> Optional[str]:
    """Format the example value for Nix."""
    if not param.example:
        return None

    param_type = param.param_type
    rust_type = param.rust_type

    # Extract value from "key = value" format
    example = param.example

    # Clean up any troff formatting first
    example = example.replace('.br', '\n').strip()

    # Handle multi-line examples - skip if it looks like a full config block
    if example.startswith('['):
        return None

    if ' = ' in example:
        # Take first line with an assignment
        for line in example.split('\n'):
            line = line.strip()
            if ' = ' in line and not line.startswith('#') and not line.startswith('['):
                example = line.split(' = ', 1)[1].strip()
                break
        else:
            # No valid assignment found
            return None

    if param_type == 'bool':
        return 'true' if example.lower() == 'true' else 'false'

    elif param_type in ('u64', 'u32', 'usize'):
        try:
            return str(int(example))
        except ValueError:
            return None

    elif param_type == 'string':
        if 'Vec<' in rust_type:
            # Parse comma-separated list
            items = [item.strip() for item in example.split(',')]
            items_str = ' '.join(f'"{item}"' for item in items)
            return f'[ {items_str} ]'
        else:
            return f'"{example}"'

    elif param_type == 'string_list':
        # Parse comma-separated list
        items = [item.strip() for item in example.split(',')]
        items_str = ' '.join(f'"{item}"' for item in items)
        return f'[ {items_str} ]'

    elif param_type == 'enum':
        # Handle <option1|option2> format
        if example.startswith('<') and example.endswith('>'):
            # Take first option as example
            first_option = example[1:-1].split('|')[0]
            return f'"{first_option}"'
        return f'"{example}"'

    elif param_type == 'range':
        return f'"{example}"'

    elif param_type == 'ttl':
        return f'"{example}"'

    else:
        return f'"{example}"'


def generate_nix_options(params: List[Parameter], sections: Dict[str, Section]) -> str:
    """Generate NixOS module options from parameters."""
    lines = []

    # Header
    lines.append('# Auto-generated by gen_param_code.py - DO NOT EDIT')
    lines.append('# Generated from XML parameter definitions in docs-xml/himmelblauconf/')
    lines.append('#')
    lines.append('# This file provides typed NixOS options for himmelblau.conf settings.')
    lines.append('# Import this file and use the options under services.himmelblau.settings')
    lines.append('')
    lines.append('{ lib, ... }:')
    lines.append('')
    lines.append('let')
    lines.append('  inherit (lib) mkOption types;')
    lines.append('in')
    lines.append('{')
    lines.append('  options.services.himmelblau.settings = {')
    lines.append('')

    # Group parameters by section
    params_by_section: Dict[str, List[Parameter]] = {}
    for param in params:
        if not param.documented:
            continue
        section = param.section
        if section not in params_by_section:
            params_by_section[section] = []
        params_by_section[section].append(param)

    # Generate global section options first
    if 'global' in params_by_section:
        lines.append('    # [global] section options')
        global_params = sorted(params_by_section['global'], key=lambda p: p.order)

        for param in global_params:
            lines.extend(_generate_nix_option(param, indent=4))
            lines.append('')

    # Generate other sections as nested attrsets
    for section_name, section_params in sorted(params_by_section.items()):
        if section_name == 'global':
            continue

        # Get section info if available
        section_info = sections.get(section_name)

        lines.append(f'    # [{section_name}] section options')
        if section_info and section_info.preamble:
            clean_preamble = clean_troff_description(section_info.preamble)
            # Add as a comment
            for preamble_line in clean_preamble.split('\n')[:3]:  # First 3 lines
                if preamble_line.strip():
                    lines.append(f'    # {preamble_line.strip()}')

        lines.append(f'    {section_name} = {{')

        sorted_params = sorted(section_params, key=lambda p: p.order)
        for param in sorted_params:
            lines.extend(_generate_nix_option(param, indent=6))
            lines.append('')

        lines.append('    };')
        lines.append('')

    lines.append('  };')
    lines.append('}')

    return '\n'.join(lines)


def _generate_nix_option(param: Parameter, indent: int = 4) -> List[str]:
    """Generate a single NixOS option definition."""
    lines = []
    ind = ' ' * indent

    # Option name
    lines.append(f'{ind}{param.name} = mkOption {{')

    # Type - wrap in nullOr to make all options optional
    nix_type, _ = xml_type_to_nix_type(param)
    lines.append(f'{ind}  type = types.nullOr ({nix_type});')

    # Default - always null to make options optional
    lines.append(f'{ind}  default = null;')

    # Description
    if param.description:
        clean_desc = clean_troff_description(param.description)
        # Escape special characters for Nix
        clean_desc = clean_desc.replace("''", "'''")
        clean_desc = clean_desc.replace('${', "\\${")

        lines.append(f"{ind}  description = ''")
        for desc_line in clean_desc.split('\n'):
            lines.append(f'{ind}    {desc_line}')

        # Add default info if available
        if param.default:
            lines.append(f'{ind}')
            lines.append(f'{ind}    Default: {param.default}')

        lines.append(f"{ind}  '';")

    # Example
    example = format_nix_example(param)
    if example:
        lines.append(f'{ind}  example = {example};')

    lines.append(f'{ind}}};')

    return lines


def main():
    parser = argparse.ArgumentParser(
        description='Generate Rust code, man page, and NixOS options from XML parameter definitions'
    )
    parser.add_argument('--gen-rust', action='store_true',
                        help='Generate Rust code')
    parser.add_argument('--gen-man', action='store_true',
                        help='Generate man page')
    parser.add_argument('--gen-nix', action='store_true',
                        help='Generate NixOS module options')
    parser.add_argument('--rust-output', type=str,
                        help='Output path for generated Rust code')
    parser.add_argument('--man-output', type=str,
                        help='Output path for generated man page')
    parser.add_argument('--nix-output', type=str,
                        help='Output path for generated NixOS options')
    parser.add_argument('--xml-dir', type=str,
                        help='Directory containing XML parameter files')

    args = parser.parse_args()

    if not args.gen_rust and not args.gen_man and not args.gen_nix:
        parser.error('At least one of --gen-rust, --gen-man, or --gen-nix must be specified')

    if args.gen_rust and not args.rust_output:
        parser.error('--rust-output is required when --gen-rust is specified')

    if args.gen_man and not args.man_output:
        parser.error('--man-output is required when --gen-man is specified')

    if args.gen_nix and not args.nix_output:
        parser.error('--nix-output is required when --gen-nix is specified')

    # Determine XML directory
    if args.xml_dir:
        xml_dir = args.xml_dir
    else:
        # Default: relative to script location
        script_dir = Path(__file__).parent.parent
        xml_dir = script_dir / 'docs-xml' / 'himmelblauconf'

    if not Path(xml_dir).exists():
        print(f'Error: XML directory not found: {xml_dir}', file=sys.stderr)
        sys.exit(1)

    # Load all parameters
    print(f'Loading parameters from {xml_dir}...', file=sys.stderr)
    params, sections = load_all_parameters(str(xml_dir))
    print(f'Loaded {len(params)} parameters', file=sys.stderr)

    # Generate outputs
    if args.gen_rust:
        print(f'Generating Rust code to {args.rust_output}...', file=sys.stderr)
        rust_code = generate_rust_code(params, sections)
        Path(args.rust_output).parent.mkdir(parents=True, exist_ok=True)
        with open(args.rust_output, 'w') as f:
            f.write(rust_code)
        print('Rust code generated successfully', file=sys.stderr)

    if args.gen_man:
        print(f'Generating man page to {args.man_output}...', file=sys.stderr)
        man_page = generate_man_page(params, sections)
        Path(args.man_output).parent.mkdir(parents=True, exist_ok=True)
        with open(args.man_output, 'w') as f:
            f.write(man_page)
        print('Man page generated successfully', file=sys.stderr)

    if args.gen_nix:
        print(f'Generating NixOS options to {args.nix_output}...', file=sys.stderr)
        nix_options = generate_nix_options(params, sections)
        Path(args.nix_output).parent.mkdir(parents=True, exist_ok=True)
        with open(args.nix_output, 'w') as f:
            f.write(nix_options)
        print('NixOS options generated successfully', file=sys.stderr)


if __name__ == '__main__':
    main()
