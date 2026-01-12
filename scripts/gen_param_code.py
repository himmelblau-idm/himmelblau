#!/usr/bin/env python3
"""
Himmelblau Configuration Parameter Code Generator

This script parses XML parameter definitions from docs-xml/himmelblauconf/
and generates:
1. Rust code (config_gen.rs) with getter functions and constants
2. Man page (himmelblau.conf.5) in troff format

Usage:
    gen_param_code.py --gen-rust --rust-output <path>
    gen_param_code.py --gen-man --man-output <path>
    gen_param_code.py --gen-rust --gen-man --rust-output <path> --man-output <path>

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


def main():
    parser = argparse.ArgumentParser(
        description='Generate Rust code and man page from XML parameter definitions'
    )
    parser.add_argument('--gen-rust', action='store_true',
                        help='Generate Rust code')
    parser.add_argument('--gen-man', action='store_true',
                        help='Generate man page')
    parser.add_argument('--rust-output', type=str,
                        help='Output path for generated Rust code')
    parser.add_argument('--man-output', type=str,
                        help='Output path for generated man page')
    parser.add_argument('--xml-dir', type=str,
                        help='Directory containing XML parameter files')

    args = parser.parse_args()

    if not args.gen_rust and not args.gen_man:
        parser.error('At least one of --gen-rust or --gen-man must be specified')

    if args.gen_rust and not args.rust_output:
        parser.error('--rust-output is required when --gen-rust is specified')

    if args.gen_man and not args.man_output:
        parser.error('--man-output is required when --gen-man is specified')

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


if __name__ == '__main__':
    main()
