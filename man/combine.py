#!/usr/bin/python3
import re
from pathlib import Path
from datetime import date

# Directory where man pages are stored
data_dir = Path("./data")

# Output file path
man_dir = Path("./man1")
output_path = man_dir / "aad-tool.1"

# Man section headers to ignore or skip when merging
skip_sections = [".TH", ".SH NAME"]

# Combine all .1 man page files
combined_lines = [
    ".TH AAD-TOOL \"1\" \"%s\" \"aad-tool\" \"User Commands\"" % date.today().strftime("%Y-%m-%d"),
    ".SH NAME",
    "aad-tool \\- Azure Entra ID (AAD) management utility for Himmelblau",
    ".SH SYNOPSIS",
    ".B aad-tool",
    "\\fI<COMMAND>\\fR [OPTIONS]",
    ".SH DESCRIPTION",
    "The `aad-tool` utility is part of the Himmelblau project, designed to manage and interact with Azure Entra ID through various commands. It allows you to test authentication, manage caches, and check the status of services related to the `himmelblaud` resolver.",
]

top_man = data_dir / "aad-tool.1"
with open(top_man, "r") as f:
    in_skip = False
    for line in f:
        if any(line.startswith(section) for section in skip_sections):
            in_skip = True
            continue
        if in_skip and line.startswith(".SH"):
            in_skip = False
        if not in_skip:
            combined_lines.append(line.rstrip())

# Sort files alphabetically
man_files = sorted(data_dir.glob("aad-tool-*.1"))

for file in man_files:
    command_name = file.stem.replace("aad-tool-", "").replace("-", " ")
    combined_lines.append(".PP")
    with file.open() as f:
        in_skip = False
        for line in f:
            if any(line.startswith(section) for section in skip_sections):
                in_skip = True
                continue
            if in_skip and line.startswith(".SH"):
                in_skip = False
            if line.startswith('.SH SYNOPSIS'):
                line = line.replace('.SH SYNOPSIS', '.SH')
            if line.startswith('.SH DESCRIPTION'):
                line = line.replace('.SH DESCRIPTION', '.SS DESCRIPTION')
            if line.startswith('.SH OPTIONS'):
                line = line.replace('.SH OPTIONS', '.SS OPTIONS')
            if line.startswith('.SH EXAMPLES'):
                line = line.replace('.SH EXAMPLES', '.SS EXAMPLES')
            if not in_skip:
                combined_lines.append(line.rstrip())

"""
.SH SEE ALSO
.BR himmelblau.conf (5),
.BR himmelblaud (8),
.BR himmelblaud-tasks (8)
"""

combined_lines.extend([
    ".SH SEE ALSO",
    ".BR himmelblau.conf (5),",
    ".BR himmelblaud (8),",
    ".BR himmelblaud-tasks (8)",
    ".SH AUTHOR",
    "David Mulder <dmulder@himmelblau-idm.org>,",
    "<dmulder@samba.org>",
])

def postprocess_troff(text):
    """Post-process combined troff for cleaner pandoc conversion.

    Converts numbered paragraphs to .IP list items and wraps
    inline example commands in .EX/.EE blocks.
    """
    # Convert numbered paragraphs (.PP followed by "N. ...") to .IP "N." items
    text = re.sub(
        r'^\.PP\n(\d+)\. ',
        r'.IP "\1." 4\n',
        text,
        flags=re.MULTILINE,
    )

    return text


# Write combined man page
text = "\n".join(combined_lines)
text = text.replace('aad-tool\n\\fI\\,', 'aad-tool \\fI\\,')
text = text.replace('.SH\n.B', '.SH SUBCOMMAND\n.B')
text = postprocess_troff(text)
output_path.write_text(text + "\n")

output_path.name
