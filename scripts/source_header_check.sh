#!/bin/bash

# Define the license headers to search for
gpl_license="it under the terms of the GNU General Public License as published by"
mpl_license="This Source Code Form is subject to the terms of the Mozilla Public"
mit_license="Permission is hereby granted, free of charge, to any person obtaining a copy"
murmurhash3_license="This file is based on the public domain MurmurHash3"

# Define the directories to exclude
exclude_dirs="./target"

# Find all source files while excluding certain directories
find . -type d \( -path "$exclude_dirs" \) -prune -o \
    -type f \( -name "*.c" -o -name "*.cpp" -o -name "*.h" -o -name "*.py" -o -name "*.rs" \) -print | while read -r file; do
    
    # Check if the file contains any of the license headers
    if ! grep -q "$gpl_license" "$file" && \
       ! grep -q "$mpl_license" "$file" && \
       ! grep -q "$mit_license" "$file" && \
       ! grep -q "$murmurhash3_license" "$file"; then
        echo "Missing license header: $file"
    fi
done
