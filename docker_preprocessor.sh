#!/bin/bash

INPUT="$1"
shift

# Parse flags into associative array
declare -A FLAGS
for flag in "$@"; do
    # Remove all double quotes around the flag
    clean_flag="${flag//\"/}"
    FLAGS["$clean_flag"]=1
done

INCLUDE=1
STACK=()

while IFS= read -r line; do
    # Trim leading spaces
    case "$line" in
        \#if\ *)
            # Extract flag name
            cond="${line#\#if }"
            STACK+=("$INCLUDE")

            if [[ -n "${FLAGS[$cond]}" ]]; then
                INCLUDE=1
            else
                INCLUDE=0
            fi
            continue
            ;;
        
        \#endif)
            # Pop previous state
            INCLUDE="${STACK[-1]}"
            unset 'STACK[-1]'
            continue
            ;;
    esac

    if [[ "$INCLUDE" -eq 1 ]]; then
        echo "$line"
    fi

done < "$INPUT"
