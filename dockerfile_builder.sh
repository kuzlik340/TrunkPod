#!/bin/bash
set -e

DEFAULT_DOCKERFILE="defaults/default_dockerfile"
ADDITIONS_DIR="pods_additions/$SERVICE"
TMP_DIR=$(mktemp -d)
echo "[+] Created temp directory: $TMP_DIR"

echo "Number of args: $#"

cp "$DEFAULT_DOCKERFILE" "$TMP_DIR/Dockerfile"
    echo "[+] Copied default Dockerfile"

while [[ $# -gt 0 ]]; do
    service="$1"
    port="$2"

    # --- COPY DEFAULT DOCKERFILE --------------------------------------------


    # --- APPEND ADDITIONAL DOCKERFILE SNIPPETS ------------------------------

    echo "[+] Adding service-specific Dockerfile parts from $ADDITIONS_DIR"
    ADDITION_FILE="$ADDITIONS_DIR"/"$service"/dockerfile_addition
    
    if [ ! -f "$ADDITION_FILE" ]; then
        echo "Error: $ADDITION_FILE does not exist."
        exit 1
    fi
    echo "[+] Adding service-specific addition: $ADDITION_FILE"
    cat "$ADDITION_FILE" >> "$TMP_DIR/Dockerfile"
    echo -e "\n" >> "$TMP_DIR/Dockerfile"
    echo "EXPOSE $port" >> "$TMP_DIR/Dockerfile"
    shift 2
done
echo "[+] Final Dockerfile built at $TMP_DIR/Dockerfile"
# --- OUTPUT --------------------------------------------------------------

# echo
# echo "================================================================="
# echo "Your Dockerfile is ready:"
# echo "  $TMP_DIR/Dockerfile"
# echo "================================================================="
# echo
# echo "You can now build it:"
# echo "  docker build -t ${SERVICE,,}:latest $TMP_DIR"
# echo

    # # --- CHECK DIRECTORIES ---------------------------------------------------

    # if [ ! -f "$DEFAULT_DOCKERFILE" ]; then
    #     echo "Error: $DEFAULT_DOCKERFILE does not exist."
    #     exit 1
    # fi

    # if [ ! -d "$ADDITIONS_DIR" ]; then
    #     echo "Error: service additions directory $ADDITIONS_DIR does not exist."
    #     exit 1
    # fi