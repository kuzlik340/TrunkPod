# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' 

logfile="$(cat log_file_path)"


print_logfile_message() {
    echo -e "[*] Logfile for all 3 stage: $logfile"
}

# Buildah logger: logs only buildah output, errors will be seen in stdout
run_buildah() {
    buildah "$@" >> "$logfile" 2>>"$logfile"
    rc=${PIPESTATUS[0]} 

    if [[ $rc -ne 0 ]]; then
        echo -e "${RED}[!] BUILD ERROR:${NC} buildah failed on command: buildah $*" >&2
        echo "[!] Please check log file: $logfile" >&2
        return $rc
    fi
}


rollback() {
    echo -e "${RED}[!] ERROR occurred while running build${NC}"
    buildah rm $ctr > /dev/null
    echo "[*] Build phase rollback completed"
    exit 1
}
# Will be called if error occurs