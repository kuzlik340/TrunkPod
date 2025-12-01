# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' 
logfile="/var/log/honeybridge_build.log"

# Buildah logger: logs only buildah output, prints your echo normally

run_buildah() {
    buildah "$@" >> "$logfile" \
        2> >(sed 's/^/[!] BUILD ERROR /' >&2)
    local rc=$? 
    return $rc
}

rollback() {
    echo -e "${RED}[!] ERROR occurred while running build${NC}"
    buildah rm $ctr
    echo "[*] Rollback finished"
    exit 1
}
# Will be called if error occurs