#!/bin/bash

logfile="$PROJECT_ROOT"/build_services/trunkpod_build_current.log

source "$PROJECT_ROOT"/global_functions.sh

print_logfile_message() {
    print_info "Logs for build are accessible via symlink: ${BLUE}$logfile${NC}"
}

# Buildah logger: logs only buildah output, errors will be seen in stdout
run_buildah() {
    buildah "$@" >> "$logfile" 2>>"$logfile"
    rc=${PIPESTATUS[0]} 

    if [[ $rc -ne 0 ]]; then
        print_error "Build failed on command: buildah $*" >&2
        print_info "Please check logs here: ${BLUE}$logfile${NC}" >&2
        return $rc
    fi
}

rollback() {
    print_error "Error occurred while running build${NC}"
    buildah rm $ctr > /dev/null
    print_info "Build phase rollback completed"
    exit 1
}
# Will be called if error occurs