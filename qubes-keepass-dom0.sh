#!/usr/bin/bash

VAULT="vault"

function get_id() {
    # Get the id of the currently focused window. This function
    # was copied from the default resources that are shiped with
    # Qubes.
    local id=$(xprop -root _NET_ACTIVE_WINDOW)
    echo ${id##* }
}

function get_vm() {
    # Get the name of the VM the currently focused window belongs to.
    # This function was copied from the default resources that are
    # shiped with Qubes.
    local id=$(get_id)
    local vm=$(xprop -id $id | grep '_QUBES_VMNAME(STRING)')
    local vm=${vm#*\"} # extract vmname
    echo ${vm%\"*} # extract vmname
}

function main() {
    # Get the currently focused VM name and run qubes-keepass.py within
    # the ${VAULT} VM using the currently focused VM name as argument.
    local vm=$(get_vm)

    if [[ -n "${vm}" ]]; then
        qvm-run ${VAULT} "/home/user/.local/bin/qubes-pass ${vm}"
    fi
}

main
