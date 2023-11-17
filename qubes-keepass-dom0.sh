#!/usr/bin/bash


VAULT='vault'
VERSION='qubes-keepass v1.2.0'


function get_id() {
    # Get the id of the currently focused window. This function
    # was copied from the default resources that are shipped with
    # Qubes OS.
    #
    # Parameters:
    #   None
    #
    # Returns:
    #   currently focused window id
    #
    local ID=$(xprop -root _NET_ACTIVE_WINDOW)
    echo ${ID##* }
}


function get_xprop() {
    # Get the specified xproperty from the specified window ID.
    #
    # Parameters:
    #   ID          the window ID to obtain the property from
    #   PROP        the property to obtain
    #   TYPE        the type to obtain (str, int)
    #
    # Returns:
    #   the requested property
    #
    local ID=${1}
    local PROP=${2}
    local TYPE=${3}

    local VALUE=$(xprop -id "${ID}" | grep "${PROP}")

    if [ "${TYPE}" == "str" ]; then
        VALUE=${VALUE#*\"}
        echo ${VALUE%\"*}

    elif [ "${TYPE}" == "int" ]; then
        echo ${VALUE#*= }

    else
        echo ''
    fi
}


function main() {
    # Obtain the required properties from the currently focused window and call
    # qubes-keepass with them.
    #
    # Parameters:
    #   None
    #
    # Returns:
    #   None
    #
    set -e
    set -x

    qvm-check --running -q "${VAULT}"

    if [ $? -ne 0 ]; then
        echo "[-] Your vault qube ${VAULT} is not running yet."
        echo "[-] Aborting to prevent unwanted qube startup."
        return
    fi

    local ID=$(get_id)
    local VM=$(get_xprop "${ID}" '_QUBES_VMNAME(STRING)' 'str')
    local LABEL=$(get_xprop "${ID}" '_QUBES_LABEL(CARDINAL)' 'int')

    if [ -n "${VM}" ] && [ -n "${LABEL}" ]; then
        qvm-run --no-shell "${VAULT}" '/home/user/.local/bin/qubes-keepass.py' "${VM}" --trust-level "${LABEL}"
    fi
}


main
