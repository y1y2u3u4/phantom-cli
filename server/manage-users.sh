#!/bin/bash
# manage-users.sh - Manage SOCKS5 proxy users for Phantom Server
# Usage: manage-users.sh add|remove|list [username] [password]

set -e

ACTION="${1:-}"
USERNAME="${2:-}"
PASSWORD="${3:-}"

usage() {
    echo "Usage: manage-users.sh <action> [username] [password]"
    echo ""
    echo "Actions:"
    echo "  add <username> <password>   Add a new SOCKS5 user"
    echo "  remove <username>           Remove a SOCKS5 user"
    echo "  list                        List all SOCKS5 users"
    echo ""
    echo "Examples:"
    echo "  manage-users.sh add dev01 mypassword"
    echo "  manage-users.sh remove dev01"
    echo "  manage-users.sh list"
    exit 1
}

add_user() {
    if [ -z "$USERNAME" ] || [ -z "$PASSWORD" ]; then
        echo "Error: username and password are required for add"
        usage
    fi

    if id "$USERNAME" &>/dev/null; then
        echo "Error: User '$USERNAME' already exists"
        exit 1
    fi

    # Create system user (no home dir, no login shell)
    useradd -r -s /usr/sbin/nologin "$USERNAME"
    echo "${USERNAME}:${PASSWORD}" | chpasswd

    echo "User '$USERNAME' added successfully."
}

remove_user() {
    if [ -z "$USERNAME" ]; then
        echo "Error: username is required for remove"
        usage
    fi

    if ! id "$USERNAME" &>/dev/null; then
        echo "Error: User '$USERNAME' does not exist"
        exit 1
    fi

    userdel "$USERNAME" 2>/dev/null
    echo "User '$USERNAME' removed successfully."
}

list_users() {
    echo "SOCKS5 Users:"
    echo "─────────────"
    # List users with nologin shell (our proxy users)
    awk -F: '$7 == "/usr/sbin/nologin" && $3 >= 100 { print "  " $1 }' /etc/passwd
    echo ""
    TOTAL=$(awk -F: '$7 == "/usr/sbin/nologin" && $3 >= 100 { count++ } END { print count+0 }' /etc/passwd)
    echo "Total: $TOTAL user(s)"
}

case "$ACTION" in
    add)
        add_user
        ;;
    remove)
        remove_user
        ;;
    list)
        list_users
        ;;
    *)
        usage
        ;;
esac
