#!/bin/sh
# Runs inside the existing db container. No host PostgreSQL installation is needed.
set -eu
umask 077
export PGHOST=127.0.0.1 PGPORT=5432
export PGUSER="${POSTGRES_USER:?Missing POSTGRES_USER}"
export PGPASSWORD="${POSTGRES_PASSWORD:?Missing POSTGRES_PASSWORD}"
operation=${1:?Missing operation}
archive=${2:?Missing archive path}
case "$archive" in
    /tmp/cybersentinel_*.dump) ;;
    *) echo 'Unexpected archive path' >&2; exit 2 ;;
esac
case "$operation" in
    backup)
        test ! -e "$archive" || { echo 'Archive already exists' >&2; exit 2; }
        pg_dump --dbname="${POSTGRES_DB:?Missing POSTGRES_DB}" --format=custom \
            --no-owner --no-acl --file="$archive"
        pg_restore --list "$archive" > /dev/null
        test -s "$archive"
        ;;
    restore)
        target=${3:?Missing target database}
        case "$target" in
            ''|[!a-z]*|*[!a-z0-9_]*|postgres|template0|template1)
                echo 'Use a new lowercase database name (letters, digits, underscore)' >&2
                exit 2 ;;
        esac
        test "${#target}" -le 63 || { echo 'Database name is too long' >&2; exit 2; }
        test -s "$archive"
        pg_restore --list "$archive" > /dev/null
        # createdb fails if the name already exists. Never drop or overwrite a database.
        createdb --template=template0 -- "$target"
        pg_restore --dbname="$target" --no-owner --no-acl \
            --single-transaction --exit-on-error "$archive"
        ;;
    *) echo 'Unknown maintenance operation' >&2; exit 2 ;;
esac
