#!/bin/sh
# Prepare the app, then hand over to the CMD (gunicorn by default).
set -eu

python src/manage.py collectstatic --noinput --verbosity 0

# One replica should migrate; set AUTO_MIGRATE=0 on the others, or when
# migrations are run as a separate release step.
if [ "${AUTO_MIGRATE:-1}" = "1" ]; then
    python src/manage.py migrate --noinput
fi

exec "$@"
