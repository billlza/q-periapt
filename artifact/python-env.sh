#!/bin/sh
# Source this file before every repository Python invocation used by a proof,
# package, device, or release gate.  The function below deliberately does not
# inherit the caller's Python startup configuration and never imports adjacent
# repository bytecode caches.

export QPERIAPT_PYTHON_ENV_INITIALIZED=1

if [ -n "${QPERIAPT_PYTHON:-}" ]; then
	python_candidate=$QPERIAPT_PYTHON
else
	python_candidate=
	for candidate in /opt/homebrew/bin/python3 /usr/local/bin/python3 /usr/bin/python3; do
		if [ -x "$candidate" ] && "$candidate" -I -S -c \
			'import sys; raise SystemExit(0 if sys.implementation.name == "cpython" and sys.version_info >= (3, 11) else 1)' \
			>/dev/null 2>&1; then
			python_candidate=$candidate
			break
		fi
	done
fi
case "$python_candidate" in
	/*) ;;
	*)
		printf 'error: QPERIAPT_PYTHON must select an absolute CPython path\n' >&2
		exit 2
		;;
esac
QPERIAPT_PYTHON=$(
	"$python_candidate" -I -S -c 'import os, sys
if sys.implementation.name != "cpython" or sys.version_info < (3, 11):
    raise SystemExit(2)
print(os.path.realpath(sys.executable))'
) || {
	printf 'error: hardened proof tooling requires an isolated CPython >= 3.11\n' >&2
	exit 2
}
QPERIAPT_PYTHON_BOOTSTRAP="$(CDPATH='' cd -- "$(/usr/bin/dirname -- "${ROOT:-.}/artifact/python_bootstrap.py")" && pwd)/python_bootstrap.py"
export QPERIAPT_PYTHON QPERIAPT_PYTHON_BOOTSTRAP

if [ ! -x "$QPERIAPT_PYTHON" ] || [ ! -f "$QPERIAPT_PYTHON_BOOTSTRAP" ] || [ -L "$QPERIAPT_PYTHON_BOOTSTRAP" ]; then
	printf 'error: hardened Python runtime is unavailable\n' >&2
	exit 2
fi

# -I below ignores PYTHON* variables, but clearing them here also prevents a
# later non-Python subprocess from accidentally forwarding hostile settings.
unset PYTHONBREAKPOINT PYTHONCASEOK PYTHONCOERCECLOCALE PYTHONDEBUG \
	PYTHONDEVMODE PYTHONDONTWRITEBYTECODE PYTHONEXECUTABLE PYTHONFAULTHANDLER \
	PYTHONHASHSEED PYTHONHOME PYTHONINSPECT PYTHONINTMAXSTRDIGITS \
	PYTHONIOENCODING PYTHONMALLOC PYTHONMALLOCSTATS PYTHONOPTIMIZE \
	PYTHONPATH PYTHONPLATLIBDIR PYTHONPROFILEIMPORTTIME PYTHONPYCACHEPREFIX \
	PYTHONSAFEPATH PYTHONSTARTUP PYTHONTRACEMALLOC PYTHONUNBUFFERED \
	PYTHONUSERBASE PYTHONUTF8 PYTHONWARNDEFAULTENCODING PYTHONWARNINGS

python3() (
	set +e
	cache_dir=$(/usr/bin/mktemp -d /tmp/qperiapt-python-cache.XXXXXXXX)
	if [ -z "$cache_dir" ] || [ ! -d "$cache_dir" ] || [ -L "$cache_dir" ]; then
		printf 'error: cannot create a private Python bytecode-cache prefix\n' >&2
		exit 125
	fi
	if ! /bin/chmod 0700 "$cache_dir"; then
		/bin/rmdir "$cache_dir" 2>/dev/null || :
		printf 'error: cannot restrict the private Python bytecode-cache prefix\n' >&2
		exit 125
	fi

	# -I blocks caller environment and user site packages; -S blocks all site and
	# .pth startup code; -B prevents writes.  The private empty prefix prevents
	# CPython from reading a forged adjacent timestamp/hash pyc before -B matters.
	"$QPERIAPT_PYTHON" -I -S -B -X "pycache_prefix=$cache_dir" \
		"$QPERIAPT_PYTHON_BOOTSTRAP" "$@"
	python_status=$?

	if ! /bin/rmdir "$cache_dir"; then
		printf 'error: hardened Python cache prefix was unexpectedly populated: %s\n' "$cache_dir" >&2
		exit 125
	fi
	exit "$python_status"
)
