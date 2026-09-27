#!/bin/sh
# Cargo's host build tools must not inherit the Apple SDK deployment floor.
# Only invocations with an explicit supported --target produce SDK objects.
set -eu
compiler=$1
shift
sdk_target=
expect_target=0
for argument do
	if [ "$expect_target" -eq 1 ]; then
		if [ -z "$argument" ]; then exit 2; fi
		sdk_target=$argument
		expect_target=0
	elif [ "$argument" = "--target" ]; then
		if [ -n "$sdk_target" ]; then exit 2; fi
		expect_target=1
	else
		case "$argument" in
			--target=*)
				if [ -n "$sdk_target" ]; then exit 2; fi
				sdk_target=${argument#--target=}
				if [ -z "$sdk_target" ]; then exit 2; fi ;;
		esac
	fi
done
if [ "$expect_target" -ne 0 ]; then exit 2; fi
unset MACOSX_DEPLOYMENT_TARGET IPHONEOS_DEPLOYMENT_TARGET
case "$sdk_target" in
	"") ;; # proc macros, build scripts and compiler queries run on the host
	aarch64-apple-darwin|x86_64-apple-darwin)
		MACOSX_DEPLOYMENT_TARGET=13.0
		export MACOSX_DEPLOYMENT_TARGET ;;
	aarch64-apple-ios|aarch64-apple-ios-sim|x86_64-apple-ios)
		IPHONEOS_DEPLOYMENT_TARGET=16.0
		export IPHONEOS_DEPLOYMENT_TARGET ;;
	*) printf 'error: unsupported Apple SDK rustc target\n' >&2; exit 2 ;;
esac
exec "$compiler" "$@"
