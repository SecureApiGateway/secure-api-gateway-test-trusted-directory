#!/usr/bin/env bash
# Manage configurations for the ForgeRock platform. Copies configurations in git to the Docker/ folder
#    Can optionally export configuration from running products and copy it back to the git /config folder.
# This script is not supported by ForgeRock.
set -oe pipefail

## Start of arg parsing - originally generated by argbash.io
die()
{
	local _ret=$2
	test -n "$_ret" || _ret=1
	test "$_PRINT_HELP" = yes && print_help >&2
	echo "$1" >&2
	exit ${_ret}
}


begins_with_short_option()
{
	local first_option all_short_options='pch'
	first_option="${1:0:1}"
	test "$all_short_options" = "${all_short_options/$first_option/}" && return 1 || return 0
}

# THE DEFAULTS INITIALIZATION - POSITIONALS
_positionals=()

_arg_profile="${_PROFILE:-test-trusted-directory}"
_arg_environment="${_ENVIRONMENT:-dev}"
_arg_version="${_VERSION:-7.3.0}"
_arg_ig_mode=${_IGMODE:-development}
_IGMODES=(production development)

print_help()
{
#  test init add clean diff restore
	printf '%s\n' "manage ForgeRock platform configurations"
	printf 'Usage: %s [-p|--profile <arg>] [-c|--component <arg>] [-v|--version <arg>] [-h|--help] <operation>\n' "$0"
	printf '\t%s\n' "<operation>: operation is one of"
	printf '\t\t%s\n' "test   - Prints main script values"
	printf '\t\t%s\n' "init   - to copy initial configuration. This deletes any existing configuration in docker/"
	printf '\t\t%s\n' "add    - to add to the configuration. Same as init, but will not remove existing configuration"
	printf '\t\t%s\n' "diff   - to run the git diff command"
	printf '\t\t%s\n' "restore - restore git (abandon changes)"
	printf '\t%s\n' "-p, --profile: Select configuration source (default: 'securebanking')"
	printf '\t%s\n' "-e, --env: Select configuration environment source (default: 'dev')"
	printf '\t%s\n' "-igm, --igmode: Select configuration environment source values['production', 'development'(default)]"
	printf '\t%s\n' "-v, --version: Select configuration version (default: '7.3.0')"
	printf '\t%s\n' "-h, --help: Prints help"
	printf '\n%s\n' "example: config.sh -e dev -igm development init"
}


parse_commandline()
{
	_positionals_count=0
	while test $# -gt 0
	do
		_key="$1"
		case "$_key" in
			-p|--profile)
				test $# -lt 2 && die "Missing value for the optional argument '$_key'." 1
				_arg_profile="$2"
				shift
				;;
			--profile=*)
				_arg_profile="${_key##--profile=}"
				;;
			-p*)
				_arg_profile="${_key##-p}"
				;;
			-v|--version)
				test $# -lt 2 && die "Missing value for the optional argument '$_key'." 1
			    _arg_version="$2"
				shift
				;;
			--version=*)
				_arg_version="${_key##--version=}"
				;;
			-v*)
				_arg_version="${_key##-v}"
				;;
			-h|--help)
				print_help
				exit 0
				;;
			-h*)
				print_help
				exit 0
				;;
		  -e|--env)
				test $# -lt 2 && die "Missing value for the optional argument '$_key'." 1
			    _arg_environment="$2"
				shift
				;;
			--env=*)
				_arg_environment="${_key##--env=}"
				;;
			-e*)
				_arg_environment="${_key##-e}"
				;;
		  -igm|--igmode)
				test $# -lt 2 && die "Missing value for the optional argument '$_key'." 1
				modefounded="false"
        for v in "${_IGMODES[@]}"; do
          if [ "$2" == "$v" ]; then
            modefounded="true"
          fi
        done
          if [ "$modefounded" != "true" ]; then
            echo "ERROR: $2 isn't a valid value for the argument '$_key'."
            print_help
            exit 0
          fi
			    _arg_ig_mode="$2"
				shift
				;;
			--igmode=*)
				_arg_ig_mode="${_key##--igmode=}"
				;;
			-igm*)
				_arg_ig_mode="${_key##-igm}"
				;;
			*)
				_last_positional="$1"
				_positionals+=("$_last_positional")
				_positionals_count=$((_positionals_count + 1))
				;;
		esac
		shift
	done
}

handle_passed_args_count()
{
	local _required_args_string="'operation'"
	test "${_positionals_count}" -ge 1 || _PRINT_HELP=yes die "FATAL ERROR: Not enough positional arguments - we require exactly 1 (namely: $_required_args_string), but got only ${_positionals_count}." 1
	test "${_positionals_count}" -le 1 || _PRINT_HELP=yes die "FATAL ERROR: There were spurious positional arguments --- we expect exactly 1 (namely: $_required_args_string), but got ${_positionals_count} (the last one was: '${_last_positional}')." 1
}

assign_positional_args()
{
	local _positional_name _shift_for=$1
	_positional_names="_arg_operation "

	shift "$_shift_for"
	for _positional_name in ${_positional_names}
	do
		test $# -gt 0 || break
		eval "$_positional_name=\${1}" || die "Error during argument parsing, possibly an Argbash bug." 1
		shift
	done
}

parse_commandline "$@"
handle_passed_args_count
assign_positional_args 1 "${_positionals[@]}"

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)" || die "Couldn't determine the script's running directory, which probably matters, bailing out" 2

# End of arg parsing


# clear the product configs $1 from the docker directory.
clean_config()
{
    ## remove previously copied configs
    echo "removing $1 configs from $DOCKER_ROOT"

    if [ "$1" == "amster" ]; then
        rm -rf "$DOCKER_ROOT/$1/config"
    elif [ "$1" == "am" ]; then
	      rm -rf "$DOCKER_ROOT/$1/config"
    elif [ "$1" == "idm" ]; then
        rm -rf "$DOCKER_ROOT/$1/conf"
	      rm -rf "$DOCKER_ROOT/$1/script"
	      rm -rf "$DOCKER_ROOT/$1/ui"
    elif [ "$1" == "ig" ]; then
        rm -rf "$DOCKER_ROOT/$1/config"
        rm -rf "$DOCKER_ROOT/$1/scripts"
    fi
}

init_config()
{
  echo "${PROFILE_ROOT}/$1"
  if [ -d "${PROFILE_ROOT}/$1" ]; then
    echo "*********************************************************************************************"
    echo "Initialisation of 'docker/$_arg_version/$1' for [$_arg_environment] environment in [$_arg_ig_mode] mode"
    echo "*********************************************************************************************"
    echo "copy ${PROFILE_ROOT}/$1/scripts to $DOCKER_ROOT/$1/"
    cp -r "${PROFILE_ROOT}/$1/scripts" "$DOCKER_ROOT/$1/"
    echo "copy ${PROFILE_ROOT}/$1/config/$_arg_environment/config to $DOCKER_ROOT/$1/"
    cp -r "${PROFILE_ROOT}/$1/config/$_arg_environment/config" "$DOCKER_ROOT/$1/"
    jq --arg mode "$(echo $_arg_ig_mode | tr '[:lower:]' '[:upper:]')" '.mode = $mode' "$DOCKER_ROOT/$1/config/"admin.json > "$DOCKER_ROOT/$1/config/"admin.json.tmp
    mv "$DOCKER_ROOT/$1/config/"admin.json.tmp "$DOCKER_ROOT/$1/config/"admin.json
    echo "IG mode $_arg_ig_mode"
    if [ "$_arg_ig_mode" == "development" ]; then
      init_routes_dev "$1"
    else
      echo "copy ${PROFILE_ROOT}/$1/routes/ to $DOCKER_ROOT/$1/config"
      cp -r "${PROFILE_ROOT}/$1/routes/" "$DOCKER_ROOT/$1/config"
    fi
  fi
}

init_routes_dev(){
  echo "copy ${PROFILE_ROOT}/$1/routes/ to $DOCKER_ROOT/$1/config"
  if [ ! -d "$DOCKER_ROOT/ig-local/config/routes" ]; then
    echo "Creating the Directory $DOCKER_ROOT/$1/config/routes"
    mkdir "$DOCKER_ROOT/$1/config/routes"
  fi
  find "${PROFILE_ROOT}/$1/routes/"*/ -type f -print0 | xargs -0 -I {} cp {} "$DOCKER_ROOT/$1/config/routes/"
}

# Show the differences between the source configuration and the current Docker configuration
# Ignore dot files, shell scripts and the Dockerfile
# $1 - the product to diff
diff_config()
{
	for p in "${COMPONENTS[@]}"; do
		echo "diff  -u --recursive ${PROFILE_ROOT}/$p $DOCKER_ROOT/$p"
		diff -u --recursive -x ".*" -x "Dockerfile" -x "*.sh" "${PROFILE_ROOT}/$p" "$DOCKER_ROOT/$p" || true
	done
}

# chdir to the script root/..
cd "$script_dir/.."
PROFILE_ROOT="config/$_arg_version/$_arg_profile"
DOCKER_ROOT="secure-api-gateway-test-trusted-directory-docker/$_arg_version"


# if [ "$_arg_component" == "all" ]; then
# COMPONENTS=(idm ig amster am)
# else
#	COMPONENTS=( "$_arg_component" )
# fi
# core only uses IG component
COMPONENTS=(ig)

case "$_arg_operation" in
test)
  echo "Environment: " $_arg_environment
  echo "Docker root: " $DOCKER_ROOT
  echo "Operation:" $1
  echo "Profile root: " ${PROFILE_ROOT}
  echo "Components: " ${COMPONENTS}
  ;;
init)
	for p in "${COMPONENTS[@]}"; do
		clean_config "$p"
		init_config "$p"
	done

#	rm -rf docker/forgeops-secrets/forgeops-secrets-image/config
#	mkdir -p docker/forgeops-secrets/forgeops-secrets-image/config
#
#	echo "Copying version to version.sh"
#	echo -n "CONFIG_VERSION=${_arg_version}" > docker/forgeops-secrets/forgeops-secrets-image/config/version.sh
	;;
add)
	# Same as init - but do not delete existing files.
	for p in "${COMPONENTS[@]}"; do
		init_config "$p"
	done
	;;
clean)
	for p in "${COMPONENTS[@]}"; do
		clean_config "$p"
	done
	;;
diff)
	diff_config
	;;
restore)
	git restore "$PROFILE_ROOT"
	;;
*)
	echo "Unknown command $_arg_operation"
esac
