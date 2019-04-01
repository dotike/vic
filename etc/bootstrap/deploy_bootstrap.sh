#!/bin/sh

# Utility to deploy bootstrap files to internal S3 (web server).
# It is effectively a self-contained mini-deploy tool, which by itself,
# could be used safely by other programs- as well as interactively by humans.
#
# For more information please run the program with the '-h' flag,
#
#     $ thisprogram -h

yell() { echo "$0: $*" >&2; }
die() { yell "$*"; exit 111; }
try() { "$@" || die "cannot $*"; }

chirp() { fd="${fd:-2}";[ "$verbose" ] && try echo "# $*" >&${fd}; }

usage() {
# accepts 1 optional user message as string
# does not print help block if -s flag is thrown (verbose unset)
fd="${fd:-2}" # stderr
ec="${ec:-5}" # Input/output error
if [ ! "$nohelp" ] ; then
try cat - 2>&$fd << EOM

${0##*/} -- deploy boostrap files to S3 for immediate use

  usage:
       ${0##*/}
       ${0##*/} [-v|s]
       ${0##*/} [-F </optional/dir/path>

  The ${0##*/} utility is used to deploy boostrap code for use. 

  Uploaded files are encrypted using an embedded passphrase, which is
  intended to provide lightweight protection against public view
  of the code.
  Files containing secrets should NEVER be deployed to the S3
  bootstrap bucket, just code.


  CREDENTIALS/CONFIGURATION:

    To upload/deploy these files, you must have AWS Cridentials
    which allow for S3 upload to:

      ${bucket}/${aws_path}

    This program uses AWS credentials .ini configuration file, and
    defaults to '~/.aws/credentials', 'default' role, where the
    two variables will be sourced:

       [default]
       aws_access_key_id = string
       aws_secret_access_key = string

    Please refer to AWS cli setup for more information.

    The following ENV value will override the location of your AWS
    credentials file lcoation

      AWS_CONF="/path/to/.aws/credentials"

    And, the following ENV value allows named profiles other than
    'default', if that is necessary:

      AWS_CONF_PROFILE='Profile Name String'

    To enforce best security practices in this critical program, if auth
    variables are found to be previously set as ENV var overrides, this
    program will exit immediately.

    To enforce security best-practices in this critical program, if the
    following env vars are detected, this script will immediately exit:
      - access_key_id
      - secret_access_key
    This is intended to prohibit manually overriding local vars (that contain
    auth info) in this script with ones from a user's environment.

    AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY are currrently respected,
    yet they are scrubbed from ENV after they are discovered, before we
    do anything which could obviously leak them in network operatons.


  ARGUEMENTS:

     -s    Silent operation, overrides verbose if both flags thrown.

     -v    Verbose, print relevant request information for interactive use.
           Default behavior when program is called with no args.

     -h    Explain what ${0##*/} does, (this text).

     -F </optional/path/to/location>
           Fetch files, useful for debugging uploads.

  ENV:

     UPLOAD_FILES="file:path/to/file"
        Overrides default files to encrypt and upload. 
        Colon-delimited list of file paths, with their root assumed
        in the same directory as this deploy program.
        Default: 'bootstrap.sh:update_hostname_in_dns'

      AWS_CONF="/path/to/.aws/credentials"
        A path to your local credentials, see CREDENTIALS section above.
        If this is explicitly set, AWS ENV credentials are ignored.
        If this is not set, but the default file exists, AWS ENV values
        still win, matching behavior of aws-cli and friends.

      AWS_CONF_PROFILE='Profile Name String'
        Overrides AWS 'default' named profile in AWS config, .inii format.

  SEE ALSO:
      openssl(1), aws-cli
 http://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html

  BUGS:
      This help text should really be a man page.
      Currently, the lightweight use of crypto provides file validation in
      various common security cases, (e.g. MITM code replacement is hard).
      Yet, this is merely a sloppy side-effect, and does not cover actual
      validation cases.  So, when the crypto is finally removed, (VPC endpoint
      future, or other auth-less private access), either signature or checksum
      validation should be employed.

EOM
fi
[ -n "$1" ] && printf "${1}\n"
exit "$ec"
}

cleanup() {
# Files to remove and general cleaning up after ourseleves.
# Intended to be called via trap as well as after execution.
# Caution with safety functions, because various things here may exit nonzero.
  chirp "Cleaning up local temporary files."
  [ -d "${encrypted_tmpdir}" ] && rm -r "${encrypted_tmpdir}"
  [ -d "${_tmp_src}" ] && rm "${_tmp_src}"
  
}

fetch_lite() {
# expects argv1 to be a file name to fetch from bootstrap s3 location
# provided as a convienence for testing/etc,
  _target_file="${1:-Cannot fetch empty file name.}"
  _repeat="${retry_count:-1}"
  _dl_temp="`try mktemp ${fetchto}/${_target_file}.XXXX`"
  _fetch_s3_bootstrap_url="${bucket}/${aws_path}/${_target_file}.enc"
  while [ ${_repeat} -gt 0 ] ; do
    curl -sf --connect-timeout ${conn_timeout:-5} --output "${_dl_temp}" "${_fetch_s3_bootstrap_url}"
    [ $? = 0 ] && break
    _repeat="$((_repeat - 1))"
    yell "WARNING: failed to reach S3 for ${_fetch_s3_bootstrap_url}, will retry ${_repeat} more times before bailing."
    sleep "${retry_wait}"
  done
  [ ${_repeat} -le 0 ] && die "FATAL: failed ${retry_count} times to fetch from S3, ${_fetch_s3_bootstrap_url}"

  # simple decryption of the file
  # please heed the encryption notice in the 'encrypt_lite' function

  export encrypt_passphrase="${encrypt_passphrase}"
  try openssl enc -aes-256-cbc -d \
    -salt -pass "env:encrypt_passphrase" \
    -in "${_dl_temp}" \
    -out "${_dl_temp}.decrypted"

  try mv "${_dl_temp}.decrypted" "${fetchto}/${_target_file}"
  chirp "${fetchto}/${_target_file} fetched from S3 and decrypted"
}

encrypt_lite() {
# Encryption function with encryption secret embedded in this code, returns a
# path string to the encrypted file location as well the corresponding tools
# which download bootstrap files.
# This provides *lightweight* security to protect programs in S3 which we do
# not want readable by the public internet.  Embedding the secret decryption
# passphrase in this manner has 2 major problems,
#      - decryption passphrase lives in these files
# These are perfectly acceptable risks for this utility, but they deserve
# this notice.
# TODO: this can just dissapear when we move to AWS VPC, because S3 buckets
# can then simply have internal/open VPC endpoints.
# Currently, the lightweight use of crypto provides file validation as
# a sloppy side-effect.  Yet, when the crypto is finally removed, (VPC
# future or other auth-less private access), some form of either signature
# or checksum validation should be employed.
  _encrypt_filepath="${1:?FATAL: do not have name of file to encrypt}"
  _encrypt_filename="`try basename ${_encrypt_filepath}`"

  chirp "Encrypting ${dothere}/${_encrypt_filepath}"
  export encrypt_passphrase="${encrypt_passphrase}"
  try openssl enc -aes-256-cbc \
    -salt -pass "env:encrypt_passphrase" \
    -in "${dothere}/${_encrypt_filepath}" \
    -out "${encrypted_tmpdir}/${_encrypt_filename}.enc"
  chirp "Finished encrypting ${dothere}/${_encrypt_filepath}"
}

iniparse() {
# Expects an .ini format file path as argv1 input,
# optional argv2 input expect string to only load a given section name.
# A safe and portable .ini parser which sets dot delimited values e.g.:
#   section_header__key=value
# Adheres to the current Python .ini specification,
#   https://docs.python.org/3/library/configparser.html#supported-ini-file-structure
# Does not support any interpolation of values, e.g. '%(home_dir)s/lumberjack'
# No handling for 'space_around_delimiters', only can be single spaces or no characters.
# Leading and trailing whitespace is removed from keys and values, per spec.
# Key name is stripped to IEEE Std 1003.1-2001 POSIX variable names, alphanum and _ only.
  _ifs="${IFS}" ; IFS=''
  _tmp_src="`try mktemp ${tmpdir:-/tmp}/${0##*/}.XXXX`"
# strip comments, # or ; - on their own line, possibly indented
  try grep -v '^$\|^\s*[\#\|\;\]' "${1}" \
  | while read -r line ; do
    _sectiononly="${2}"
    _is_section=0
# leading and trailing whitespace removed to spec,
    _cleanline="`echo ${line}| sed 's/^[ 	]*//;s/[ 	]*$//'`"
    _starts="`echo ${_cleanline} | try cut -c1`"
    _ends="`echo ${_cleanline} | try awk '{print substr($0,length($0),1)}'`"
    if [ "`echo ${line} | grep '\(=\)\|\(:\)'`" ] ; then
      _iskeyline=1
    else
      _iskeyline=0
    fi
    if [ "${_starts}" = '[' ] && [ "${_ends}" = ']' ] ; then
      _is_section=1
      [ "${_cutearly}" = 1 ] && break
      _section_rawname="`echo ${_cleanline} | sed 's/^\[//;s/\]$//;s/ /_/g'`"
      #_section="`echo ${_section_rawname} | sed 's/^\[//;s/\]$//;s/ /_/g'`"
      _section="`echo ${_section_rawname} | sed ';s/^\[//;s/\]$//;s/  / /g;s/ /_/g'`"
      [ "${_section_rawname}" = "${_sectiononly}" ] && _cutearly=1
    elif [ "${_iskeyline}" = 1 ] ; then
      _is_section=0
      _key="`echo ${_cleanline} | awk -F'[=:]' '{print $1}' | sed 's/[ 	]*$//;s/ /_/g;s/[^a-zA-Z0-9_]//g'`"
      _value="`echo ${_cleanline} | awk -F'[=:]' '{for (i=2; i<NF; i++) printf $i " "; print $NF}' | sed 's/^[ 	]*//'`"
    elif [ "`echo ${line} | grep '^\s'`" ] && [ ! "${_starts}" = '[' ] && [ "${_iskeyline}" = '0' ] ; then
      _is_section=0
      if [ "${_value}" ] ; then
        _value="${_value} \\n${_cleanline}"
      else
        _value="${_cleanline}"
      fi
    fi
    if [ "${_starts}" = '' ] ; then
      _is_section=0
      unset _section
      unset _value
      unset _key
    elif [ -n "${_sectiononly}" ] ; then
        [ "${_cutearly}" = 1 ] && [ "${_is_section}" = 0 ] && echo "${_key}=\"${_value}\""
    else
      [ "${_is_section}" = 0 ] && [ ! ${_key} = '' ] && echo "${_section}__${_key}=\"${_value}\""
    fi
  done > "${_tmp_src}"
  IFS="${_ifs}"
  iniparse_vars="${inparse_vars} `try grep '=' "${_tmp_src}" | try cut -d '=' -f1 | sort | uniq`"
  try .  "${_tmp_src}" # code simplicity over elegance in loading
  try rm "${_tmp_src}" # also can be handled in your own trap/cleanup
  if [ -n "$DEBUG" ] ; then
     [ "${2}" ] && _sec_note=", section '${2}'"
     echo "## The program \`${0##*/}\` has sourced the following variables, from '${1}'${_sec_note}." >&${fd:-2}
     for i in $iniparse_vars ; do
       try echo "##   \"${i}\"" >&${fd:-2}
     done
     echo "## The variable '\$inparse_vars' is also available to the ${0##*/} program, and contains this list of variable names." >&${fd:-2}
     chirp "Sourced variables from '${1}'${_sec_note}."
  fi
}

put_S3_bootstrap() {
# expects local path for file to be uploaded as argv1
  _upload_filepath="${1:?FATAL: do not have name of file to upload}"
  _upload_filename="`try basename ${_upload_filepath}`"

  chirp "Beginning upload ${_upload_filepath} to S3."

  _rfc822_date="`date +'%a, %d %b %Y %T %z'`"
  # text/html relaxes CRLF requirements,
  # https://www.w3.org/Protocols/rfc2616/rfc2616-sec3.html#sec3.7
  #For plain text, "text/html; charset=utf-8"
  _content_type="application/octet-stream"

  _string="PUT\n\n${_content_type}\n${_rfc822_date}\n${acl_perms}\n/${bucket}/${aws_path}/${_upload_filename}"
  _signature="`printf "${_string}" | try openssl sha1 -hmac "${secret_access_key}" -binary | base64`"

  try curl -k -X PUT -T "${_upload_filepath}" \
    -H "Host: ${bucket}.s3.amazonaws.com" \
    -H "Date: ${_rfc822_date}" \
    -H "Content-Type: ${_content_type}" \
    -H "${acl_perms}" \
    -H "Authorization: AWS ${access_key_id}:${_signature}" \
    "https://${bucket}.s3.amazonaws.com/${aws_path}/${_upload_filename}"
  chirp "Finished uploading ${_upload_filepath} to S3."
}


## vars

verbose=1

while getopts 'F:vsh' opt; do
case "$opt" in
F) fetchto="${OPTARG}"
;;
v) verbose=1
;;
s) unset verbose
   nohelp=1
;;
h) ec=1 fd=1 usage
;;
*) usage "FATAL: unknown arguements passed # ${0##*/} ${*}"
;;
esac
done
shift $((OPTIND - 1))

chirp "Verbose mode (default behavior), -h for help and options."

# colin delimited list of target filenames to push,
local_files="${UPLOAD_FILES:-bootstrap.sh:update_hostname_in_dns}"

# absolute and portable variation of 'dirname $0',
dothere=$(cd "${0%/*}" 2>/dev/null; echo "`pwd -L`")
breadcrumbs="`try pwd -L`"
_me="`who am i | awk '{print $1}'`" # absurd portability

# remote bits,
bucket='files.foo.tld'
aws_path="bootstrap"
acl_perms="x-amz-acl:public-read"

# pre-variables ENV check, no overloading allowed in this program,
[ `env | grep -q '^access_key_id'` ] && \
  die "FATAL: ${0%/*} does not allow override of critical secrets as ENV vars."
[ `env | grep -q '^secret_access_key'` ] && \
  die "FATAL: ${0%/*} does not allow override of critical secrets as ENV vars."

# Now lets massage auth vars in order,
_confdefault="${HOME}/.aws/credentials"
aws_conf="${AWS_CONF:-$_confdefault}"
aws_conf_profile="${AWS_CONF_PROFILE:-default}"

trap 'cleanup' 0 1 2 3 6 14 15
# order of operations explained in help,
if [ ! "${AWS_CONF:--1}" = "-1" ] ; then
   chirp "Sourcing from ${AWS_CONF} because this value was specified from ENV."
   iniparse "${AWS_CONF}" "${aws_conf_profile}"
   access_key_id="${aws_access_key_id:?Missing value for 'aws_access_key_id' in ${AWS_CONF}.}"
   secret_access_key="${aws_secret_access_key:?Missing value for 'secret_access_key' in ${AWS_CONF}.}"
   unset aws_access_key_id ; unset aws_secret_access_key
elif [ "${AWS_ACCESS_KEY_ID}" ] && [ "${AWS_SECRET_ACCESS_KEY}" ] ; then
   chirp "AWS credentials being used from ENV vars."
   access_key_id="${AWS_ACCESS_KEY_ID:-ENV var AWS_ACCESS_KEY_ID set, but is empty or null}"
   secret_access_key="${AWS_SECRET_ACCESS_KEY:-ENV var AWS_SECRET_ACCESS_KEY, but is empty or null}"
elif [ -r "${aws_conf}" ] ; then
   chirp "Sourcing from default location, ${aws_conf}."
   iniparse "${aws_conf}" "${aws_conf_profile}"
   access_key_id="${aws_access_key_id:?Missing value for 'aws_access_key_id' in ${AWS_CONF}.}"
   secret_access_key="${aws_secret_access_key:?Missing value for 'aws_access_key_id' in ${aws_conf}.}"
   unset aws_access_key_id ; unset aws_secret_access_key
else
   ec=87 usage "FATAL: unable to acquire AWS credentials."
fi
# we should have picked up access_key_id and secret_access_key by now,
# lobotomize this program and it's children,
unset AWS_ACCESS_KEY_ID
unset AWS_SECRET_ACCESS_KEY
unset aws_conf
unset aws_conf_profile

# this "light security" passphrase is used in programs fetching the programs.
# Please see the 'encrypt_lite' function above for more detail on applied use.
encrypt_passphrase=" create one "

# be sure we've already trapped for exit somewhere above,
encrypted_tmpdir="`try mktemp -d /tmp/${0##*/}.enc.XXXX`"
chirp "Created temporary working directory: ${encrypted_tmpdir}"


## action

if [ "${fetchto}" ] ; then

  chirp "Fetching ${local_files} to ${fetchto}" >&2
  for file in `echo "${local_files}" | try sed 's/:/ /g'` ; do
    fetch_lite "${file}"
  done

else

  # make sure we have all local files before we start this,
  for i in `echo "${local_files}" | try sed 's/:/ /g'` ; do
    [ -r "${dothere}/${i}" ] || die "FATAL: We don't have all our local_files, nothing will be uploaded ${local_files}"
  done

  # encrypt and stage our files list,
  for i in `echo "${local_files}" | try sed 's/:/ /g'` ; do
    encrypt_lite "${i}"
  done
  unset encrypt_passphrase

  # loop it again to upload the files,
  for i in `find "${encrypted_tmpdir}" -type f` ; do
    put_S3_bootstrap "${i}"
  done

  try cd "${breadcrumbs}"

  chirp "ALL FILES UPLOADED, bootstrap files available for new hosts."

fi

true
