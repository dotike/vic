#!/bin/sh

# This bootstrap program is run during AWS instance launch.
#
# This template program has key variables expanded from the values in
# `${CLUSTER}/instances.ini`, and is not intended to be executed directly.
# Template expansion is done by pboot_lib.
#
# IMPORTANT: do not add more variables to this program, instead,
# remove variables and secrets until only hostname/host-unique identifiers
# remain.
#
# During runtime, this program does not appear to hit disk, behavior is
# documented in AWS as "user_data" and --user-data.
# http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/user-data.html
#
# Because of size constraints for EC2 user data, it has 3 small chores:
#   1) reliably fetch bootstrap.sh from S3 internal bucket
#   2) write bootstrap config (TODO STUB: Currently contains secrets!)
#   3) reliably ensure run bootstrap.sh


yell() { echo "$0: $*" >&2; }
die() { yell "$*"; exit 111; }
try() { "$@" || die "cannot $*"; }

bootlogger() { try logger -t "bootstrap.${_iid}" "${local_ip}:${0}: ${*}"; }

cleanup() {
# Files to remove and general cleaning up after ourseleves.
# Intended to be called via trap as well as after execution.
# Caution with safety functions, because various things here may exit nonzero.
  bootlogger "stage zero cleanup"
  rm "${_dl_temp}"
}

sourceif() {
# only sources file if it exists,
# expects file to be sourced as argv1
bootlogger "sourcing ${1}"
if [ -r "${1}" ] ; then
  . "${1}"
 _count=$((_count+1))
 _shortcircuit="1"
fi
}

fetch_bootstrap() {
# Intended to be rock-solid download, failure here results in silent DOA server.
  bootlogger "fetching actual bootstrap from S3"
  _repeat="${retry_count:-2}"
  _dl_temp="`try mktemp ${bootstrap_tmp}/${bootstrap_program}.XXXX`"
  while [ ${_repeat} -gt 0 ] ; do
    curl -sf --connect-timeout ${conn_timeout} --output "${_dl_temp}" "${s3_bootstrap_url}"
    [ $? = 0 ] && break
    _repeat="$((_repeat - 1))"
    yell "WARNING: failed to reach S3 for ${s3_bootstrap_url}, will retry ${_repeat} more times before bailing."
    sleep "${retry_wait}"
  done
  [ ${_repeat} -le 0 ] && die "FATAL: failed ${retry_count} times to fetch from S3, ${s3_bootstrap_url}"

  # simple decryption of the file per deploy_bootstrap.sh
  # please heed the encryption notice in that file 'encrypt_lite' function

  export encrypt_passphrase="${encrypt_passphrase}"
  try openssl enc -aes-256-cbc -d \
    -salt -pass "env:encrypt_passphrase" \
    -in "${_dl_temp}" \
    -out "${_dl_temp}.decrypted"
  unset encrypt_passphrase

  try chmod 755 "${_dl_temp}.decrypted"
  try mv "${_dl_temp}.decrypted" "${local_bootstrap_program}"
  bootlogger "actual bootstrap fetched, decrypted, and installed from S3"
}

write_configs() {
# critical handoff for $bootstrap_program
# contatins secrets and way too many variables, both practices deprecated
  try mkdir -p "${sys_config_dir}"  
  try touch "${sys_config_dir}/${sys_config_filename}"
  try chmod 0600 "${sys_config_dir}/${sys_config_filename}"

  bootlogger "write config from template secrets to "${sys_config_dir}/${sys_config_filename}""
  try cat - << EOF > "${sys_config_dir}/${sys_config_filename}"
# `date`
# This config was set during bootstrap by ${0##*/}
#
# Templatized configuration paramiters, values derived from python config
# ".ini" files, ultimately parsed and expanded by "pboot_lib.py".

domain_name="%domain_name%"
instance_role="%instance_role%"
set_role_dns="%set_role_dns%"
add_role_cname="%add_role_cname%"
cpengine_master_special_bootstrap="%cpengine_master_special_bootstrap%"
no_register_dns="%no_register_dns%"
no_register_elb="%no_register_elb%"
awscli_url="%awscli_url%"
cpengine_deb_url="%cpengine_deb_url%"
ec2_region="%ec2_region%"
ec2_access_key="%ec2_access_key%"
ec2_secret_key="%ec2_secret_key%"
ec2_url="%ec2_url%"
worker_queue="%worker_queue%"
worker_process_number="%worker_process_number%"
redeye_chunk_id="%redeye_chunk_id%"

# TODO: capture these for use by new update_hostname_in_dns
dns_sqs_queue="%dns_sqs_queue%"
dns_sqs_region="%dns_sqs_region%"
EOF
  bootlogger "config for boostrap in place "${sys_config_dir}/${sys_config_filename}""
}

run_bootstrap() {
# set lockfile while kicking off our program, retry on failure: 
  bootlogger "locking and executing bootstrap program"
  _repeat="${retry_count:-2}"
  while [ ${_repeat} -gt 0 ] ; do
    flock -x -w "${conn_timeout}" "${bootstrap_lock}" "${local_bootstrap_program}"
    [ $? = 0 ] && break
    _repeat="$((_repeat - 1))"
    yell "WARNING: failed to run ${local_bootstrap_program}, will retry ${_repeat} more times before bailing."
    sleep "${retry_wait}"
  done
  [ ${_repeat} -le 0 ] && die "FATAL: failed ${retry_count} times to run ${bootstrap_program}"
  bootlogger "bootstrap program has been successfully run"
}


## vars

bootstrap_program="bootstrap.sh"
s3_bootstrap_url="files.foo.tld/bootstrap/${bootstrap_program}.enc"
local_bootstrap_program="/etc/${bootstrap_program}"
sys_config_dir="/etc/bootstrapconfig"
sys_config_filename="bootstrap_withsecrets.conf"
retry_count="6"    # controls both download and kickoff retries
retry_wait="5"     # wait between retries
conn_timeout="5"   # network connection timeout 
bootstrap_lock="/tmp/bootstrap.lock"
bootstrap_tmp="/tmp"
# ENV var to reference self for subsequent programs,
export BOOTCONFIG="${0}"

# This "light security" passphrase is used in programs fetching the programs.
# Check the 'encrypt_lite' function in accompanying 'deploy_bootstrap.sh' for
# scope and usage.
encrypt_passphrase="khN0ZGluKT0gOTU2N3YjhkZDQ2NWQ3NTM5ODc3Mzc2NGMzYTc5YTVkNwo"


## action

bootlogger "START stage 0 bootstrap, AWS metadata run."
trap 'cleanup' 0 1 2 3 6 14 15
fetch_bootstrap
write_configs
run_bootstrap
bootlogger "FINISH stage zero bootstrap, AWS metadata run."

true
