#!/bin/sh

# "A program which does the actual bootstrapping work,
# globally accessable to all hosts via internal S3 bucket,
#  (or, alternatively, a simple static web server).
# Intended be run by aws-user_data-template.sh, but with some
# attention to runtime locking, could also be run from cron.
#
# Functional Intent: Safely, do as little as possible to hand off to
# CFEngine automation to control the host.
# This bootstrap still does way too much,  please whittle away
# features every time you touch it.
#
# Implementation Intent: Isolate the bootstrap stage of a server
# launch to only the most primitive and "run everywhere" tasks.
#
# FUTURE WORK AND INTENT:
# + remove all AWS related *writes*
#   - installs py packages way too early, entangles upstream cfengine
#   - implements worker clustering logic, should be managed by workers
#     (at least this should definately not be hacked into *this* layer)
#   - setting aws metadata here makes devolate/burg/future cry
#
# Note: TODO STUB comments left below for future work.
#

# A rare mutation of the 3-finger claw, typically don't do this unless it's
# part of a build/bootstrap process which inherently has tons of output.
# This change reliably lets us try to get our meaningful *failing* line,
# out to network syslog if this bootstrap fails.
yell() { echo "$0: $*" >&2; }
yelltwice() { yell "$*"; bootlogger "BOOTSTRAP FAILED: $0: $*"; }
die() { yelltwice "$*"; exit 111; }
try() { "$@" || die "cannot $*"; }

bootlogger() { try logger -t "bootstrap.${_iid}" "${local_ip}:${0}: ${*}"; }

cleanup_files() {
# files remove/handle after bootstrapping work is complete
# don't use safety functions, by this point cfengine may be running and cause
# various things to exit nonzero
  bootlogger "deleting bootstrap materials"

  rm -f "${BOOTCONFIG}" # original aws-user_data-template.sh if exists
  # Unsure if we want to leave or keep config for now, 
  rm -f "${sys_config_dir}/${sys_config_filename}"
  rm -f "${0}"
  
  # log messages from the host will dissappear until cfengine takes over,
  bootlogger "WARNING: Last bootstrap message, trusting cfengine to handle syslog config from here, さよなら"
  rm -f "${remote_syslog_conf}"
  rm -f "${remote_syslog_conf_qa}"
  service rsyslog restart
}

purge_aptitude() {
# CFEngine will prefer aptitude over apt-get if both are installed. We
# don't want aptitude to be used, so we have to remove it. CFengine can
# remove aptitude itself, but after it does it still tries to use it for
# the remainder of the current run, which throws errors and slows
# provisioning time. So we improve efficiency by removing it here.
# Note that CFEngine's software/packages.cf still includes aptitude in the
# list of packages to remove, so if we change our minds we need to update
# that too.
  bootlogger "aptitude purge START"
  try apt-get --assume-yes purge aptitude
  bootlogger "aptitude purge FINISH"
}

scrub_entropy() {
# Cannot trust that seed entropy is not from snapshot, which makes an insanely
#  dangerous condition for boot/early crypto, like fetching packages :)
# Scrub /var/run/random-seed and re-seed it just like man page examples,
# http://man7.org/linux/man-pages/man4/random.4.html
  bootlogger "re-seed entropy START, first breath full of pollen"
  _random_seed="/var/run/random-seed"
  # Carry a random seed from start-up to start-up
  # Load and then save the whole entropy pool
  if [ -f "${_random_seed}" ]; then
    try rm "${_random_seed}"
  fi
  try touch "${_random_seed}"
  try chmod 600 "${_random_seed}"
  _bits="`cat /proc/sys/kernel/random/poolsize 2> /dev/null`"
  _bytes=$(expr ${_bits:-4096} / 8)
  dd if=/dev/urandom of="${_random_seed}" count=1 bs="${_bytes}"
  bootlogger "re-seed entropy FINISH"
}

set_wallclock() {
# make sure time is set
# (cfengine will clobber this config later but go ahead anyhow)
  bootlogger "ntp sync START, cfengine will handle more later"
  try apt-get --assume-yes install ntp
  ntpd -gq
  try service ntp restart
  bootlogger "ntp sync FINISH"
}

ca_cert_update() {
# make sure ssl/ssh/crypto/cert-bundle all up to date
  bootlogger "crypt update START"
  bootlogger "update-ca-certificates..."
  # update-ca-certificate may not exist before Ubuntu >=14.04 era,
  # and may not succeed on the few remaining Ubuntu 12.x hosts.
  update-ca-certificates
  bootlogger "update openssl, openssh-server"
  try apt-get --assume-yes install openssl openssh-server
  bootlogger "crypt update FINISH"
}

syslog_remote_quickset() {
# set up to speak to remote syslog server to continue bootstrap, e.g.
# /etc/rsyslog.d/<syslog_config_name.conf>
  bootlogger "set remote syslog server START"

  # TODO: re-visit this brittle QA/Prod logic.
  # Simple solution: set domain in /etc/resolv.conf and use short hostname
  #  (requires untangling work in current DNS setup)
  # In future VPC's, can greatly simplify config by simply sending
  # messages to the same domain named 'syslog.foo.tld', and trust the zone.
  if [ "${domain_name}" = "foo.tld" ] ; then
try cat - << EOF > "${remote_syslog_conf:?FATAL: missing remote_syslog_conf path}"
# `date`
# This config was set during bootstrap by ${0##*/}
# This config should be overwritten by cfengine later.
# ${remote_syslog_conf}
#
# Send all the logs to the centralized log server as UDP
*.* @syslog.foo.tld
EOF
  else
try cat - << EOF > "${remote_syslog_conf_qa:?FATAL: missing remote_syslog_conf_qa path}"
# `date`
# This config was set during bootstrap by ${0##*/}
# This config should be overwritten by cfengine later.
# ${remote_syslog_conf_qa}
#
# Send all the logs to the centralized log server as UDP
*.* @syslog.qaolate.com
EOF
  fi
    try service rsyslog restart
    bootlogger "set remote syslog server FINISH"
    _mic_count="6"
    for i in `seq 1 ${_mic_count}` ; do
      # time for rsyslog to coalesce
      bootlogger "mic check ${i} of ${_mic_count}"
      sleep 1
    done
    bootlogger "`hostname` server instance reporting for service, still running ${0##*/}"
}

request_dns_names() {
# Request one or more DNS entries upstream.
# Requires local hostname to have been set, set_local_hostname() here.
# Expects var 'instance_hostname' in this program.
# Respects --no-register-dns for unique role names, but still sets
# host-unique domain names.

  # order of events may get funky in the larger program,
  [ -x /usr/local/bin/update_hostname_in_dns ] || fetch_dns_updater
  # 'OK if this is already run, safe and idemvicent,
  test_no_register_dns

  # Worst case time, ~60 minutes. best case time, ~30 minutes.
  # See update_hostname_in_dns -h for more info,
  export RETRIES="${dns_retries}"

  # These nested functions help clarify final test logic,
  __dns_req_full_hostname() {
    # All hosts request regular CNAME, e.g. 'full.hostname.role.fqdn.tld',
    # worst case time, ~60 minutes. best case time, ~30 minutes.
    # Because it's unique to the host, this happens even when
    # --no-register-dns touchfile exists,
    bootlogger "requesting common DNS entry: `hostname`.${domain_name}"
    try /usr/local/bin/update_hostname_in_dns -f
  }
  __dns_req_unique_rolename() {
    # This is a double-safety, the update_hostname_in_dns program
    # also bails for --no-register-dns touchfile.
    if [ -f "${pop_dns_no_register_file}" ] ; then
      bootlogger "WARNING: Found '--no-register-dns' touchfile, not registering DNS name '${instance_role}.${domain_name}' due to presence of ${pop_dns_no_register_file}, please follow post-deploy instructions for this type of host."
    else
      bootlogger "Requesting unique role DNS entry: ${instance_role}.${domain_name}"
      try /usr/local/bin/update_hostname_in_dns \
        -N "${instance_role}.${domain_name}"
    fi
  }
  __dns_request_convenience_shortname() {
    # convienence breadcrumbs only, aids finding a redundant host
    # when all you have is instance id, (from logs, aws, or our tooling...)
    # Because it's unique to the host, this happens even when
    # --no-register-dns touchfile exists,
    bootlogger "requesting convienence DNS entry: ${instance_id}.${domain_name}"
    try /usr/local/bin/update_hostname_in_dns \
      -f -N "${instance_id}.${domain_name}"
  }
  __dns_request_additional_role_cname() {
    # Feature added to allow for arbitrary CNAME to be added to balance
    # CFEngine enttanglements parsing domain names when they are >64 character names
    bootlogger "requesting additionally specified role DNS entry: ${add_role_cname}.${domain_name}"
    try /usr/local/bin/update_hostname_in_dns \
      -f -N "${add_role_cname}.${domain_name}"
  }


  # default names set for hosts across the entire fleet,
  __dns_req_full_hostname
  __dns_request_convenience_shortname
  #
  # set via instances .ini config,
  if [ "${set_role_dns}" = 'yes' ] ; then
    bootlogger "WARNING: Explicitly setting role based DNS entry, 'set_role_dns = yes'."
    __dns_req_unique_rolename
  elif [ "${set_role_dns}" = 'no' ] ; then
    bootlogger "Explicitly not setting role based DNS entry, 'set_role_dns = no'."
  else
    bootlogger "By default, not setting role based DNS entry, 'set_role_dns' not defined for this role.."
  fi

  if [ ! "${add_role_cname}" = 'none' ] ; then
    bootlogger "Setting alternative 'add_role_cname' based DNS entry, 'add_role_cname = ${add_role_cname}'."
   __dns_request_additional_role_cname
  fi

  unset RETRIES
}

set_local_hostname() {
# sets local hostname and hosts file - uniformly across hosts.
# Expects var 'instance_hostname' in this program.
# This function expects the following variables to have already been set:
#
#   instance_id, unique ID for the host
#   instance_role, role as defined from .ini
#   domain_name, top level domain, typically an internal TLD
#   local_hostname, a combination of some of the above variables
#
# TODO STUB: Future DR/Multi-site may want to include
# geographic zone (ec2_region) for local hostname, yet we
# now set region as a search domain in resolv.conf/TLD.
# Check out the set_local_resolv function in this bootstrap.

  _full_hostname="${local_hostname}.${domain_name}"

  bootlogger "hostname about to change from `hostname` to ${_full_hostname}"

  # Sanity check if our hostname is greater than 64 characters,
  # defined in Linux kernel compile-time variable '_POSIX_HOST_NAME_MAX'
  [ ${#_full_hostname} -gt 64 ] && bootlogger "ERROR: hostname longer than 64 characters: ${_full_hostname}"

  # set our hostname file and load it
  echo "${_full_hostname}" > /etc/hostname
  try hostname --file /etc/hostname
  bootlogger "hostname set to `hostname`"

  # set our hosts file,
try cat - << EOF > /etc/hosts
# `date`
# This config was set during bootstrap by ${0##*/}
#
## DUE TO USE OF 'hostname -f' in legacy utils, positional params are critical for us.
## (Do not use 'hostname -f', Ubuntu's hostname(1) implementation is woefully incomplete.)
127.0.0.1 ${_full_hostname} ${instance_id} ${local_hostname} localhost
::1 ${_full_hostname} ${instance_id} ${local_hostname} ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
ff02::3 ip6-allhosts
EOF
  bootlogger "Finished setting /etc/hosts"
}

set_local_resolv() {
# sets local resolv.conf domain to persist between reboots
# TODO STUB: Future DR/Multi-site may want to include
# geographic zone (ec2_region) for local hostname, yet we
# now set region as a search domain in resolv.conf/TLD.
  bootlogger "Writing DHCP aware resolv.conf settings."

  _resolv_dhcp_file='/etc/resolvconf/resolv.conf.d/base'
  _domainline="domain ${domain_name}"
    bootlogger "resolv: ${_domainline}"
  _searchline="search ${domain_name} ${ec2_region}"
    bootlogger "resolv: ${_searchline}"

  try mkdir -p `dirname "${_resolv_dhcp_file}"` 
  echo "# `date`" > "${_resolv_dhcp_file}"
  echo "# Set during bootstrap and should not be changed," \
    >> "${_resolv_dhcp_file}"
  echo "${_domainline}" >> "${_resolv_dhcp_file}"
  echo "${_searchline}" >> "${_resolv_dhcp_file}"
  try resolvconf -u
}

ask_aws() {
# convienence for querying AWS metadata API
# expects last URI method call as argv1
  curl -sf --connect-timeout 3 \
    "http://169.254.169.254/latest/meta-data/${1:?FATAL: missing URI method for AWS meta-data API}"
}

test_no_register_dns() {
# If automation set as True, touch the file to prevent dns from being updated.
  if [ "${no_register_dns}" = "True" ] ; then
    try mkdir -p "${ourlocal_etc_dir}"
    try touch "${pop_dns_no_register_file}"
    bootlogger "no_register_dns involked, touchfile prevents dns update ${pop_dns_no_register_file}"
  fi
}

test_no_register_elb() {
# If this is true, touch the file to prevent restart_service_elb from
# registering the instance with an ELB automatically
  if [ "${no_register_elb}" = "True" ] ; then
    try mkdir -p "${ourlocal_etc_dir}"
    try touch "${ourlocal_elb_no_register_file}"
    bootlogger "Flag placed to prevent registration with ELB, touched ${ourlocal_elb_no_register_file}"
  fi
}

install_basics() {
# installs some very basic software necessary for bootstrapping
  bootlogger "git software install START"
  [ `command -v git` ] || try apt-get --assume-yes install git
  bootlogger "Basic OS software installs completed."
}

install_cfengine() {
# only performs our install of cfengine software, for clients or server
  bootlogger "CFEngine software install START"
  _breadcrumbs="`pwd -L`"
  _download_dir="`try mktemp -d /${tmpdir}/${0##*/}.XXX`"
  try cd "${_download_dir}"
  try wget -T 10 "${cfengine_deb_url}"
  try dpkg -i `basename "${cfengine_deb_url}"`
  try cd "${_breadcrumbs}"
  try rm -rf "${_download_dir}"
  bootlogger "CFEngine software install FINISH"
}

start_cfengine() {
# bootstrap start of cfengine,
# NOTICE: better not be doing much more work as cfengine takes control!
  bootlogger "NOTICE: CFEngine starting on `hostname`, bootstrap relinquishing control."
  try /var/cfengine/bin/cf-agent --bootstrap "${cfengine_hub_url}"
}

uncool_notice() {
# Log notice for deprecated or architecturally coupled operation.
# accepts optional string arg.
  _descr="${*:-couple together discrete systems, partcularly to host bootstrapping}"
  bootlogger "UNCOOL: It is uncool to ${_descr}, http://blackskyresearch.net/cool.mp3"
}

install_awscli() {
# aws cli will get re-installed with a bundle in cfengine:/software/packages.cf
# Sadly, it must still be installed during bootstrap for these reasons:
# 1) AWS tags cannot be *set* using curl, (without seriously reverse-engineering the aws cli).
# Some metadata can however be read trivially using curl(1), (and should be, in every case.)
# 2) AWS instance types do not uniformly allow setting tags during instantiation
# http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/svic-requests.html#concepts-svic-instances-request-tags
# 3) moving tag setting logic to CFEngine brings unique stateful information
# into what is otherwise totally uniform and stateless, which is a critical objective for
# all automation in CFEngine.
  bootlogger "installing awscli"
  # Check for and install the AWS CLI if it's not there
  if [ ! "`command -v aws`" ] ; then
# TODO: after 12.x is gone, fetch a .deb via apt from apt from our 14.04 repos
    # We expect the tgz archive at $awscli_url to contain a single folder
    # called 'awscli-bundle' (as it does from AWS)
    echo "Installing the AWS CLI"
    curl "${awscli_url}" | tar -xz
    ./awscli-bundle/install -i /usr/local/aws -b /usr/local/bin/aws
    rm -rf awscli-bundle
  fi

  # Configure aws credentials
  [ -f "${aws_root_cred}" ] && bootlogger "WARNING: overwriting ${aws_root_cred}"
  try mkdir -p `dirname "${aws_root_cred}"`
    echo '[default]' > "${aws_root_cred}"
    try chmod 0600 "${aws_root_cred}" # note this ordering intent for what comes next,
    echo "aws_access_key_id = $ec2_access_key" >> "${aws_root_cred}"
    echo "aws_secret_access_key = $ec2_secret_key" >> "${aws_root_cred}"
}

install_euca2ools() {
# It would be good to get this out of the bootstrap, used here for SQS requests.
# SQS queries can be crafted trivially and sent via curl(1).
  bootlogger "installing euca2ools"
  # Make sure the euca2ools are installed,
  [ `command -v euca-describe-tags` ] || try apt-get --assume-yes install euca2ools

  # Make sure the euca2ools configuration directory exists,
  [ -d /etc/euca2ools ] || try mkdir /etc/euca2ools

  # Configure credentials for euca2ools 2.x
  if [ ! -f /etc/euca2ools/eucarc ] ; then
    echo "${cfengine_etc_eucarc}" > /etc/euca2ools/eucarc
    try chmod 0600 /etc/euca2ools/eucarc
  fi

  # Configure credentials for euca2ools 3.x
  if [ ! -f /etc/euca2ools/euca2ools.ini ] ; then
    echo "${cfengine_etc_euca2ools_ini}" > /etc/euca2ools/euca2ools.ini
    try chmod 0600 /etc/euca2ools/euca2ools.ini
  fi
}

tag_instance() {
# expects argv1 as key, argv2 as value - expecting no spaces in args themselves.
# sets these variables as local config, expected promotion to a
# network-global location (currently AWS tags).
# TODO STUB: This tagging alltogether is some uncool architectural action,
  uncool_notice "tag instances during bootstrapping, requiring early/special heavy software install"
  _repeat="${retry_count:-2}"
  while [ ${_repeat} -gt 0 ] ; do
    # Sometime the euca-create-tags hangs on a SYN, timeout is needed
    timeout "${net_timeout}" euca-create-tags --tag "${1}=${2}" "${instance_id}"
    [ $? = 0 ] && break
    _repeat="$((_repeat - 1))"
    bootlogger "WARNING: failed to reach AWS for instance tagging, will retry ${_repeat} more times before bailing."
    sleep "${retry_wait}"
  done
  if [ ${_repeat} -le 0 ] ; then
    die "FATAL: failed ${retry_count} times to set our tag in AWS: ${1}=${2}"
  fi
}

fetch_dns_updater() {
# Fetch update_hostname_in_dns program from wherever we were fetched from
# mv it to /usr/local/bin/update_hostname_in_dns with correct perms first.
# Rely on program to handle all dns setting logic, we just fetch/set/run it.

  bootlogger "Fetching and installing update_hostname_in_dns."

  _local_result="/usr/local/bin/update_hostname_in_dns"
  _repeat="${retry_count:-2}"
  _dl_temp="`try mktemp /${tmpdir}/update_hostname_in_dns.XXX`"
  _dl_url="${s3_bootstrap_url}/update_hostname_in_dns.enc"

  while [ ${_repeat} -gt 0 ] ; do
    curl -sf --connect-timeout 3 --output "${_dl_temp}" "${_dl_url}"
    [ $? = 0 ] && break
    _repeat="$((_repeat - 1))"
    bootlogger "WARNING: failed to reach AWS S3 to fetch ${_dl_url}, will retry ${_repeat} more times before bailing."
    sleep "${retry_wait}"
  done
  if [ ${_repeat} -le 0 ] ; then
    msg="FATAL: failed ${retry_count} times to fetch ${_dl_url}"
    bootlogger "${msg}"
    die "${msg}"
  fi

  # simple decryption of the file per deploy_bootstrap.sh
  # please heed the encryption notice in that file 'encrypt_lite' function
  # TODO: rip this out once we have no-auth solution, (VPC S3 endpoint)
  export encrypt_passphrase="${encrypt_passphrase}"
  try openssl enc -aes-256-cbc -d \
    -salt -pass "env:encrypt_passphrase" \
    -in "${_dl_temp}" \
    -out "${_dl_temp}.decrypted"
  unset encrypt_passphrase

  try chmod 755 "${_dl_temp}.decrypted"
  try mv "${_dl_temp}.decrypted" "${_local_result}"
}

cfengine_masterserver_extras() {
# PLEASE DO NOT add any functionality to this function.
# CFEngine automation servers will always be a special snowflake, naturally.
# Docs for deploying a new CFEngine server can be found here,
  _cfe_setup_doc='https://github.com/ourlocal/doc/blob/master/teams/ops/cfengine.md'

  bootlogger "NOTICE: A CFEngine Server coming online, extra bootstrap config in progress, ${_cfe_setup_doc}."

  _cfengine_root_ssh_config="`cat <<END
# Originally deployed from ${0##*/} $(date)
# ${_cfe_setup_doc}
# Dropping TUFU validation is pretty darned dangerous but what else can we do,
Host github.com
    StrictHostKeyChecking no
    IdentityFile ~/.ssh/github_cfengine_deploy
END`"
  # force write a working config during bootstrap,
  echo "${_cfengine_root_ssh_config}" > /root/.ssh/config

  # writes a stub file, respects that a key may already exist
  _cfengine_stub_deploy_key="`cat <<END
# this is a dummy file for private key
# deployed via ${0##*/} $(date)
# Human: Replace this file with a working GitHub SSH deploy key, instructions are here:
# ${_cfe_setup_doc}
END`"
  # writes a dummy file, tries to respect that a key may already exist
  _gh_cfe_dk="/root/.ssh/github_cfengine_deploy"
  if [ ! -f "${_gh_cfe_dk}" ] ; then
    bootlogger "WARNING: CFEngine not functional until a human admin deploys /root/.ssh/github_cfenine_deploy"
    echo "${_cfengine_stub_deploy_key}" > "${_gh_cfe_dk}"
    try chmod 0600 "${_gh_cfe_dk}"
  fi
}

set_aws_tags() {
# TODO get tagging (and aws tooling) out of boostrap long-term
  uncool_notice "setting AWS tags during bootstrap, this logic should move to CFEngine"
  tag_instance "Name" "${local_hostname}"
  tag_instance "Role" "${instance_role}"
  tag_instance "Domain" "${domain_name}"

  # on all hosts, just set em' if you got em',
  if [ "${worker_queue}" ] && [ "${worker_process_number}" ] ; then
      uncool_notice "set Queue and Concurrency on behalf of workers, as a hack during bootstrap"
      tag_instance "Queue" "${worker_queue}"
      tag_instance "Concurrency" "${worker_process_number}"
  fi
  if [ "${redeye_chunk_id}" ] ; then
    uncool_notice "set 'Chunk' on behalf of workers, as a hack during bootstrap"
    tag_instance "Chunk" "${redeye_chunk_id}"
  fi
}

write_configs() {
# Writes and populates config files for anyone to use later,
# both shell sourcable and .ini for convienence.
# DO NOT write any secrets to these files.

  bootlogger "Writing bootstrap config for future users: ${sys_postboostrap_config} and companion ${sys_postboostrap_config}"
  try touch "${sys_postboostrap_config}"
  try chmod 640 "${sys_postboostrap_config}"
  try touch "${sys_postboostrap_ini}"
  try chmod 640 "${sys_postboostrap_ini}"

try cat - << EOF > "${sys_postboostrap_config}"
# `date`
# This config was set during bootstrap by ${0##*/}
# This file should contain no secrets.
# ${0##*/} version ${version}

domain_name="${domain_name}"
instance_role="${instance_role}"
set_role_dns="${set_role_dns}" 
add_role_cname="${add_role_cname}"
no_register_dns="${no_register_dns}" 
no_register_elb="${no_register_elb}" 
awscli_url="${awscli_url}" 
cfengine_deb_url="${cfengine_deb_url}"
ec2_region="${ec2_region}" 
ec2_url="${ec2_url}" 
# Tags which may exist for worker instances,
worker_queue="${worker_queue}"  
redeye_chunk_id="${redeye_chunk_id}"
# 'Concurrency' tag for workers,
worker_process_number="${worker_process_number}"
EOF

try cat - << EOF > "${sys_postboostrap_ini}"
# This file is a Python .ini corollary to ${sys_postboostrap_config}
# deployed here for convienence.

[default]
EOF

  try grep . "${sys_postboostrap_config}" \
    | try sed 's/=/ = /' \
    >> "${sys_postboostrap_ini}"

  try chmod 0444 "${sys_postboostrap_config}"
  try chmod 0444 "${sys_postboostrap_ini}"
}


## vars

version='2.2'

# Now we get all our templated variables, and should be the only coordination
# to keep in sync with config set by aws-user_data-template.sh,
sys_config_dir="/etc/ourlocal"
sys_config_filename="bootstrap_withsecrets.conf"
try . "${sys_config_dir}/${sys_config_filename}"

# Post-bootstrap, we'll leave behind these files for the life of the host:
# DO NOT LEAVE ANY SECRETS BEHIND.
sys_postboostrap_name="bootstrap"
sys_postboostrap_config="${sys_config_dir}/${sys_postboostrap_name}.conf"
sys_postboostrap_ini="${sys_config_dir}/${sys_postboostrap_name}.ini"


boostrap_lockout="/etc/bootstrap_completed.touchfile"
tmpdir="${TEMP_DIR:-/tmp}"
ourlocal_dir="${ourlocal_dir:-/ourlocal}"
ourlocal_etc_dir="${ourlocal_dir}/etc"
pop_dns_no_register_file="${ourlocal_etc_dir}/no_register_dns"
ourlocal_elb_no_register_file="${ourlocal_etc_dir}/no_register_elb"
# Make the DNS TTL 300s on live, 60s elsewhere (e.g. QA),
if [ "${domain_name}" = "foo.tld" ] ; then
  dns_ttl="${TTL:-300}"
else
  dns_ttl="${TTL:-60}"
fi
aws_root_cred='/root/.aws/credentials'
s3_bootstrap_url="files.foo.tld/bootstrap"

# This "light security" passphrase is used in programs fetching the programs.
# Check the 'encrypt_lite' function in accompanying 'deploy_bootstrap.sh' for
# scope and usage.
# TODO rip this out along with openssl code in fetch_dns_updater function,
encrypt_passphrase=" create one "

# Sometimes the euca-create-tags hangs on a SYN, timeout is needed
net_timeout=60
# retry count for things which may hang,
retry_count=5
retry_wait=2
bootstrap_lock="/tmp/bootstrapping.lock"

# DNS retry logic, refer to update_hostname_in_dns -h for more info,
dns_retries=180

# syslog config file location, gets removed before cfengine takes over:
remote_syslog_conf="/etc/rsyslog.d/01-bootstrap-production-syslog.conf"
remote_syslog_conf_qa="/etc/rsyslog.d/01-bootstrap-qa-syslog.conf"

# fetch instance id reliably,
# STUB: different host/vendor identification strings possible here,
_iid="`ask_aws instance-id`"
instance_id="${_iid:-no-aws-id}"
_lip="`ask_aws local-ipv4`"
local_ip="${_lip:-no-aws-id}"

# addtional massaging for inherited tags template pachenko,
[ "${worker_queue}" = "%worker_queue%" ] && worker_queue=''
[ "${redeye_chunk_id}" = "%redeye_chunk_id%" ] && redeye_chunk_id=''
# For the 'Concurrency' tag,
[ "${worker_process_number}" = "%worker_process_number%" ] && worker_process_number=''
#
# checking inherited vars, bail if these don't exist,
domain_name="${domain_name:?template var %domain_name% not set}"
instance_role="${instance_role:?template var %instance_role% not set}"
no_register_dns="${no_register_dns:?template var %no_register_dns% not set}"
no_register_elb="${no_register_elb:?template var %no_register_elb% not set}"
awscli_url="${awscli_url:?template var %awscli_url% not set}"
cfengine_deb_url="${cfengine_deb_url:?template var %cfengine_deb_url% not set}"
ec2_region="${ec2_region:?template var %ec2_region% not set}"
ec2_access_key="${ec2_access_key:?template var %ec2_access_key% not set}"
ec2_secret_key="${ec2_secret_key:?template var %ec2_secret_key% not set}"
ec2_url="${ec2_url:?template var %ec2_url% not set}"

# checking optional inherited vars, 
worker_queue="${worker_queue:-}"
redeye_chunk_id="${redeye_chunk_id:-}"
worker_process_number="${worker_process_number:-}"
set_role_dns="${set_role_dns:-undefined}"
add_role_cname="${add_role_cname:-none}"
cfengine_master_special_bootstrap="${cfengine_master_special_bootstrap:-undefined}"

# full hostname without the TLD,
local_hostname="${instance_id}.${instance_role}"

# QA will get its own CFEngine hub, everyone else uses the live one
_instance_tld="`echo "${domain_name:-FATAL: no domain_name var}" | awk -F  "." '{print tolower($(NF-1)) "." tolower($NF)}'`"
if [ "${_instance_tld}" = qaolate.com ] ; then
  cfengine_hub_url="cfengine.qaolate.com"
else
  cfengine_hub_url="cfengine.foo.tld"
fi

cfengine_root_ssh_config="`cat <<END
# Originally deployed from ${0##*/} $(date)
# Dropping TUFU validation is pretty darned dangerous but what else can we do,
Host github.com
    StrictHostKeyChecking no
    IdentityFile ~/.ssh/github_cfengine_deploy
END`"

cfengine_etc_eucarc="`cat <<END
ec2_access_key=${ec2_access_key}
ec2_secret_key=${ec2_secret_key}
ec2_url=$ec2_url
END`"

cfengine_etc_euca2ools_ini="`cat <<END
[global]
default-region = ${ec2_region}

[user pops]
key-id = ${ec2_access_key}
secret-key = ${ec2_secret_key}

[region aws:${ec2_region}]
ec2-url = ${ec2_url}
user = pops
END`"


## action

# bail early if we've already run bootstrap,
if [ -f "${boostrap_lockout}" ] ; then
  cleanup_files # attempt to delete myself, etc... 
  _nopmsg="FATAL: bootstrap has already been run to completion on this host (${boostrap_lockout})."
  bootlogger "${_nopmsg}" ; die "${_nopmsg}"
fi

# righteous pwd,
try cd "${tmpdir}"
#
# minimal set of critical system basics
#
# start logging remotely ASAP
syslog_remote_quickset
# ensure system entropy is scrubbed
scrub_entropy

# perform any necessary OS upgrade/cleanup, keep it to bootstrap requisites
  #    (order below is critical)
purge_aptitude
try apt-get update # OLD COMMENT: Needed to apt-get install anything and prevent 404s
# TODO STUB maybe?: we do not upgrade all packages in hosts, but instead
# selectively upgrade packages via cfengine (cfengine:software/packages.cf).
# If we want to change this, re-visit this Asana ticket:
# https://app.asana.com/0/322042960726488/373088630304419
# Uncomment this line to close the above ticket,
#try apt-get upgrade

  # make sure time is set
set_wallclock
  # make sure ssl/ssh/crypto/cert-bundle all up to date
ca_cert_update

# required software installs for bootstrapping,
install_basics
install_awscli
install_euca2ools
# critical: get cfengine installed
install_cfengine

# O, be some other name!  What's in a name?
#
# override logic set from various ops utilities,
test_no_register_dns
test_no_register_elb
# rely on update_hostname_in_dns to do its job and handle overrides,
fetch_dns_updater
#
set_local_hostname
set_local_resolv
request_dns_names

# TODO STUB: Deprecated, move AWS tagging logic to cfengine.
set_aws_tags

# Special handling for CFEngine master, (hostname/dns handled separately),
[ "${cfengine_master_special_bootstrap}" = "yes" ] && cfengine_masterserver_extras

# write non-secret bootstrap vars for future use,
write_configs
# prevent ourselves from running again,
try touch "${boostrap_lockout}"

##############################################################################
# Let go and get outta' here...

# ensure cfengine is running, (hands off control to CFEngine),
start_cfengine

# delete myself and bootstrap utils, and make it snappy,
cleanup_files

true
