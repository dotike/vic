#!/bin/sh

# OPERATOR BEWARE:
# This utility is a one-off for rare updates to 'update_hostanme_in_dns'.
#
# Not meant to be regularly used, but in the rare cases
# when bootstrap programs need to be pushed to hosts.
# No flags, no sophistocation, no features- just safety measures.
#
# A final y/n safety must be answered in order to run.
#
# Depends:
#  - working a_list_instances on your laptop.
#  - root level access to all cluster hosts 
#

yell() { echo "$0: $*" >&2; }
die() { yell "$*"; exit 111; }
try() { "$@" || die "cannot $*"; }

chirp() { echo "$*" >&2; }

prompt_confirm() {
  while true; do
    read -r -n 1 -p "${1:-Continue?} [y/n]: " REPLY
    case $REPLY in
      [yY]) echo ; return 0 ;;
      [nN]) echo ; return 1 ;;
      *) printf "  %s \n" "invalid input"
    esac 
  done  
}

# The gateway as jump-host,
GATEWAY="${GATEWAY:-gateway.foo.tld}"
GWPORT="${GWPORT:-22}"

# The directory where this script lives,
dothere=$(cd "${0%/*}" 2>/dev/null; echo "`pwd -L`")

chirp "# Gathering hosts IP addresses, this may take some time..."
chirp "# You will be prompted before proceeding with actual file deploy."

# awk bit reverses the list, (emulates tac())
all_ips="`try a_list_instances  --role=* --output=priv_ip | awk '{a[i++]=$0} END {for (j=i-1; j>=0;) print a[j--] }'`"

# Our program details on the end host,
_end_file='/usr/local/bin/update_hostname_in_dns'
_end_perms='755'
_end_tmp='/tmp'
_end_user='root'
_end_group='root'

# Our program details on the local host,
_local_file='update_hostname_in_dns'

_cheap_rand="`date | openssl dgst -md5 -binary | xxd -p`"
_end_tmp_file="${_end_tmp}/.${_local_file}.${USER}.${_cheap_rand}"

ip_count=0
for host in ${all_ips} ; do
  ip_count=$(( $ip_count + 1 ))
done

chirp ''
chirp "You are about to push these file to ${ip_count:?No IP addresses returned by a_list_instances?} hosts:"
chirp ''
chirp "  local: ${dothere}/${_local_file}"
chirp " remote: ${_end_file}"
chirp "   mode: ${_end_perms}"
chirp "   user:group ${_end_user}:${_end_group}"

chirp ''
chirp "! THIS MAY BE A VERY DANGEROUS OPERATION: you are about to push and possibly overwrite ${_end_file} on all ${ip_count} hosts."
chirp ''
prompt_confirm "Do you really want to proceed?" || die "Bailing with no changes."
chirp ''

host_count=0
for host in ${all_ips} ; do 
  host_count=$(( $host_count + 1 ))
  echo "##############################################################################"
  echo "# ${host} `date`"
  echo "# ${host_count}/${ip_count}"

  echo "# scp our file,"
  scp -o ProxyCommand="ssh -W %h:%p ${GATEWAY}" \
     -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no \
     "${dothere}/${_local_file}" \
     "${host}:${_end_tmp_file}"
  
  echo "# move our file into place,"
  ssh -J "${GATEWAY}:${GWPORT}" \
      -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no \
      ${host} \
      "hostname ; timeout 10 ${_end_file} -V ; sudo timeout 20 install -v -o ${_end_user} -g ${_end_group} -m ${_end_perms} ${_end_tmp_file} ${_end_file} ; rm -v ${_end_tmp_file} ; timeout 10 ${_end_file} -V" 2> /dev/null

  #echo "# Test harness check,"
  #try ssh -J "${GATEWAY}:${GWPORT}" \
  #    ${host} \
  #    "hostname; ${_end_file} -V" 2> /dev/null

done 

true
