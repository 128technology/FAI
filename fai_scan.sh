#!/bin/sh
#
#   Copyright ® Juniper Networks, Inc. 2021, 2022. All rights reserved.
#
# Version 1.9
#  -- Add archive information for eeprom before pass/fail check 
#  -- add hostname of system by default to the archive name
#  -- add option to place the archive in a different target directory
#  -- exit if mkdir operation for archive staging location cannot be created
#  -- replace echo statement to reduce run time output and provide verbose flag
#  -- create seperate Summary status file
#  -- add 128tok.sh to Summary status file
#  -- add pass/fail print function
#  -- add collection of route-* files
#  -- add in bootstrapper log collection
#  -- collect the eerpom contents into the eeprom archive file
# Version 1.8
#  -- change archiver to zip from tar
#  -- check for qmi mode vs. mbim mode
# Version 1.7
#  -- collect SSR installation logs
#  -- Collect yum and dnf logs
#  -- Insulated the /usr/bin/tee command
#  -- added echo information to summary report file
#  -- added eeprom validation
#  -- added "nn" to lspci command for vendor ID information
#  -- Changed 128T non specific text references to SSR
# Version 1.6
#  -- collect the /var/log/messages file
# Version 1.5
#  -- added lspci -vvvv
#  -- fixed finding cdc-wdm
#  -- added additional qmicli commands
#  -- added non-default check and warning message
#  -- put in protection for archive staging location removal
# Version 1.4
#  -- added last command to get login history
# Version 1.3
#  -- variablize the boot scan line count obtained
#  -- Set the default boot scan line count to 50
# Version 1.2
#  -- Changed smartctl to scan for sat and nvme type devices, from lshw
#  -- adding capture of the head and tail of the last X boot operations, default of 5
#  -- moved process forest to summary mode
#  -- moved list boots to summary mode
#  -- added additional collection information for /boot and /boot/efi
# Version 1.1
#  -- collect the information from /var/log/128T-iso if it exist
# Version 1.0
#  -- added collection of new 128T-ISO-release file and updated iso log files
#  -- dump the process list
#  -- added system information extraction from dmidecode to summary report 
#  -- added switch to use explicit name for archive in place of date stamp
#  -- added switches for dnf|yum, and journalctl output counts
# Version 0.10
#  -- added lsmod command to get loaded modules
# Version 0.9
#  -- get the hostjname from the system and add to the Summary output
# Version 0.8
#  -- Adding in listing of /var/lib/install128t/repos/saved under full
#  -- added journalctl line option
#  -- added journalctl list boots
#  -- Added coredumpctl output
#  -- variablized the nix commands
# Version 0.7
#  -- Added global.init and local.init collection
#  -- check huge pages
#  -- added smartctl scanning information
#  -- Moved location for getting systemctl service information
# Version 0.6
#  -- added disk info to summary report file
#  -- changed order of the tar and output of the summary output runtime
#  -- added identifer for EFI vs legacy boot mode
#  -- changed default mode to summary and added "full" option for full mode
# Version 0.5
#  -- added lscpu
#  -- added free
#  -- added post process to have a summary report
# Version 0.4
#  -- added dpdk-devbind.py --status dev
# Version 0.3
#  -- Added qmicli commands
# Version 0.2
#  -- Added disk information
# Version 0.1
#  -- initial script provided to SSR Partner

##
#   Details of what this script does:
##
#  Summary mode (default with no command line options), it collects:
#     dmiecode – dmidecode output (linux cmd)
#     lshw – lshw output (linux cmd)
#     lspci -vvvv - lspci output (linux cmd)
#     lsmod – lsmod output (what modules are loaded  (linux cmd)
#     ip a – Output of linux level network interface information (linux cmd)
#     ip r – Output of linux level network interface information (linux cmd)
#     dpdk-devbind.py – output of nic dpdk is and is not bound to (128t cmd)
#     lscpu – cpu information (linux cmd)
#     lsblk – disk block information (linux cmd)
#     systemctl list-unit-files – gets the list of all services
#     obtains the following files:
#        /root/.bash_history, /etc/chrony.conf, /etc/sysconfig/network,
#        /etc/sysconfig/network-scripts/ifcfg-*, /etc/128technology/global.init,
#        /etc/128technology/local.init, /etc/hostname, /etc/sysconfig/network-scripts/route-*
#     smartctl – obtains disk smarctl information found from smartctl scan of
#                 sat and nvme devices (does not support raid)
#     qmicli – If there are lte devices it will query to get information on
#              the current device(s)
#     rpm -qa – to get current installed rpms
#     ls of saved repo location
#     list journal boots
#     obtains 50 beginning and ending entries of the last 5 system boots
#          (Use -b option to change the default count)
#     “-auxwww –forest” -  Get current process tree (forest)
#     Check if the system is booted legacy or uEFI and grub information
#     Obtain 128T ISO used to image the system was (if available)
#     Obtain the /var/log/messages file
#     Obtain the install, dnf and yum logs if they exist
#     Check if jnpr eeprom exists
#     Check for JNPR eeprom and validate if possible
#     run 128tok.sh if available
#     
#      
#  Full mode (additional commands run beyond above, "full" option):
#     rpm -qa -V – gets the list of rpms from the system and performs a
#          verification on each. (This one will scan the complete database,
#          if a disk failure is suspect, this may result in the system to fail
#          in unexpected ways. If the system is healthy, there is limited risk
#          in running in this mode.
#     obtain dmesg from the last boot output
#     List last 20k journal lines (use -j option to obtain a different count)
#     obtain the last 10 dnf and yum history transactions (use -d to obtain
#          a different count)
#
##
#
#  Risk of running this script on a production system:
#    In Summary mode there are no risks. 
#    In "full" mode, the risks are:
#       1. If there is a disk failure scanning the rpms and database could
#            trigger the OS running into the disk failure.
#       2. If the system is under high load, the “rpm -V <file>” operation may
#            result in the system slowing down or have a performance impact.
#       3. The script does not check the disk space usage and puts the files
#            and archive in /tmp. If the system has limited memory this could
#            use the remaining memory available resulting in other operations
#            failing.
##


## Set linux command to specific locations
# Base command variables
USR_BIN="/usr/bin"
USR_SBIN="/usr/sbin"

## /usr/bin commands
CAT_CMD="${USR_BIN}/cat"
COREDUMPCTL_CMD="${USR_BIN}/coredumpctl"
CP_CMD="${USR_BIN}/cp"
DNF_CMD="${USR_BIN}/dnf"
ECHO_CMD="${USR_BIN}/echo"
FIND_CMD="${USR_BIN}/find"
FREE_CMD="${USR_BIN}/free"
GAWK_CMD="${USR_BIN}/gawk"
GREP_CMD="${USR_BIN}/grep"
JOURNALCTL_CMD="${USR_BIN}/journalctl"
LAST_CMD="${USR_BIN}/last"
LSBLK_CMD="${USR_BIN}/lsblk"
LSCPU_CMD="${USR_BIN}/lscpu"
LS_CMD="${USR_BIN}/ls"
MKDIR_CMD="${USR_BIN}/mkdir"
PS_CMD="${USR_BIN}/ps"
QMICLI_CMD="${USR_BIN}/qmicli"
RM_CMD="${USR_BIN}/rm"
RPM_CMD="${USR_BIN}/rpm"
SED_CMD="${USR_BIN}/sed"
SORT_CMD="${USR_BIN}/sort"
SYSTEMCTL_CMD="${USR_BIN}/systemctl"
TAR_CMD="${USR_BIN}/tar"
TAIL_CMD="${USR_BIN}/tail"
TEE_CMD="${USR_BIN}/tee"
TOUCH_CMD="${USR_BIN}/touch"
YUM_CMD="${USR_BIN}/yum"
HOSTNAME_CMD="${USR_BIN}/hostname"
ZIP_CMD="${USR_BIN}/zip"

## List of sbin commands
DMIDECODE_CMD="${USR_SBIN}/dmidecode"
FDISK_CMD="${USR_SBIN}/fdisk"
GRUBBY_CMD="${USR_SBIN}/grubby"
IP_CMD="${USR_SBIN}/ip"
LSHW_CMD="${USR_SBIN}/lshw"
LSPCI_CMD="${USR_SBIN}/lspci"
LSMOD_CMD="${USR_SBIN}/lsmod"
SMARTCTL_CMD="${USR_SBIN}/smartctl"
I2CDETECT_CMD="${USR_SBIN}/i2cdetect"
I2CDUMP_CMD="${USR_SBIN}/i2cdump"

EEPROM_VALIDATE_CMD="/usr/libexec/hardwareBootstrapper128t"

# terminal color/style control characters
TERMINAL_COLOR_RED='\033[0;31m'
TERMINAL_COLOR_BLUE='\033[0;34m'
TERMINAL_COLOR_GREEN='\033[0;32m'
TERMINAL_COLOR_NONE='\033[0m'
TERMINAL_STYLE_BOLD=$(tput bold)
TERMINAL_STYLE_NORMAL=$(tput sgr0)

# 128T should run properly
STATUS_OK=0
# 128T might run, but this could be an issue
STATUS_WARN=1
# 128T will not run properly
STATUS_FAIL=2
# output indent / column width
DO_ECHO_INDENT_COUNT=29
# Message Type to display
DO_ECHO_DISPLAY_MODE=${STATUS_OK}

## Local functions
## usage should match parsing section below
function usage()
{
    cat << EODOC

    Usage: $(basename $0) [full] [-a|--archive-name] [-d|--dnf-yum-count] [-j|--journalctl-count] [-b|--boot-scan-count] [-l|--boot-scan-line-count] [-t|--targetdir]

    optional arguments:
        -h, --help            This help ;)
        full                  perform a full fai scan, this will take longer as
                                rpm scanning is done. When not passed in, a
                                summary sacn is performed
        -a|--archive-name     Create a specific archive name. directory with
                                same name in /tmp will be removed if found
                                without asking
                                default: fai-scan-(with-a-date-stamp)
        -d|--dnf-yum-count    yum and dnf history scanning count.
                                default: 10
        -j|--journalctl-count journalctl history line count output.
                                default: 20000
        -b|--boot-scan-count journalctl list-boot scan count, used to inspect
                                boot operations
                                default: 5
        -l|--boot-scan-line-count journalctl list-boot scan line count, used to
                                inspect boot operations
                                default: 50
        -t|--targetdir        target directory for the archive, must be full path
                                (This option does not request user input.)
                                default: /tmp
        -f|--force_run        Forces execution run without use request for non default
                                command line options

EODOC
}

## Function to print details to output or just to log file
##   0 - minimal - Will only print pass/fail and ending msg
##   1 - info - will print dots, and PASS fail details
##   2 - verbose - Will print details while running
function echo_info()
{
    if [ ${print_level} -eq 1 ] ; then
         ## Check the arguments passed in, 1 which is the msg or 2 which is the log file
         ## If msg only and verbose 0 do not print
         if [[ "$2" != "" ]] ; then
             ${ECHO_CMD} "${1}" >> ${2}
         fi
         ${ECHO_CMD} -n "."
    elif [ ${print_level} -eq 2 ] ; then
         ## Check the arguments passed in, 1 which is the msg or 2 which is the log file
         if [[ "$2" != "" ]] ; then
             ${ECHO_CMD} "${1}" | ${TEE_CMD} -a ${2}
         else
             ${ECHO_CMD} "${1}"
         fi
    fi
}

#
# do_echo:
# $1 - In status (0 => FAIL, !=0 => FAIL)
# $2 - In invoking function
# $3 - In message to output
#
# Outputs a string or format:
# <function|check>: [PASS|WARN|FAIL] <message>
#
# On failure, the message is bold and red on terminals which support
# color
#
function do_echo() {
    local __prestr=""
    local __poststr=""
    local __smsg=""
    local __sfunc=""

    if [ $1 -lt $DO_ECHO_DISPLAY_MODE ] ; then
        return
    fi

    if [ "$1" == "$STATUS_FAIL" ] ; then
        __prestr=${TERMINAL_COLOR_RED}
        __prestr=${__prestr}${TERMINAL_STYLE_BOLD}
        __poststr=${TERMINAL_STYLE_NORMAL}
        __smsg="FAIL"
    elif [ "$1" == "$STATUS_WARN" ] ; then
        __prestr=${TERMINAL_COLOR_BLUE}
        __prestr=${__prestr}${TERMINAL_STYLE_BOLD}
        __poststr=${TERMINAL_STYLE_NORMAL}
        __smsg="WARN"
    else
        __prestr=${TERMINAL_COLOR_GREEN}
        __prestr=${__prestr}${TERMINAL_STYLE_BOLD}
        __smsg="PASS"
        __smsg=${__smsg}${TERMINAL_STYLE_NORMAL}
    fi

    __sfunc="$2:"
    printf "%-${DO_ECHO_INDENT_COUNT}s ${__prestr}%s${__poststr}\n" "${__sfunc}" "${__smsg} ${3}" >> ${summary_status_file}
}

## Set Local variables
## Set a date stamp
date_stamp=`date +%m-%d-%Y-%H-%M-%S`

#default base_archive_name
base_archive_name=""

## /var/lib/install128t/repos/saved/
repo_saved_location="/var/lib/install128t/repos/saved/"

## Set default mode
run_mode="summary"

## Set default ${JOURNALCTL_CMD} count, default 20000
journalctl_line_count="20000"

## Set dnf and yum history count to get, default 10
dnf_yum_history_count="10"

## Set boot_scan_count default
boot_scan_count="5"

## Set boot_scan_line_count default
boot_scan_line_count="50"

## target archive directory
target_dir="/tmp"

## qmicli command list
qmicli_cmd_list="dms-get-firmware-preference \
dms-list-stored-images \
dms-swi-get-current-firmware \
nas-get-signal-strength \
dms-get-ids \
dms-get-manufacturer \
dms-get-model \
dms-get-revision \
dms-get-software-version \
uim-get-card-status \
wds-get-profile-list=3gpp \
wds-get-packet-service-status\
"

## param to request user yes or no input to proceed
request_yorn_response=0

## Force run override
force_scan_run=0

## Print output level default info
print_level=1

## Store off the cmdline args
cmd_line_args="$0 $@"

# default the return code to 5 for, unknown
summary_status_value=5

# Ok process cmdline arguments here before proceeding:
while [[ "$#" -gt 0 ]] ; do
    case $1 in
        full) run_mode="${1}";
              echo_info "RUNNING IN FULL MODE";;
        -a|--archive-name) base_archive_name="${2}";
                           echo_info "Setting archive name to: '${2}'";
                           shift;;
        -d|--dnf-yum-count) dnf_yum_history_count="${2}";
                            request_yorn_response=1;
                            echo_info "Setting dnf/ym count to: '${2}'";
                            shift;;
        -j|--journalctl-count) journalctl_line_count="${2}";
                               request_yorn_response=1;
                               echo_info "Setting journalctl count to: '${2}'";
                               shift;;
        -b|--boot-scan-count) boot_scan_count="${2}";
                               request_yorn_response=1;
                               echo_info "Setting boot scan count to: '${2}'";
                               shift;;
        -l|--boot-scan-line-count) boot_scan_line_count="${2}";
                               request_yorn_response=1;
                               echo_info "Setting boot scan line count to: '${2}'";
                               shift;;
        -t|--target-dir) target_dir="${2}";
                        echo_info "Setting archive target location to: '${2}'";
                        shift;;        
        -f|--force_run) force_scan_run=1;;
        -p|--print-level) print_level="${2}";
                    shift;;
        -h|--help) usage; exit 0;;
        *) usage; exit 1;;
    esac
    shift
done

## Check user input and force run
if [ ${request_yorn_response} -eq 1 -a ${force_scan_run} -eq 0 ] ; then
    ${ECHO_CMD} " Non-default scan options have been entered. Running this program"
    ${ECHO_CMD} "    with large scan options may take an extended amount of execution"
    ${ECHO_CMD} -n "    time and consume system resources. Continue (Y/N):"
    read answer
    case ${answer} in
        y | Y | ye | YE | yes | YES ) ${ECHO_CMD} "Running with \"${cmd_line_args}\"";;
        *) ${ECHO_CMD} "Terminating!";
           exit 0;;
    esac
fi

# Set up scan dir repository
## Set the base_archive_name
if [ "${base_archive_name}" == "" ] ; then
    target_archive_name="`hostname`-fai-scan-${date_stamp}"
else
    # Check if a "/" was passed in for the base_archive_name and get out if yes
    if [[ "${base_archive_name}" == *"/"* ]] ; then
        ${ECHO_CMD} "ERROR: the --archive-name cannot have a '/' in the name"
        exit 1
    fi
    target_archive_name="${base_archive_name}-`hostname`-fai-scan-${date_stamp}"
fi

target_archive_name="`echo ${target_archive_name}| ${SED_CMD} -e 's/\./-/g'`"
base_scan_dir="/tmp/${target_archive_name}"

## Set the tar archive file based on the base_scan_dir
archive_name="/${target_dir}/${target_archive_name}"


## Make tmp dir for collection
${MKDIR_CMD} ${base_scan_dir}
if [ "$?" -ne 0 ] ; then
    ${ECHO_CMD} "ERROR: cannot create staging directory: ${base_scan_dir}" 1>&2
    ${ECHO_CMD} "Besure the archive name does not include special characters."
    exit 1
fi

if [[ ! -e /${target_dir} ]] ; then
    ${MKDIR_CMD} /${target_dir}
elif [[ ! -d /${target_dir} ]] ; then
    ${ECHO_CMD} "ERROR: /${target_dir} exists but is not a directory." 1>&2
    exit 1
fi

if [ "${run_mode}" == "summary" ] ; then
    echo_info "** RUNNING IN SUMMARY MODE ***"
fi

## Set summary report file and include command line options in this file
summary_report_file="${base_scan_dir}/Summary-report.txt"
summary_status_file="${base_scan_dir}/Summary-status.txt"
echo_info " Running with ${cmd_line_args} " ${summary_report_file}

# commands to run
echo_info " Collecting FAI information ..."
echo_info "running ${DMIDECODE_CMD}" ${summary_report_file}
${DMIDECODE_CMD} > ${base_scan_dir}/dmidecode-output.txt 2>&1

echo_info "running ${LSHW_CMD}" ${summary_report_file}
${LSHW_CMD} -quiet > ${base_scan_dir}/lshw-output.txt 2>&1

echo_info "running ${LSPCI_CMD}" ${summary_report_file}
${LSPCI_CMD} -nnvvvv > ${base_scan_dir}/lspci-vvvv-output.txt 2>&1

echo_info "running ${LSMOD_CMD}" ${summary_report_file}
${LSMOD_CMD} | ${SORT_CMD} > ${base_scan_dir}/lsmod-output.txt

echo_info "running ip a and ip r" ${summary_report_file}
${IP_CMD} a > ${base_scan_dir}/ip_a-output.txt 2>&1
${IP_CMD} r > ${base_scan_dir}/ip_r-output.txt 2>&1

echo_info "Collecting dpdk-devbind output" ${summary_report_file}
dpdk-devbind.py --status dev >> ${base_scan_dir}/dpdk-devbind.txt

echo_info "Collect Misc system information" ${summary_report_file}
${LSCPU_CMD} > ${base_scan_dir}/lscpu-free-info.txt 2>&1
${FREE_CMD} >> ${base_scan_dir}/lscpu-free-info.txt 2>&1

echo_info "Collecting disk information" ${summary_report_file}
${LSBLK_CMD} > ${base_scan_dir}/disk-info-output.txt 2>&1
${FDISK_CMD} -l >> ${base_scan_dir}/disk-info-output.txt 2>&1

echo_info "running ${SYSTEMCTL_CMD} list-unit-files" ${summary_report_file}
${SYSTEMCTL_CMD} list-unit-files > ${base_scan_dir}/systemctl_list-unit-files-output.txt

echo_info "collecting history" ${summary_report_file}
${CP_CMD} -p /root/.bash_history ${base_scan_dir}/history-output.txt 2> /dev/null

echo_info "collecting network configuration files information" ${summary_report_file}
${CP_CMD} -p /etc/chrony.conf ${base_scan_dir}/chrony.conf
${CP_CMD} -p /etc/sysconfig/network ${base_scan_dir}/network
${CP_CMD} -p /etc/sysconfig/network-scripts/ifcfg-* ${base_scan_dir}/
${CP_CMD} -p /etc/resolv.conf ${base_scan_dir}/
${FIND_CMD} /etc/sysconfig/network-scripts/ -name route-\* -exec ${CP_CMD} {} ${base_scan_dir}/ \;

echo_info "collecting SSR specific files" ${summary_report_file}
${CP_CMD} -p /etc/128technology/global.init ${base_scan_dir}/
${CP_CMD} -p /etc/128technology/local.init ${base_scan_dir}/

echo_info "collecting hostname information" ${summary_report_file}
${CP_CMD} -p /etc/hostname ${base_scan_dir}/

echo_info "collecting last information" ${summary_report_file}
${LAST_CMD} >> ${base_scan_dir}/last-cmd.txt

echo_info "Getting ${SMARTCTL_CMD} information" ${summary_report_file}
echo_info "=== ${SMARTCTL_CMD} -d sat information ==" ${base_scan_dir}/disk-smartctl.txt
${SMARTCTL_CMD} --scan -d sat >> ${base_scan_dir}/disk-smartctl.txt 2>&1
echo_info "=== ${SMARTCTL_CMD} -d nvme information ==" ${base_scan_dir}/disk-smartctl.txt
${SMARTCTL_CMD} --scan -d nvme >> ${base_scan_dir}/disk-smartctl.txt 2>&1

for i in `${SMARTCTL_CMD} --scan -d sat | ${GREP_CMD} -v ^# | ${GAWK_CMD} '{print $1}'; ${SMARTCTL_CMD} --scan -d nvme | ${GREP_CMD} -v ^# | ${GAWK_CMD} '{print $1}'`
do 
    echo_info "====Getting --all drive ${i} information:" ${base_scan_dir}/disk-smartctl.txt
    ${SMARTCTL_CMD} --all ${i} >> ${base_scan_dir}/disk-smartctl.txt 2>&1
    echo_info "====Getting --xall drive ${i} information:" ${base_scan_dir}/disk-smartctl.txt
    ${SMARTCTL_CMD} --xall ${i} >> ${base_scan_dir}/disk-smartctl.txt 2>&1
done

echo_info "Getting Huge page information" ${summary_report_file}
${GREP_CMD} -r "hugepages=" /boot >> ${base_scan_dir}/hugepage-boot-info.txt
${GREP_CMD} HugePages_ /proc/meminfo >> ${base_scan_dir}/hugepage-boot-info.txt

for cdcwdm_name in cdc-wdm0 cdc-wdm1
do
  if [ -c /dev/${cdcwdm_name} ] ; then
    ## Init device driver name
    driver_name=""
    ## Ok get the network interface name and extract the device driver for it
    ## redirect the error to the qmicli-output for triage if needed
    net_dev_name=`${QMICLI_CMD} -d /dev/${cdcwdm_name} --device-open-proxy --get-wwan-iface 2> ${base_scan_dir}/qmicli-output.txt`
    ## Check if the qmicli command failed, if yes try another way to get to the device
    if [ "${net_dev_name}" == "" ] ; then
        net_dev_name=`ls /sys/class/usbmisc/${cdcwdm_name}/device/net/`
        ## If above fails, try a different way
        if [ "${net_dev_name}" == "" ] ; then
            echo_info "check_qmi_wwan: Cannot determine interface name extracting from lshw" ${summary_report_file}
            ## Ok last ditch effort, if this fails the check below will fail
            driver_name=`${GREP_CMD} -A7 "product: Sierra" ${base_scan_dir}/lshw-output.txt | ${GREP_CMD} "driver=" | ${GAWK_CMD} '{print $2}' | ${SED_CMD} -e's/driver=//'`
        fi
    fi

    if [ "${net_dev_name}" != "" ] ; then
        driver_name=`${CAT_CMD} /sys/class/net/${net_dev_name}/device/uevent | ${GREP_CMD} ^DRIVER | ${SED_CMD} -e's/DRIVER=//'`
    fi

    echo_info "Collecting ${cdcwdm_name} LTE/QMI net-device ${net_dev_name} Information" ${summary_report_file}
    echo_info " obtaining ${QMICLI_CMD} information for ${cdcwdm_name} net-device ${net_dev_name}" ${base_scan_dir}/qmicli-output.txt
    for i in ${qmicli_cmd_list}
    do
      echo_info " --${i}" ${base_scan_dir}/qmicli-output.txt
      ${QMICLI_CMD} -d /dev/${cdcwdm_name} --${i} >> ${base_scan_dir}/qmicli-output.txt 2>&1
      echo_info "------ END ${i}" ${base_scan_dir}/qmicli-output.txt
    done

    ## Check the driver setting
    echo_info "Wireless modem '${cdcwdm_name}' interface '${net_dev_name}' setting ${driver_name}" ${summary_report_file}
    qmi_status=${STATUS_FAIL}
    if [ "${driver_name}" == "qmi_wwan" ] ; then
        qmi_status=${STATUS_OK}
    fi
    do_echo $qmi_status "check_qmi_wwan" "modem '${cdcwdm_name}' int '${net_dev_name}' setting is ${driver_name}"
  fi
done

echo_info "running ${RPM_CMD} -qa ${SORT_CMD}" ${summary_report_file}
${RPM_CMD} -qa | ${SORT_CMD} >> ${base_scan_dir}/rpm_-qa_sort-output.txt 2>&1

echo_info "listing ${repo_saved_location} location" ${summary_report_file}
${LS_CMD} -v ${repo_saved_location} >> ${base_scan_dir}/repo_saved_location.txt

echo_info "Getting core and kernel crash history" ${summary_report_file}
echo_info "=== core listing" ${base_scan_dir}/coredumpctl-list.txt
${COREDUMPCTL_CMD} >> ${base_scan_dir}/coredumpctl-list.txt 2>&1
echo_info "=== kernel crash listing" ${base_scan_dir}/coredumpctl-list.txt
${LS_CMD} -lrta /var/crash/ >> ${base_scan_dir}/coredumpctl-list.txt

echo_info "Getting grubby and boot information from system" ${summary_report_file}
echo_info "=== grubby default-kernel" ${base_scan_dir}/grubby-info.txt
${GRUBBY_CMD} --default-kernel  >> ${base_scan_dir}/grubby-info.txt 2>&1
echo_info "=== grubby default-index" ${base_scan_dir}/grubby-info.txt
${GRUBBY_CMD} --default-index  >> ${base_scan_dir}/grubby-info.txt 2>&1
echo_info "=== grubby info=ALL"  ${base_scan_dir}/grubby-info.txt
${GRUBBY_CMD} --info=ALL  >> ${base_scan_dir}/grubby-info.txt 2>&1

echo_info "Getting boot partition information" ${summary_report_file}
echo_info "=== find /boot -ls" ${base_scan_dir}/boot-partition-information.txt
${FIND_CMD} /boot -ls >> ${base_scan_dir}/boot-partition-information.txt
echo_info "Getting /boot/grub2/grubenv"
${MKDIR_CMD} ${base_scan_dir}/boot
${CP_CMD} -p /boot/grub2/grubenv ${base_scan_dir}/boot/grub2-grubenv

## Get process tree
echo_info "Collecting process tree information" ${summary_report_file}
echo_info " --- ${PS_CMD} -auxwww --forest" ${base_scan_dir}/process-list-tree.txt
${PS_CMD} -auxwww --forest >> ${base_scan_dir}/process-list-tree.txt 2>&1

echo_info "Obtaining minimal journal information" ${summary_report_file}
echo_info "==== List Boots ===" ${base_scan_dir}/journalctl-output.txt
${JOURNALCTL_CMD} --list-boots >> ${base_scan_dir}/journalctl-output.txt 2>&1

# Scan initial and ending boot entries from journalctl
echo_info "scanning journal information" ${summary_report_file}
while [[ "${boot_scan_count}" -gt -1 ]] ; do
    echo_info "======= boot head count = ${boot_scan_count} ======" ${base_scan_dir}/boot-scan-count-journalctl-output.txt
    journalctl -b -${boot_scan_count} 2>&1 | head -${boot_scan_line_count} >> ${base_scan_dir}/boot-scan-count-journalctl-output.txt 2>&1
    echo_info "======= boot tail count = ${boot_scan_count} ======" ${base_scan_dir}/boot-scan-count-journalctl-output.txt
    journalctl -b -${boot_scan_count} -n ${boot_scan_line_count} --no-page >> ${base_scan_dir}/boot-scan-count-journalctl-output.txt 2>&1
    ((boot_scan_count--))
done

## Non summary information here
if [ "${run_mode}" == "full" ] ; then 
  echo_info "RUNNING IN FULL MODE" ${summary_report_file}
  echo_info "running ${RPM_CMD} -qa -V" ${summary_report_file}
  for i in `${RPM_CMD} -qa | ${SORT_CMD}` 
  do
    echo_info " --- ${i}" ${base_scan_dir}/rpm_-qa_-V-output.txt
    ${RPM_CMD} -V ${i} >> ${base_scan_dir}/rpm_-qa_-V-output.txt 2>&1
  done

  echo_info "running journctl" ${summary_report_file}
  echo_info "==== List dmesg ===" ${base_scan_dir}/journalctl-output.txt
  ${JOURNALCTL_CMD} --dmesg >> ${base_scan_dir}/journalctl-output.txt 2>&1
  echo_info "==== List lines ${journalctl_line_count} ===" ${base_scan_dir}/journalctl-output.txt
  ${JOURNALCTL_CMD} -a --lines=${journalctl_line_count} >> ${base_scan_dir}/journalctl-output.txt 2>&1

  echo_info "Collecting dnf and yum history information" ${summary_report_file}
  echo_info "=== running ${DNF_CMD} history count ${dnf_yum_history_count}" ${base_scan_dir}/dnf_history_info-output.txt
  for i in `${DNF_CMD} history | ${GREP_CMD} -vE 'ID|\-\-\-\-|history' | awk '{print $1}' | head -${dnf_yum_history_count}`
  do 
    echo_info " --- ${DNF_CMD} history info $i" ${base_scan_dir}/dnf_history_info-output.txt
    ${DNF_CMD} history info $i >>${base_scan_dir}/dnf_history_info-output.txt 2>&1
  done

  echo_info "=== running ${YUM_CMD} history count ${dnf_yum_history_count}" ${base_scan_dir}/yum_history_info-output.txt
  for i in `${YUM_CMD} history list all | ${GREP_CMD} -vE 'ID|\-\-\-\-|history|Loaded' | awk '{print $1}' | head -${dnf_yum_history_count}`
  do
    echo_info " --- ${YUM_CMD} history info $i" ${base_scan_dir}/yum_history_info-output.txt
    ${YUM_CMD} history info $i >> ${base_scan_dir}/yum_history_info-output.txt 2>&1
  done

fi

## Collect install, dnf and yum logs
echo_info "Collecting install, dnf and yum logs" ${summary_report_file}
pushd /var/log/ > /dev/null
${TAR_CMD} cfz ${base_scan_dir}/install_dnf_yum_logs.tgz install128t dnf* yum* 2>> ${summary_report_file}
popd > /dev/null

## Check if i2c eeprom is present
if [ -x ${I2CDETECT_CMD} -a -x ${EEPROM_VALIDATE_CMD} ] ; then
    echo_info "Checking for i2c EEPROM" ${summary_report_file}
    eeprom_status=$STATUS_WARN
    ## Check for the bus and log, else print not found message and move on
    echo_info "==== i2c bus infomation ====" ${base_scan_dir}/eeprom-detection.txt
    ${I2CDETECT_CMD} -l >> ${base_scan_dir}/eeprom-detection.txt 2>&1
    if [ $? -eq 0 ] ; then
        ## Default status to fail at this point
        eeprom_status=$STATUS_FAIL
        ## Get SKU and SN from smidecode table and store to the eeprom text file
        serial_number=`${DMIDECODE_CMD} | ${GREP_CMD} -A8 "^System Information" | ${GREP_CMD} "Serial Number:" | ${GAWK_CMD} '{print $3}'`
        sku_number=`${DMIDECODE_CMD} | ${GREP_CMD} -A8 "^System Information" | ${GREP_CMD} "SKU Number:" | ${GAWK_CMD} '{print $3}'`
        echo_info "====SN ${serial_number} and SKU ${sku_number} for system ====" ${base_scan_dir}/eeprom-detection.txt
        echo_info "SN: ${serial_number} and SKU: ${sku_number} " ${base_scan_dir}/eeprom-detection.txt
        echo_info "====EEPROM Validation ====" ${base_scan_dir}/eeprom-detection.txt
        echo_info "= Running ${EEPROM_VALIDATE_CMD} validate --sku ${sku_number} --serial ${serial_number}" ${base_scan_dir}/eeprom-detection.txt
        ## Running twice because the return code for tee will be a pass
        ${EEPROM_VALIDATE_CMD} validate --sku ${sku_number} --serial ${serial_number} >> ${base_scan_dir}/eeprom-detection.txt 2>&1
        if [ $? -eq 1 ] ; then
            echo_info " EEPROM validation FAIL!!! " ${base_scan_dir}/eeprom-detection.txt
            echo_info " ************************************* " ${summary_report_file}
            echo_info " **** EEPROM validation FAIL!!! **** " ${summary_report_file}
            echo_info " ************************************* " ${summary_report_file}
        else
            echo_info " EEPROM validation PASS!!! " ${base_scan_dir}/eeprom-detection.txt
            echo_info " ************************************* " ${summary_report_file}
            echo_info " **** EEPROM validation PASS!!! **** " ${summary_report_file}
            echo_info " ************************************* " ${summary_report_file}
            eeprom_status=${STATUS_OK}
        fi

        ## replicate the eeprom validation in the Summary status file
        ${GREP_CMD} -E "PASS|FAIL|WARN" ${base_scan_dir}/eeprom-detection.txt | ${GREP_CMD} -v "EEPROM validation" >> ${summary_status_file}
        ## place the contents of eeprom into eeprom-content.txt
        i2c_801_num="`${I2CDETECT_CMD} -l | ${GREP_CMD} -i i801 | ${GAWK_CMD} '{print $1;}' | ${TAIL_CMD} -c 2`"
        ${I2CDUMP_CMD} -y ${i2c_801_num} 0x54 >> ${base_scan_dir}/eeprom-detection.txt 2>&1
    else 
        echo_info "No eeprom detected" ${base_scan_dir}/eeprom-detection.txt
        echo_info "No eeprom detected" ${summary_report_file}
    fi
    ## validate command found so collect the logs from /var/log/128T-hardware-bootstrapper/
    if [ -d /var/log/128T-hardware-bootstrapper ] ; then
        pushd /var/log/ > /dev/null
        ${TAR_CMD} cfp - 128T-hardware-bootstrapper | ( cd ${base_scan_dir} ; ${TAR_CMD} xfpB -)
        popd > /dev/null
    fi

    ## register status of eeprom checks
    do_echo ${eeprom_status} "check_eeprom" "EEPROM validation see eeprom-detection.txt for additional information"
else
    echo_info "EEPROM validation tools missing, check not performed" ${base_scan_dir}/eeprom-detection.txt 
    echo_info "EEPROM validation tools missing, check not performed" ${summary_report_file}
fi

echo_info "===== Summary report being generated =======" ${summary_report_file}
echo_info ""
echo_info "--- CPU, Model and Memory from lscpu" ${summary_report_file}
${GREP_CMD} -E "(CPU\(s\):|Thread\(s\) per core:|Core\(s\) per socket:|Model name:|Mem:)" ${base_scan_dir}/lscpu-free-info.txt >> ${summary_report_file}
${GREP_CMD} -A6 "description: System Memory" ${base_scan_dir}/lshw-output.txt >> ${summary_report_file}
echo_info "--- Vendor Information" ${summary_report_file}
${GREP_CMD} -A3 "Vendor:" ${base_scan_dir}/dmidecode-output.txt >> ${summary_report_file}
echo_info "--- System Information" ${summary_report_file}
${GREP_CMD} -A8 "^System Information" ${base_scan_dir}/dmidecode-output.txt >> ${summary_report_file}
echo_info "--- Network Interfaces" ${summary_report_file}
${CAT_CMD} ${base_scan_dir}/dpdk-devbind.txt >> ${summary_report_file}
${CAT_CMD} ${base_scan_dir}/disk-info-output.txt >> ${summary_report_file}
echo_info "--- hostname from cmd ---" ${summary_report_file}
${HOSTNAME_CMD} >> ${summary_report_file}

echo_info "-=-=-=- Boot information" ${summary_report_file}
if [ -d /sys/firmware/efi ] ; then
  echo_info "Booted EFI" ${summary_report_file}
  echo_info "Getting boot/efi information" ${summary_report_file}
  ${CP_CMD} -p /boot/efi/EFI/centos/grub.cfg ${base_scan_dir}/boot/efi-EFI-centos-grub.cfg
  ${CP_CMD} -p /boot/efi/EFI/centos/grubenv ${base_scan_dir}/boot/efi-EFI-centos-grubenv
else
  echo_info "Booted Legacy (aka: BIOS mode)" ${summary_report_file}
  echo_info "Getting grub.cfg information" ${summary_report_file}
  ${CP_CMD} -p /boot/grub2/grub.cfg ${base_scan_dir}/boot/grub2-grub.cfg
fi
echo_info "" ${summary_report_file}
if [ -f /etc/128technology/version-info/128T-ISO-release ] ; then
    echo_info "--- SSR ISO version information '`cat /etc/128technology/version-info/128T-ISO-release`'" ${summary_report_file}
else
    echo_info "--- SSR ISO version NOT FOUND" ${summary_report_file}
fi

if [ -d /var/log/128T-iso ] ; then
    pushd /var/log/ > /dev/null
    ${TAR_CMD} cfp - 128T-iso | ( cd ${base_scan_dir} ; ${TAR_CMD} xfpB -)
    popd > /dev/null
    echo_info "--- Collected ISO install logs from /var/log/128T-iso ---" ${summary_report_file}
else
    echo_info "--- ISO install logs NOT FOUND ---" ${summary_report_file}
fi

if [ -f /var/log/messages ] ; then
    ${CP_CMD} -p /var/log/messages ${base_scan_dir}
fi


## This section is the new Summary output that will also be added to the Summary report file
### Disk check, must get at least one PASS for check to PASS, default to 0/fail
disk_check_pass=0
for i in `${LSBLK_CMD} | ${GREP_CMD} disk | ${GAWK_CMD} '{print $1}'`; do 
    ## Default the check to warning
    disk_check_status=${STATUS_WARN}
    disk_space=`${LSBLK_CMD} /dev/${i} | ${GREP_CMD} disk | ${GREP_CMD} "G" | ${GAWK_CMD} '{print $4}' | ${SED_CMD} -E -e 's/G|\..*$//g'`
    if [ -z "${disk_space}" ] ; then
        disk_check_status=${STATUS_WARN}
    elif [ ${disk_space} -ge 100 ] ; then
        disk_check_status=${STATUS_OK}
        disk_check_pass=1
    fi
    do_echo ${disk_check_status} "check_disk_space" "Disk '${i}' with '${disk_space}' G space"
done

## Final check to see if one disk was found
if [ ${disk_check_pass} -eq 0 ] ; then
    disk_check_status=${STATUS_FAIL}
    do_echo ${disk_check_status} "check_disk_space" "no disk found that is large enough for the SSR OS"
fi

## Check for the 128tok.sh script, run it, dump the contents and then post process them
if [ -x /bin/128tok.sh ] ; then
    echo_info "Running 128tok.sh" ${summary_report_file}
    /bin/128tok.sh >> ${base_scan_dir}/128tok-sh-output.txt 2>&1
    ${CAT_CMD} ${base_scan_dir}/128tok-sh-output.txt | ${GREP_CMD} -E "PASS|FAIL|WARN" | ${GREP_CMD} -v -E "check_ecc_memory|check_disk_space|All 128T Tests"  >> ${summary_status_file}
fi

## Getting summary PASS/FAIL status
get_summary_status_value="`${CAT_CMD} ${summary_status_file} | ${GREP_CMD} "FAIL"`"
if [ "${get_summary_status_value}" == "" ] ; then
    summary_status_value=${STATUS_OK}
else
    summary_status_value=${STATUS_FAIL}
fi

do_echo ${summary_status_value} "FAI Summary Status"

## cat summary_status_file into summary_report_file
${CAT_CMD} ${summary_status_file} >> ${summary_report_file}

echo_info " Compressing the scanning archive as: ${archive_name}.zip"
${ZIP_CMD} -r -qdgds 10m ${archive_name} ${base_scan_dir}

${ECHO_CMD} ""
${ECHO_CMD} "======= Printing Summary Status ==========="
${CAT_CMD} ${summary_status_file}

## " removing archive directory: ${base_scan_dir} "
${RM_CMD} -rf ${base_scan_dir}

${ECHO_CMD} ""
${ECHO_CMD} "****** FAI Scan complete ********"
${ECHO_CMD} " A FAI Summary Status of \"FAIL\" means the system does not meet the SSR runtime requirements"
${ECHO_CMD} " Please provide the archive file: ${archive_name}.zip to the SSR team for review"

exit ${summary_status_value}
