#!/bin/sh
#
#   Copyright ® Juniper Networks, Inc. 2021. All rights reserved.
#
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
#     dpdk-devbind.py – output of nic dpdk is and is not bound to (128t cmd)
#     lscpu – cpu information (linux cmd)
#     lsblk – disk block information (linux cmd)
#     systemctl list-unit-files – gets the list of all services
#     obtains the following files:
#        /root/.bash_history, /etc/chrony.conf, /etc/sysconfig/network,
#        /etc/sysconfig/network-scripts/ifcfg-*, /etc/128technology/global.init,
#        /etc/128technology/local.init, /etc/hostname
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
SORT_CMD="${USR_BIN}/sort"
SYSTEMCTL_CMD="${USR_BIN}/systemctl"
TAR_CMD="${USR_BIN}/tar"
TEE_CMD="${USR_BIN}/tee"
TOUCH_CMD="${USR_BIN}/touch"
YUM_CMD="${USR_BIN}/yum"
HOSTNAME_CMD="${USR_BIN}/hostname"

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

EEPROM_VALIDATE_CMD="/usr/libexec/hardwareBootstrapper128t"

## Local functions
## usage should match parsing section below
function usage()
{
    cat << EODOC

    Usage: $(basename $0) [full] [-a|--archive-name] [-d|--dnf-yum-count] [-j|--journalctl-count]

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

EODOC
}

## Set Local variables
## Set a date stamp
date_stamp=`date +%m-%d-%Y-%H-%M-%S`

#default base_scan_name
base_scan_name=""

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

## qmicli command list
qmicli_cmd_list="dms-get-firmware-preference dms-list-stored-images dms-swi-get-current-firmware nas-get-signal-strength dms-get-ids dms-get-manufacturer dms-get-model dms-get-revision dms-get-software-version uim-get-card-status wds-get-profile-list=3gpp wds-get-packet-service-status"

## param to request user yes or no input to proceed
request_yorn_response=0

## Force run override
force_scan_run=0

## Store off the cmdline args
cmd_line_args="$0 $@"

# Ok process cmdline arguments here before proceeding:
while [[ "$#" -gt 0 ]] ; do
    case $1 in
        full) run_mode="${1}"; echo "RUNNING IN FULL MODE";;
        -a|--archive-name) base_scan_name="${2}";
                           echo "Setting archive name to: '${2}'";
                           shift;;
        -d|--dnf-yum-count) dnf_yum_history_count="${2}";
                            request_yorn_response=1;
                            echo "Setting dnf/ym count to: '${2}'";
                            shift;;
        -j|--journalctl-count) journalctl_line_count="${2}";
                               request_yorn_response=1;
                               echo "Setting journalctl count to: '${2}'";
                               shift;;
        -b|--boot-scan-count) boot_scan_count="${2}";
                               request_yorn_response=1;
                               echo "Setting boot scan count to: '${2}'";
                               shift;;
        -l|--boot-scan-line-count) boot_scan_line_count="${2}";
                               request_yorn_response=1;
                               echo "Setting boot scan line count to: '${2}'";
                               shift;;
        -f|--force_run) force_scan_run=1;
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
## Set the bsae_scan_dir
if [ "${base_scan_name}" == "" ] ; then
    base_scan_dir="/tmp/fai-scan-${date_stamp}"
    ## Set the tar archive file based on the base_scan_dir
    tar_archive_name="${base_scan_dir}.tgz"
else
    base_scan_dir="/tmp/${base_scan_name}-${date_stamp}"
    ## Set the tar archive file based on the base_scan_dir
    tar_archive_name="${base_scan_dir}-fai-scan.tgz"
fi

## Make tmp dir for collection
${MKDIR_CMD} ${base_scan_dir}

if [ "${run_mode}" == "summary" ] ; then
    ${ECHO_CMD} "** RUNNING IN SUMMARY MODE ***"
fi

## Set summary report file and include command line options in this file
summary_report_file="${base_scan_dir}/Summary-report.txt"
${ECHO_CMD} " Running with ${cmd_line_args} " | ${TEE_CMD} ${summary_report_file}

# commands to run
${ECHO_CMD} " Collecting FAI command information ..."
${ECHO_CMD} "running ${DMIDECODE_CMD}" | ${TEE_CMD} -a ${summary_report_file}
${DMIDECODE_CMD} > ${base_scan_dir}/dmidecode-output.txt

${ECHO_CMD} "running ${LSHW_CMD}" | ${TEE_CMD} -a ${summary_report_file}
${LSHW_CMD} > ${base_scan_dir}/lshw-output.txt

${ECHO_CMD} "running ${LSPCI_CMD}" | ${TEE_CMD} -a ${summary_report_file}
${LSPCI_CMD} -nnvvvv > ${base_scan_dir}/lspci-vvvv-output.txt

${ECHO_CMD} "running ${LSMOD_CMD}" | ${TEE_CMD} -a ${summary_report_file}
${LSMOD_CMD} > ${base_scan_dir}/lsmod-output.txt

${ECHO_CMD} "running ip a" | ${TEE_CMD} -a ${summary_report_file}
${IP_CMD} a > ${base_scan_dir}/ip_a-output.txt

${ECHO_CMD} "Collecting dpdk-devbind output" | ${TEE_CMD} -a ${summary_report_file}
dpdk-devbind.py --status dev >> ${base_scan_dir}/dpdk-devbind.txt

${ECHO_CMD} "Collect Misc system information" | ${TEE_CMD} -a ${summary_report_file}
${LSCPU_CMD} > ${base_scan_dir}/lscpu-free-info.txt
${FREE_CMD} >> ${base_scan_dir}/lscpu-free-info.txt

${ECHO_CMD} "Collecting disk information" | ${TEE_CMD} -a ${summary_report_file}
${LSBLK_CMD} > ${base_scan_dir}/disk-info-output.txt
${FDISK_CMD} -l >> ${base_scan_dir}/disk-info-output.txt

${ECHO_CMD} "running ${SYSTEMCTL_CMD} list-unit-files" | ${TEE_CMD} -a ${summary_report_file}
${SYSTEMCTL_CMD} list-unit-files > ${base_scan_dir}/systemctl_list-unit-files-output.txt

${ECHO_CMD} "collecting history" | ${TEE_CMD} -a ${summary_report_file}
${CP_CMD} -p /root/.bash_history ${base_scan_dir}/history-output.txt

${ECHO_CMD} "collecting network configuration files information" | ${TEE_CMD} -a ${summary_report_file}
${CP_CMD} -p /etc/chrony.conf ${base_scan_dir}/chrony.conf
${CP_CMD} -p /etc/sysconfig/network ${base_scan_dir}/network
${CP_CMD} -p /etc/sysconfig/network-scripts/ifcfg-* ${base_scan_dir}/

${ECHO_CMD} "collecting SSR specific files" | ${TEE_CMD} -a ${summary_report_file}
${CP_CMD} -p /etc/128technology/global.init ${base_scan_dir}/
${CP_CMD} -p /etc/128technology/local.init ${base_scan_dir}/

${ECHO_CMD} "collecting hostname information" | ${TEE_CMD} -a ${summary_report_file}
${CP_CMD} -p /etc/hostname ${base_scan_dir}/

${ECHO_CMD} "collecting last information" | ${TEE_CMD} -a ${summary_report_file}
${LAST_CMD} >> ${base_scan_dir}/last-cmd.txt

${ECHO_CMD} "Getting ${SMARTCTL_CMD} information" | ${TEE_CMD} -a ${summary_report_file}
${ECHO_CMD} "=== ${SMARTCTL_CMD} -d sat information ==" >> ${base_scan_dir}/disk-smartctl.txt
${SMARTCTL_CMD} --scan -d sat >> ${base_scan_dir}/disk-smartctl.txt
${ECHO_CMD} "=== ${SMARTCTL_CMD} -d nvme information ==" >> ${base_scan_dir}/disk-smartctl.txt
${SMARTCTL_CMD} --scan -d nvme >> ${base_scan_dir}/disk-smartctl.txt

for i in `${SMARTCTL_CMD} --scan -d sat | ${GREP_CMD} -v ^# | ${GAWK_CMD} '{print $1}'; ${SMARTCTL_CMD} --scan -d nvme | ${GREP_CMD} -v ^# | ${GAWK_CMD} '{print $1}'`
do 
    ${ECHO_CMD} "====Getting --all drive ${i} information:" >> ${base_scan_dir}/disk-smartctl.txt
    ${SMARTCTL_CMD} --all ${i} >> ${base_scan_dir}/disk-smartctl.txt
    ${ECHO_CMD} "====Getting --xall drive ${i} information:" >> ${base_scan_dir}/disk-smartctl.txt
    ${SMARTCTL_CMD} --xall ${i} >> ${base_scan_dir}/disk-smartctl.txt
done

${ECHO_CMD} "Getting Huge page information" | ${TEE_CMD} -a ${summary_report_file}
${GREP_CMD} -r "hugepages=" /boot >> ${base_scan_dir}/hugepage-boot-info.txt
${GREP_CMD} HugePages_ /proc/meminfo >> ${base_scan_dir}/hugepage-boot-info.txt

if [ -c /dev/cdc-wdm0 ] ; then
  ${ECHO_CMD} "Collecting LTE/QMI Information" | ${TEE_CMD} -a ${summary_report_file}
  ${ECHO_CMD} " obtaining ${QMICLI_CMD} information" | ${TEE_CMD} -a ${base_scan_dir}/qmicli-output.txt
  for i in ${qmicli_cmd_list}
  do
    ${ECHO_CMD} " --${i}" | ${TEE_CMD} -a ${base_scan_dir}/qmicli-output.txt
    ${QMICLI_CMD} -d /dev/cdc-wdm0 --${i} >> ${base_scan_dir}/qmicli-output.txt
    ${ECHO_CMD} "------ END ${i}" >> ${base_scan_dir}/qmicli-output.txt
  done
fi

if [ -c /dev/cdc-wdm1 ] ; then
  ${ECHO_CMD} "Collecting 2nd LTE/QMI Information" | ${TEE_CMD} -a ${summary_report_file}
  ${ECHO_CMD} " obtaining ${QMICLI_CMD} information" | ${TEE_CMD} -a ${base_scan_dir}/qmicli-output.txt
  for i in ${qmicli_cmd_list}
  do
    ${ECHO_CMD} " --${i}" | ${TEE_CMD} -a ${base_scan_dir}/qmicli-output.txt
    ${QMICLI_CMD} -d /dev/cdc-wdm1 --${i} >> ${base_scan_dir}/qmicli-output.txt
  done
fi

${ECHO_CMD} "running ${RPM_CMD} -qa ${SORT_CMD}" | ${TEE_CMD} -a ${summary_report_file}
${RPM_CMD} -qa | ${SORT_CMD} >> ${base_scan_dir}/rpm_-qa_sort-output.txt


${ECHO_CMD} "listing ${repo_saved_location} location" | ${TEE_CMD} -a ${summary_report_file}
${LS_CMD} -v ${repo_saved_location} >> ${base_scan_dir}/repo_saved_location.txt

${ECHO_CMD} "Getting core and kernel crash history" | ${TEE_CMD} -a ${summary_report_file}
${ECHO_CMD} "=== core listing" >> ${base_scan_dir}/coredumpctl-list.txt
${COREDUMPCTL_CMD} >> ${base_scan_dir}/coredumpctl-list.txt
${ECHO_CMD} "=== kernel crash listing" >> ${base_scan_dir}/coredumpctl-list.txt
${LS_CMD} -lrta /var/crash/ >> ${base_scan_dir}/coredumpctl-list.txt

${ECHO_CMD} "Getting grubby and boot information from system" | ${TEE_CMD} -a ${summary_report_file}
${ECHO_CMD} "=== grubby default-kernel" >> ${base_scan_dir}/grubby-info.txt
${GRUBBY_CMD} --default-kernel  >> ${base_scan_dir}/grubby-info.txt
${ECHO_CMD} "=== grubby default-index" >> ${base_scan_dir}/grubby-info.txt
${GRUBBY_CMD} --default-index  >> ${base_scan_dir}/grubby-info.txt
${ECHO_CMD} "=== grubby info=ALL"  >> ${base_scan_dir}/grubby-info.txt
${GRUBBY_CMD} --info=ALL  >> ${base_scan_dir}/grubby-info.txt

${ECHO_CMD} "Getting boot partition information" | ${TEE_CMD} -a ${summary_report_file}
${ECHO_CMD} "=== find /boot -ls" >> ${base_scan_dir}/boot-partition-information.txt
${FIND_CMD} /boot -ls >> ${base_scan_dir}/boot-partition-information.txt
${ECHO_CMD} "Getting /boot/grub2/grubenv"
${MKDIR_CMD} ${base_scan_dir}/boot
${CP_CMD} -p /boot/grub2/grubenv ${base_scan_dir}/boot/grub2-grubenv

## Get process tree
${ECHO_CMD} "Collecting process tree information" | ${TEE_CMD} -a ${summary_report_file}
${ECHO_CMD} " --- ${PS_CMD} -auxwww --forest" >> ${base_scan_dir}/process-list-tree.txt
${PS_CMD} -auxwww --forest >> ${base_scan_dir}/process-list-tree.txt

${ECHO_CMD} "Obtaining minimal journal information" | ${TEE_CMD} -a ${summary_report_file}
${ECHO_CMD} "==== List Boots ===" > ${base_scan_dir}/journalctl-output.txt
${JOURNALCTL_CMD} --list-boots >> ${base_scan_dir}/journalctl-output.txt

# Scan initial and ending boot entries from journalctl
${ECHO_CMD} "scanning journal information" | ${TEE_CMD} -a ${summary_report_file}
while [[ "${boot_scan_count}" -gt -1 ]] ; do
    echo "======= boot head count = ${boot_scan_count} ======" >> ${base_scan_dir}/boot-scan-count-journalctl-output.txt
    journalctl -b -${boot_scan_count} | head -${boot_scan_line_count} >> ${base_scan_dir}/boot-scan-count-journalctl-output.txt
    echo "======= boot tail count = ${boot_scan_count} ======" >> ${base_scan_dir}/boot-scan-count-journalctl-output.txt
    journalctl -b -${boot_scan_count} -n ${boot_scan_line_count} --no-page >> ${base_scan_dir}/boot-scan-count-journalctl-output.txt
    ((boot_scan_count--))
done

## Non summary information here
if [ "${run_mode}" == "full" ] ; then 
  ${ECHO_CMD} "RUNNING IN FULL MODE" | ${TEE_CMD} -a ${summary_report_file}
  ${ECHO_CMD} "running ${RPM_CMD} -qa -V" | ${TEE_CMD} -a ${summary_report_file}
  for i in `${RPM_CMD} -qa | ${SORT_CMD}` 
  do
    ${ECHO_CMD} " --- ${i}" >> ${base_scan_dir}/rpm_-qa_-V-output.txt
    ${RPM_CMD} -V ${i} >> ${base_scan_dir}/rpm_-qa_-V-output.txt
  done

  ${ECHO_CMD} "running journctl" | ${TEE_CMD} -a ${summary_report_file}
  ${ECHO_CMD} "==== List dmesg ===" >> ${base_scan_dir}/journalctl-output.txt
  ${JOURNALCTL_CMD} --dmesg >> ${base_scan_dir}/journalctl-output.txt
  ${ECHO_CMD} "==== List lines ${journalctl_line_count} ===" >> ${base_scan_dir}/journalctl-output.txt
  ${JOURNALCTL_CMD} -a --lines=${journalctl_line_count} >> ${base_scan_dir}/journalctl-output.txt

  ${ECHO_CMD} "Collecting dnf and yum history information" | ${TEE_CMD} -a ${summary_report_file}
  ${ECHO_CMD} "=== running ${DNF_CMD} history count ${dnf_yum_history_count}" | ${TEE_CMD} -a ${base_scan_dir}/dnf_history_info-output.txt
  for i in `${DNF_CMD} history | ${GREP_CMD} -vE 'ID|\-\-\-\-|history' | awk '{print $1}' | head -${dnf_yum_history_count}`
  do 
    ${ECHO_CMD} " --- ${DNF_CMD} history info $i" >> ${base_scan_dir}/dnf_history_info-output.txt
    ${DNF_CMD} history info $i >>${base_scan_dir}/dnf_history_info-output.txt
  done

  ${ECHO_CMD} "=== running ${YUM_CMD} history count ${dnf_yum_history_count}" | ${TEE_CMD} -a  ${base_scan_dir}/yum_history_info-output.txt
  for i in `${YUM_CMD} history list all | ${GREP_CMD} -vE 'ID|\-\-\-\-|history|Loaded' | awk '{print $1}' | head -${dnf_yum_history_count}`
  do
    ${ECHO_CMD} " --- ${YUM_CMD} history info $i" >> ${base_scan_dir}/yum_history_info-output.txt
    ${YUM_CMD} history info $i >> ${base_scan_dir}/yum_history_info-output.txt
  done

fi

## Collect install, dnf and yum logs
${ECHO_CMD} "Collecting install, dnf and yum logs" | ${TEE_CMD} -a ${summary_report_file}
${TAR_CMD} cvfz ${base_scan_dir}/install_dnf_yum_logs.tgz /var/log/install128t /var/log/dnf* /var/log/yum*

## Check if i2c eeprom is present
if [ -x ${I2CDETECT_CMD} -a -x ${EEPROM_VALIDATE_CMD} ] ; then
    ${ECHO_CMD} "Checking for i2c EEPROM" | ${TEE_CMD} -a ${summary_report_file}
    ## Check for the bus and log, else print not found message and move on
    ${ECHO_CMD} "==== i2c bus number ===="
    ${I2CDETECT_CMD} -l | ${GREP_CMD} -i i801 >> ${base_scan_dir}/eeprom-detection.txt
    if [ $? -eq 0 ] ; then
        ## Get SKU and SN from smidecode table and store to the eeprom text file
        serial_number=`${DMIDECODE_CMD} | ${GREP_CMD} -A8 "^System Information" | ${GREP_CMD} "Serial Number:" | ${GAWK_CMD} '{print $3}'`
        sku_number=`${DMIDECODE_CMD} | ${GREP_CMD} -A8 "^System Information" | ${GREP_CMD} "SKU Number:" | ${GAWK_CMD} '{print $3}'`
        ${ECHO_CMD} "====SN ${serial_number} and SKU ${sku_number} for system ===="
        ${ECHO_CMD} "SN: ${serial_number} and SKU: ${sku_number} " >> ${base_scan_dir}/eeprom-detection.txt
        ${ECHO_CMD} "====EEPROM Validation ====" | ${TEE_CMD} -a ${base_scan_dir}/eeprom-detection.txt
        ## Running twice because the return code for tee will be a pass
        ${EEPROM_VALIDATE_CMD} validate --sku ${sku_number} --serial ${serial_number} | ${TEE_CMD} -a ${base_scan_dir}/eeprom-detection.txt
        ${EEPROM_VALIDATE_CMD} validate --sku ${sku_number} --serial ${serial_number}
        if [ $? -eq 1 ] ; then
            ${EEPROM_VALIDATE_CMD} validate --sku ${sku_number} --serial ${serial_number} 2>&1 | ${TEE_CMD} -a ${base_scan_dir}/eeprom-detection.txt
            ${ECHO_CMD} " EEPROM validation FAILED!!! " >> ${base_scan_dir}/eeprom-detection.txt
            ${ECHO_CMD} " ************************************* " >> ${summary_report_file}
            ${ECHO_CMD} " **** EEPROM validation FAILED!!! **** " >> ${summary_report_file}
            ${ECHO_CMD} " ************************************* " >> ${summary_report_file}
        else
            ${ECHO_CMD} " EEPROM validation PASSED!!! " >> ${base_scan_dir}/eeprom-detection.txt
            ${ECHO_CMD} " ************************************* " >> ${summary_report_file}
            ${ECHO_CMD} " **** EEPROM validation PASSED!!! **** " >> ${summary_report_file}
            ${ECHO_CMD} " ************************************* " >> ${summary_report_file}
        fi
    else 
        ${ECHO_CMD} "No eeprom detected" >> ${base_scan_dir}/eeprom-detection.txt
    fi
else
    ${ECHO_CMD} "EEPROM validation tools missing, check not performed" | ${TEE_CMD} -a ${base_scan_dir}/eeprom-detection.txt >> ${summary_report_file}
fi

${ECHO_CMD} "===== Summary report being generated =======" | ${TEE_CMD} -a ${summary_report_file}
${ECHO_CMD} ""
${ECHO_CMD} "--- CPU, Model and Memory from lscpu" >> ${summary_report_file}
${GREP_CMD} -E "(CPU\(s\):|Thread\(s\) per core:|Core\(s\) per socket:|Model name:|Mem:)" ${base_scan_dir}/lscpu-free-info.txt >> ${summary_report_file}
${GREP_CMD} -A6 "description: System Memory" ${base_scan_dir}/lshw-output.txt >> ${summary_report_file}
${ECHO_CMD} "--- Vendor Information" >> ${summary_report_file}
${GREP_CMD} -A3 "Vendor:" ${base_scan_dir}/dmidecode-output.txt >> ${summary_report_file}
${ECHO_CMD} "--- System Information" >> ${summary_report_file}
${GREP_CMD} -A8 "^System Information" ${base_scan_dir}/dmidecode-output.txt >> ${summary_report_file}
${ECHO_CMD} "--- Network Interfaces" >> ${summary_report_file}
${CAT_CMD} ${base_scan_dir}/dpdk-devbind.txt >> ${summary_report_file}
${CAT_CMD} ${base_scan_dir}/disk-info-output.txt >> ${summary_report_file}
${ECHO_CMD} "--- hostname from cmd ---" >> ${summary_report_file}
${HOSTNAME_CMD} >> ${summary_report_file}

${ECHO_CMD} "-=-=-=- Boot information" >> ${summary_report_file}
if [ -d /sys/firmware/efi ] ; then
  ${ECHO_CMD} "Booted EFI" >> ${summary_report_file}
  ${ECHO_CMD} "Getting boot/efi information"
  ${CP_CMD} -p /boot/efi/EFI/centos/grub.cfg ${base_scan_dir}/boot/efi-EFI-centos-grub.cfg
  ${CP_CMD} -p /boot/efi/EFI/centos/grubenv ${base_scan_dir}/boot/efi-EFI-centos-grubenv
else
  ${ECHO_CMD} "Booted Legacy (aka: BIOS mode)" >> ${summary_report_file}
  ${ECHO_CMD} "Getting grub.cfg information"
  ${CP_CMD} -p /boot/grub2/grub.cfg ${base_scan_dir}/boot/grub2-grub.cfg
fi
${ECHO_CMD} "" >> ${summary_report_file}
if [ -f /etc/128technology/version-info/128T-ISO-release ] ; then
    ${ECHO_CMD} "--- SSR ISO version information '`cat /etc/128technology/version-info/128T-ISO-release`'" >> ${summary_report_file}
else
    ${ECHO_CMD} "--- SSR ISO version NOT FOUND" >> ${summary_report_file}
fi

if [ -d /var/log/128T-iso ] ; then
    pushd /var/log/
    ${TAR_CMD} cfp - 128T-iso | ( cd ${base_scan_dir} ; ${TAR_CMD} xfpB -)
    popd
    ${ECHO_CMD} "--- Collected ISO install logs from /var/log/128T-iso ---" >> ${summary_report_file}
else
    ${ECHO_CMD} "--- ISO install logs NOT FOUND ---" >> ${summary_report_file}
fi

if [ -f /var/log/messages ] ; then
    ${CP_CMD} -p /var/log/messages ${base_scan_dir}
fi


## This section is the new Summary output that will also be added to the Summary report file
### Disk check (Need to convert to the variablized cmd args)
for i in `lsblk | grep disk | awk '{print $1}'`; do 
    disk_space=`lsblk /dev/${i} | grep disk | grep "G" | awk '{print $4}' | sed -e 's/\..*$//g'`
    if [ -z "${disk_space}" ] ; then
        echo "    WARN: Could not determine disk size for ${i}" >> ${summary_report_file}
    elif [ ${disk_space} -le 100 ] ; then
        echo "    WARN: Disk \"${i}\" is to small with \"${disk_space}\" G space" >> ${summary_report_file}
    else
        echo "    PASSED: Disk \"${i}\" is large enough to operate SSR software with \"${disk_space}\" G space" >> ${summary_report_file}
    fi
done

${ECHO_CMD} " Tarring up scanning archive as: ${tar_archive_name}"
${TAR_CMD} cvfz ${tar_archive_name} ${base_scan_dir}

${ECHO_CMD} "======= Printing Summary report ==========="
${CAT_CMD} ${base_scan_dir}/Summary-report.txt

${ECHO_CMD} " removing archive directory: ${base_scan_dir} "
${RM_CMD} -rf ${base_scan_dir}

${ECHO_CMD} "****** FAI Scan complete ********"
${ECHO_CMD} ""
${ECHO_CMD} " Please provide the archive file: ${tar_archive_name} to the SSR team for review"

