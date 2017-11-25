#! /bin/bash
#------------------DESCRIPTION------------------------
# bhardy, for SingleHop, LLC 11.25.2017
#
# Quick mitigation script for (CVE TBD) Exim vuln.
# That vuln potentially allows for remote code execution(!)
#------------------SRC--------------------------------
# SRC thread          : https://www.lowendtalk.com/discussion/130778/exim-security-vuln
# SRC Exim maintainers: https://lists.gt.net/exim/announce/108962
# SRC for BDAT info   : https://messagin.blogspot.com/2014/01/bdat.html
#-----------------------------------------------------
# Per maintainers, "chunking_advertise_hosts" should be set to null value to prevent this.
# This is a complete workaround. MTAs attempting a BDAT after EHLO should see it's not supported.
#
#------------------IMPACT------------------------------
# Impact of applying the workaround per Exim maintainers:
# "mail senders have to stick to the traditional DATA verb instead of using BDAT."
# Remote MTAs *should* recognize this, and simply use DATA instead per ESMTP protocol.
#
# That would look something like this:
#
# EHLO -> MTA reply with supported methods -> CHUNKING -> BDAT -> reply "non-250" -> DATA -> finish mail transaction
#
# As it's simply not supported, BDAT won't be used for chunking.
#
#------------------ANALYSIS---------------------------
# Near as I can tell, this is a way of representing the email stream. Setting this should simply force
# use of the DATA method instead of BDAT being available for "chunking" (Multiple recipients).
#
# What is BDAT? Well: 
#
# "An ESMTP command that replaces the DATA command. So that the SMTP host does not have to continuously scan for the 
# end of the data, this command sends a BDAT command with an argument that contains the total number of bytes in a message. 
# The receiving server counts the bytes in the message and, when the message size equals the value sent by the BDAT command, 
# the server assumes it has received all of the message data."
#
#--------------------CONCLUSION------------------------
# Ideally, yeah test the hell out of this.
# For now, I'd anticipate little to no impact in applying this to hosts.
#
# =========Begin:
# To start, what Exim version are we running, and if the right version, are we vulnerable?
# Checks to ensure config is persistent after restart.
#-----------Set Variables:
isvuln=$(exim -bP |grep chunking_advertise_hosts) # Here, we'd expect to see this on a cPanel setup: chunking_advertise_hosts = 198.51.100.1
fix=$"chunking_advertise_hosts ="
eximver=$(rpm -qa |grep exim |cut -d'-' -f2) #Versions 4.88 and newer are vulnerable for the moment - no CVE given yet.
#-----------Functions:
#
function chk_fix(){
    echo "Double-checking config was applied successfully..."
    if [ "$isvuln" != "$fix" ]
    then
        echo "Unfortunately, something went wrong. Check and apply the config manually."
    elif [ "$isvuln" = "$fix" ]
    then
        echo "Successfully applied config."
    fi
}
# Uses sed to apply the config.
function apply_conf(){
    sed -i 's/chunking_advertise_hosts.*/chunking_advertise_hosts =/g' /etc/exim.conf
    sed -i 's/chunking_advertise_hosts.*/chunking_advertise_hosts =/g' /usr/local/cpanel/etc/exim/config_options
}
#----------------
echo "Checking for Exim BDAT remote code execution vulnerability, and assuming cPanel host..." # Need to function and segment if this is big so that all Exim-based servers can be patched.
if [ "$eximver" = '4.88' ] && [ "$isvuln" != "$fix" ]
then
    echo "Exim version 4.88 and *IS* vulnerable, applying changes to /etc/exim.conf and /usr/local/cpanel/etc/exim/config_options ..."
    apply_conf
    echo "Config files changed, restarting Exim..."
    service exim reload
    /scripts/restartsrv_exim
    chk_fix
elif [ "$eximver" = '4.89' ] && [ "$isvuln" != "$fix" ]
then
    echo "Exim version 4.89 and *IS* vulnerable, applying changes to /etc/exim.conf and /usr/local/cpanel/etc/exim/config_options ..."
    apply_conf
    echo "Config applied, restarting Exim..."
    service exim reload
    /scripts/restartsrv_exim
    chk_fix
elif [ "$isvuln" = "$fix" ]
then
    echo "Looks like this has already been mitigated, exiting."
    exit
else
    echo "Exim version detected as" $eximver ", and chunking value is" $isvuln " unsure if this version is vulnerable, so no changes made. Check https://lists.gt.net/exim/announce/108962 for more information."
    exit
fi
echo "Exim remote code execution vulnerability mitigated. Exiting now."
exit
