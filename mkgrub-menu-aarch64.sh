#!/bin/bash
#This script is used for creating a new grub menu item when update kernel.
#It uses the new version-number as the id and display.

NEW_KERN_VERSION=$1
GRUB_CFG=$2
OP_TYPE=$3

#########################################################
#   Description:    SetupOS_Initrd_for_softraid
#   Input           none
#   Return:         0: SUCCESS
#                   1: Internal Error.
#########################################################
function SoftRaid_Initrd()
{
        SI_INITRD=initramfs-${NEW_KERN_VERSION}.img
        mkdir -p /initramfs/usr/lib/systemd/system
        mkdir -p /initramfs/etc/systemd/system/default.target.wants
        mdadm --detail --scan >>  /initramfs/etc/mdadm.conf

        cd /initramfs
        cat <<EOF > /initramfs/usr/lib/systemd/assemble-md
#!/bin/bash
declare -i count=5
if [ -f /etc/mdadm.conf ];then
      while (( count > 0 )) ;
        do
        sleep 10s
        let count--;
        if [ -e "/dev/sda1" ];then
         mdadm -A -s
         break;
        fi
        echo " waiting harddisk get online .... countdown  ${count} "
      done
fi
EOF
        if [ $? -ne 0 ];then
                g_Log_Error "generate assemble-md failed"
                return 1
        fi
        chmod -R 755 /initramfs/usr/lib/systemd/assemble-md
        cat << EOF > /initramfs/usr/lib/systemd/system/assemble-md.service
[Unit]
Description=assemble the md
DefaultDependencies=no
After=local-fs-pre.target systemd-udev-trigger.service systemd-udevd.service systemd-udevd-control.socket systemd-udevd-kernel.socket
Before=local-fs.target diskconf-reload.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/lib/systemd/assemble-md
StandardOutput=journal+console

[Install]
WantedBy=default.target
EOF
        if [ $? -ne 0 ];then
                g_Log_Error "generate assemble-md.service failed"
                return 1
        fi

        cp /initramfs/usr/lib/systemd/system/assemble-md.service   /initramfs/etc/systemd/system/default.target.wants/
        dracut --force --include /initramfs  /  /boot/${SI_INITRD}  ${NEW_KERN_VERSION}
        rm -r /initramfs
        cd -
}

if [ "x${NEW_KERN_VERSION}" == "x" ] || [ "x${GRUB_CFG}" == "x" ] || [ "x${OP_TYPE}" == "x" ] ; then
       echo "There some mkgrub-menu  parameter is null,please check "
       exit 1;
fi

if [ "update" = "${OP_TYPE}" ]; then

DEF_VER=`grep -nr "default="  $GRUB_CFG|awk -F = '{print $2}'` ;
START_LN=`grep -nr  " --id ${DEF_VER}"  $GRUB_CFG|awk -F: '{print $1}'` ;
/bin/sed -rn "p;${START_LN},/}/H;$ {g;s/^\n//;p}"   $GRUB_CFG > tempfile ;
/bin/sed -i "$[START_LN+5],/ --id ${DEF_VER}/{s/ --id ${DEF_VER}/ --id linux-${NEW_KERN_VERSION}/}"  tempfile ;
OLDLABLE=`sed -n  "$[START_LN+5],/ --id ${DEF_VER}/p"  tempfile |grep menuentry |tail -1 |awk '{print $2}' |sed "s/\"//g"  `
/bin/sed -i "$[START_LN+5],/ --id ${DEF_VER}/{s/${OLDLABLE}/EulerOS-${NEW_KERN_VERSION}/}"  tempfile ;
/bin/sed -i "/ --id linux-${NEW_KERN_VERSION}/,/}/{s/`uname -r`/${NEW_KERN_VERSION}/} "  tempfile ;
/bin/sed -i "s/default=${DEF_VER}/default=linux-${NEW_KERN_VERSION}/"  tempfile ;
mv tempfile $GRUB_CFG

if [ `cat /proc/mdstat |wc -l `  -gt  2 ]; then
  SoftRaid_Initrd > /dev/null 2>&1
fi

fi

if [ "remove" =  "${OP_TYPE}" ]; then
 /bin/sed -i "/ --id linux-${NEW_KERN_VERSION}/,/}/d"  $GRUB_CFG
 DEF_VER=`grep -nr "menuentry" $GRUB_CFG |head -1 |awk '{print $4}' |sed "s/{//g" `
 /bin/sed -i "s/default=linux-${NEW_KERN_VERSION}/default=${DEF_VER}/"  $GRUB_CFG
fi
