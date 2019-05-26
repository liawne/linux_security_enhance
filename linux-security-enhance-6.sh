#!/bin/bash
# Author: Liawne
# Date: 2017-09-04
# Location: Shenzhen
# Description: Check and configure system security
################################################################
export LANG="en_US.UTF-8"
day=`date +%Y%m%d%H%M`
systemnum=$(cat /etc/redhat-release |grep -o '[0-9]' |head -n 1)
backup_dir="/root/backup${day}"
################################################################


############################设置变量############################

# 备份重要的配置文件
backupfile_set="yes"                         # yes表示设置

# selinux设置
selinux_set="yes"                            # yes表示设置
selinux_mode="disabled"

# 关闭iptables和不必要的服务
services_set="yes"                           # yes表示设置 
srvs=( "iptables" "ip6tables" "kshell" "ntalk" "lpd" "printer" "klogin" "nfslock" "chargen" "bootps" "ypbind" )

# 历史命令时间戳设置
history_set="yes"                            # yes表示设置
HISTSIZE_num="5000"
HISTTIMEFORMAT_set='"`whoami` [%Y-%m-%d %H:%M:%S]  "'

# 禁用ctrl+alt+del组合键
stop_ctrl_alt_del="yes"                      # yes表示设置

# 禁止普通用户重启服务器权限
consolehelper_set="yes"                      # yes表示设置

# 重要文件权限修改
keyfile_set="yes"                            # yes表示设置

# 禁止usb权限 
usb_set="yes"                                # yes表示设置

# 口令设置值
passwd_time_set="yes"                        # yes表示设置
max_day_num="90"                             # 过期时间
min_day_num="1"                              # 最小修改间隔时间
min_len_num="8"                              # 密码最小长度 
warn_age_num="7"                             # 最小警告时间

# 密码复杂度设置
passwd_pam_set="yes"                         # yes表示设置
dcredit_num="dcredit=-1"                     # 至少包含一个数字
lcredit_num="lcredit=-1"                     # 至少包含一个小写字母
ucredit_num="ucredit=-1"                     # 至少包含一个大写字母
ocredit_num="ocredit=-1"                     # 至少包含一个特殊字符
retry_num="retry=3"                          # 密码修改可尝试错误次数为3次
minlen_num="minlen=8"                        # 密码最短长度为8

# 密码重复使用次数限制
passwd_remember_set="yes"                    # yes表示设置
rem_num="5"                                  # 禁止使用最近用过的5个密码

# 账户认证失败次数限制
deny_retry_set="no"                          # yes表示设置
deny_time_num="deny=5"                       # 最多允许输入错误密码次数
unlocktime_num="unlock_time=300"             # 普通用户锁定时间
root_unlock_time_num="root_unlock_time=300"  # root用户锁定时间

# ssh账户登录锁定
ssh_service_set="no"                         # yes表示设置
ssh_deny_num="deny=6"                        # ssh远程连接最多允许输入错误密码次数

# 系统登录安全设置
login_safety_set="no"                        # yes表示设置
LOG_UNKFAIL_ENAB_set="yes"
LOGIN_RETRIES_num="6"
LASTLOG_ENAB_set="yes"

# 命令行界面超时退出设置
timeout_set="yes"                            # yes表示设置
timeout_num="300"                            # 登陆超过300秒不工作，自动退出

# umask设置
umask_set="yes"                              # yes表示设置
umask_num="027"

# ntp服务器地址
ntp_set="no"                                 # yes表示设置

# limits设置
ulimit_set="yes"                             # yes表示设置

# 修改audit配置
audit_set="yes"                              # yes表示设置   

# 修改ssh banner
ssh_banner_set="yes"                         # yes表示设置   

# 修改IP伪装设置
host_conf_set="yes"                          # yes表示设置   

# 修改ftpuser限制用户
ftpuser_set="yes"                            # yes表示设置   

# 别名alias设置
aliases_set="yes"                            # yes表示设置   

# ftp anonymous禁止匿名用户登录
anonymous_set="yes"                          # yes表示设置   

# login.defs UMASK设置
login_umask_set="yes"                        # yes表示设置   
UMASK_num_set="027"                          # 新增用户家目录umask值

# 内核参数设置
kernel_parm_set="yes"                        # yes表示设置

# wheel组设置，用于su root限制
wheel_set="yes"                              # yes表示设置

# functions
dot_line() {
    echo -e "------------------------------------------\n" 
    echo
}


############################脚本更改############################

# 清屏
clear
 
# 时间服务器配置提示
if [ "${ntp_set}x" = "yesx" ]; then
    echo "默认选择配置时间服务器，请确定是否要进行配置"
    echo "[1] 不对时间服务器做改动"
    echo "[2] 我会输入时间服务器的ip地址"
    
    choice=0
    until [ "x${choice}" = "x1" -o "x${choice}" = "x2" -o "x${choice}" = "x" ]
    do
        read -p "Please make your selection [1]: " choice
    done
    
    case "${choice}" in
        ""|1)   ntp_set=""
        ;;  
           2)   read -p "Please enter your IP address :" ntpserverip
        ;;  
    esac
fi

# ulimit配置值变更提醒
# if [ "${ulimit_set}x" = "yesx" ]; then
#     echo "已选择对ulimit配置值进行更改，请先确认系统安装的应用对ulimit值尚未进行配置"
#     echo "[1] 尚未配置，可进行更改"
#     echo "[2] 已做过配置，不对ulimit进行更改"
# 
#     choice1=0
#     until [ "x${choice1}" = "x1" -o "x${choice1}" = "x2" -o "x${choice1}" = "x" ]
#     do
#         read -p "Please make your selection [1]: " choice1
#     done
# 
#     case "${choice1}" in
#         ""|1)   ulimit_set="yes"
#         ;;  
#            2)   ulimit_set=""
#         ;;  
#     esac
# fi

# 使用root用户执行该脚本
if [ $(id -u) -ne '0' ]; then
         echo "Please run as root!"
         exit 1
fi

echo "+---------------------------------------------------------+"
echo "|      注意：本脚本是一个修改脚本，会对服务器做相关设置   |"
echo "+----------------------主机安全修改-----------------------+"
echo " "

# 备份文件
file=(/etc/profile /etc/login.defs /etc/security/limits.conf /etc/pam.d/system-auth /etc.pam.d/password-auth \
        /etc/selinux/config /etc/pam.d/su /etc/rc.d/rc.local /etc/ntp.conf /etc/pam.d/crond /etc/ssh/sshd_config \
        /etc/sysconfig/i18n /etc/sysctl.conf /etc/init.d/kudzu /etc/sudoers /etc/crontab /etc/passwd /etc/shadow \
        /etc/host.conf /etc/vsftpd/ftpuser /etc/aliases /etc/vsftpd/vsftpd.conf /etc/audit/auditd.conf)
if [ "${backupfile_set}x" = "yesx" ]; then
    [ ! -d ${backup_dir} ] && mkdir ${backup_dir}
    for i in ${file[*]}
    do
        cp ${i} ${backup_dir} 1>/dev/null 2>&1 
    done 
    if [ $? -eq 0 ]; then
        echo -e "文件备份完成\n" 
    else 
        echo -e"文件备份未完成"
    fi
    dot_line
fi

# 关闭iptables和不必要的服务
if [ "${services_set}x" = "yesx" ]; then
    for i in ${srvs[*]}; do
        service ${i} stop >/dev/null 2>&1
        chkconfig ${i} off >/dev/null 2>&1
    done 
    echo -e "已关闭iptables和不必要的服务\n"
    dot_line
fi

# 设置selinux
if [ "${selinux_set}x" = "yesx" ]; then
    selinux=$(cat /etc/selinux/config | grep -v '^#' | grep "SELINUX=" | awk -F "=" '{print $2}')
    if [ "${selinux_mode}"x != "${selinux}"x ]; then 
	    sed -i "s/SELINUX=enforcing\|SELINUX=permissive/SELINUX=${selinux_mode}/g" /etc/selinux/config && \
        echo -e "selinux设置完成\n"
    else
        echo -e "selinux设置未更改\n"
    fi
    setenforce 0
    dot_line
fi

# 密码安全策略设置
if [ "${passwd_time_set}x" = "yesx" ]; then
    max_day=$(cat /etc/login.defs | grep -E "PASS_MAX_DAYS" | grep -v "#" |awk -F' ' '{print $2}')
    min_day=$(cat /etc/login.defs | grep -E "PASS_MIN_DAYS" | grep -v "#" |awk -F' ' '{print $2}')
    min_len=$(cat /etc/login.defs | grep -E "PASS_MIN_LEN" | grep -v "#" |awk -F' ' '{print $2}')
    warn_age=$(cat /etc/login.defs | grep -E "PASS_WARN_AGE" | grep -v "#" |awk -F' ' '{print $2}')
    [[ $max_day -ne $max_day_num ]] && sed -i "/PASS_MAX_DAYS/s/$max_day/$max_day_num/g" /etc/login.defs
    [[ $min_day -ne $min_day_num ]] && sed -i "/PASS_MIN_DAYS/s/$min_day/$min_day_num/g" /etc/login.defs
    [[ $min_len -ne $min_len_num ]] && sed -i "/PASS_MIN_LEN/s/$min_len/$min_len_num/g" /etc/login.defs
    [[ $warn_age -ne $warn_age_num ]] && sed -i "/PASS_WARN_AGE/s/$warn_age/$warn_age_num/g" /etc/login.defs
    if [ $? -eq 0 ]; then
        echo -e "已完成密码安全策略设置\n"
        dot_line
    else
    	echo -e "密码安全策略设置未作更改\n"
        dot_line
    fi
fi

# 账户认证失败次数限制
if [ "${deny_retry_set}x" = "yesx" ]; then
    deny=$(cat /etc/pam.d/system-auth | egrep auth | grep pam_tally2.so) 
    if [ ! -n "$deny" ]; then
        sed -i "3a \auth  required  pam_tally2.so  onerr=fail ${deny_time_num} ${unlocktime_num} "\
	 /etc/pam.d/system-auth && \
    	echo -e "已完成帐号认证失败次数限制\n" 
    else
        echo -e "帐号认证失败次数限制设置未作更改\n"
    fi 
    dot_line
fi

# 密码重复使用次数限制
if [ "${passwd_remember_set}x" = "yesx" ]; then
    rem=$(cat /etc/pam.d/system-auth | egrep password | grep pam_unix.so | grep remember | awk '{print $4}' \
        | awk -F "=" '{print $2}')
    if [ ! -n "${rem}" ];then
        sed -i "/^password\s*[a-z]*\s*pam_unix.so/s/pam_unix.so/pam_unix.so remember=$rem_num/g" \
        /etc/pam.d/system-auth && \
    	echo -e "已完成密码重复使用次数限制\n" 
    else
	    echo -e "密码重复使用次数限制设置未作更改\n"
    fi 
    dot_line
fi

# 密码复杂度设置
if [ ${passwd_pam_set}x = "yesx" ]; then
    pass=$(cat /etc/pam.d/system-auth |grep pam_cracklib.so |grep ${retry_num} |grep ${minlen_num} \
        |egrep "(${dcredit_num}|${ucredit_num}|${lcredit_num}|${ocredit_num})")
    dcredit=$(echo ${pass#*dcredit=-} | awk '{print $1}')
    lcredit=$(echo ${pass#*lcredit=-} | awk '{print $1}')
    ucredit=$(echo ${pass#*ucredit=-} | awk '{print $1}')
    ocredit=$(echo ${pass#*ocredit=-} | awk '{print $1}')
    retry=$(echo ${pass#*retry=} | awk '{print $1}')
    minlen=$(echo ${pass#*minlen=} | awk '{print $1}')
    if [ ! -n "$pass" ]; then
        echo "系统没有设置用户密码复杂度，正在对密码复杂度作修改"
        echo "..."
        sed -i "/password\s*requisite\s*pam_cracklib.so/c \password    requisite     pam_cracklib.so try_first_pass \
        $retry_num $minlen_num $lcredit_num $ucredit_num $dcredit_num $ocredit_num" /etc/pam.d/system-auth
        echo "已完成设置"
    else
        echo "密码复杂度已设置"
        [ -n  "$dcredit" ] && echo "至少包含$dcredit 个数字"
        [ -n  "$ucredit" ] && echo "至少包含$ucredit 个大写字母"
        [ -n  "$lcredit" ] && echo "至少包含$lcredit 个小写字母"
        [ -n  "$ocredit" ] && echo "至少包含$ocredit 个特殊字符"
        [ -n  "$retry" ] && echo "密码修改可尝试错误次数为${retry}次"
        [ -n  "$minlen" ] && echo "密码最短长度为${minlen}位"
    fi
    dot_line
fi

# 系统登录安全设置
if [ "${login_safety_set}x" = "yesx" ]; then
    LOG_UNKFAIL_ENAB=$(cat /etc/login.defs | grep -i LOG_UNKFAIL_ENAB | awk '{print $2}')
    LOGIN_RETRIES=$(cat /etc/login.defs | grep -i LOGIN_RETRIES | awk '{print $2}')
    LASTLOG_ENAB=$(cat /etc/login.defs | grep -i LASTLOG_ENAB | awk '{print $2}')
    [ ! -n "$LOG_UNKFAIL_ENAB" ] && echo "LOG_UNKFAIL_ENAB   yes" >> /etc/login.defs
    [[ ${LOG_UNKFAIL_ENAB} != yes ]] && sed -i "/LOG_UNKFAIL_ENAB/c \LOG_UNKFAIL_ENAB  yes" /etc/login.defs
    [ ! -n "$LOGIN_RETRIES" ] && echo "LOGIN_RETRIES  ${LOGIN_RETRIES_num}" >> /etc/login.defs
    [[ ${LOGIN_RETRIES} != ${LOGIN_RETRIES_num} ]] && \
	sed -i "/LOGIN_RETRIES/c \LOGIN_RETRIES ${LOGIN_RETRIES_num}" /etc/login.defs
    [ ! -n "$LASTLOG_ENAB" ] && echo "LASTLOG_ENAB yes" >> /etc/login.defs
    [[ ${LASTLOG_ENAB} != yes ]] && sed -i "/LASTLOG_ENAB/c \LASTLOG_ENAB yes" /etc/login.defs 
    if [ $? -eq 0 ]; then
        echo -e "已完成系统登录安全设置\n"
    else
	    echo -e "系统登录安全设置未作更改\n"
    fi
    dot_line
fi

# 系统登陆超时设置
if [ "${timeout_set}x" = "yesx" ]; then
    TMOUT=$(cat /etc/profile | grep TMOUT |egrep -o '[0-9].*')
    if [ ! -n "$TMOUT" ]; then
        echo "export TMOUT=${timeout_num}" >> /etc/profile && \
    	echo -e "已完成系统登录超时设置\n" 
    else
        echo -e "系统登录超时设置未更改\n"
    fi
    dot_line
fi

# ssh登录锁定策略
if [ "${ssh_service_set}x" = "yesx" ]; then
    ssh_set=$(cat /etc/pam.d/password-auth | grep auth | grep pam_tally2.so)
    if [ ! -n "${ssh_set}" ]; then
        sed -i "3a \auth  required  pam_tally2.so  onerr=fail  ${ssh_deny_num} " /etc/pam.d/password-auth && \
    	echo -e "已完成ssh帐号登录设置\n"
    else
        echo -e "ssh帐号登录设置未配置\n"
    fi
    dot_line
fi

# umask设置
if [ "${umask_set}x" = "yesx" ]; then
    sed -i "/umask 022/s/022/${umask_num}/g" /etc/profile && \
    echo -e "已完成umask设置\n" || echo -e "umask值未更改\n"
    dot_line
fi

# history命令设置
if [ "${history_set}x" = "yesx" ]; then
    HISTSIZE=$(cat /etc/profile | grep "^HISTSIZE=" | awk -F= '{print $2}')
    HISTTIMEFORMAT=$(cat /etc/profile | grep HISTTIMEFORMAT | grep "export" | awk -F "=" '{print $2}')
    if [[ ${HISTSIZE} != ${HISTSIZE_num} ]]; then
        sed -i "/HISTSIZE=/c \HISTSIZE=${HISTSIZE_num}" /etc/profile
    fi
    if [ ! -n "${HISTTIMEFORMAT}" ]; then
        echo "export HISTTIMEFORMAT=${HISTTIMEFORMAT_set}" >> /etc/profile
    else
        [ -n "${HISTTIMEFORMAT}" ] && [ "\"${HISTTIMEFORMAT}\"x" != "${HISTTIMEFORMAT_set}x" ] && \
            sed -i "/export HISTTIMEFORMAT=/c export HISTTIMEFORMAT=${HISTTIMEFORMAT_set}" /etc/profile
    fi 
    echo -e "history命令已设置\n"
    dot_line
fi

# 禁用ctrl+alt+del组合键
case ${systemnum} in
6)
    if [ ${stop_ctrl_alt_del}x = yesx ]; then
        [ -f /etc/init/control-alt-delete.conf ] && mv /etc/init/control-alt-delete.conf{,.bak_$day}
        echo "已禁用ctrl+alt+del"
        dot_line
    fi
;;

5)
    if [ ${stop_ctrl_alt_del}x = yesx ]; then
        ctrl_alt_del=$(cat /etc/inittab |grep -v "^#" |grep ctrlaltdel)
        [ -n "${ctrl_alt_del}" ] && sed -i "/ctrlaltdel/s/ca/#ca/" /etc/inittab
        echo "已禁用ctrl+alt+del"
        dot_line
    fi
;;
esac

# 禁止普通用户重启服务器权限
if [ "${consolehelper_set}x" = "yesx" ]; then
    chmod 744 /usr/bin/consolehelper
    echo -e "已设置禁用用户重启服务器权限\n"
    dot_line
fi

# 重要文件权限修改
if [ "${keyfile_set}x" = "yesx" ]; then
    chmod 400 /etc/crontab
    chmod 400 /etc/securetty
    chmod 644 /etc/hosts.allow
    chmod 644 /etc/hosts.deny
    chmod 600 /etc/inittab
    chmod 644 /etc/login.defs
    chmod 644 /etc/profile
    chmod 644 /etc/bashrc
    echo -e "重要文件权限已设置\n"
    dot_line
fi

# 禁止usb权限
if [ "${usb_set}x" = "yesx" ]; then
    [ ! -f /etc/modprobe.d/usb-storage.conf ] && echo "install usb-storage /bin/ture" >> \
    /etc/modprobe.d/usb-storage.conf && \
    echo -e "已设置禁用usb\n" || echo -e "禁用usb未更改\n"
    dot_line
fi

# 检查重要文件是否存在suid和sgid权限
suidfile=$(find /usr/bin/chage /usr/bin/gpasswd /usr/bin/wall /usr/bin/chfn /usr/bin/chsh /usr/bin/newgrp \
            /usr/bin/write /usr/sbin/usernetctl /usr/sbin/traceroute /bin/mount /bin/umount /bin/ping \
            /sbin/netreport -type f -perm +6000 2>/dev/null)
if [ -n "${suidfile}" ]; then
    echo "the files have suid and sgid:"
    for i in ${suidfile}
    do
        echo ${i}
    done
    dot_line
else
    echo "no suid and sgid"
    dot_line
fi

# 检查系统中是否存在其它id为0的用户
uid0=$(awk -F: '($3 == 0) { print $1 }' /etc/passwd | grep -v root)
if  [ -n "$uid0" ]; then
    echo "user=uid: ${uid0}"
    dot_line
else
    echo "no user's uid=0"
    dot_line
fi

# 检查是否存在空口令账号
emptypasswd=$(awk -F: '($2 == "") { print $1 }' /etc/shadow)
if [ "${emptypasswd}" ]; then
    echo "has emptypassword: ${emptypasswd}"
    dot_line
else
    echo "no emptypassword"
    dot_line
fi

# 检查NTP SERVER
if [ "${ntp_set}x" = "yesx" ]; then
    default_set=$(cat /etc/ntp.conf | grep -v '^#' | egrep "rhel|centos")
    [[ -n ${default_set} ]] && \
    for i in {0..3}; do
        sed -i "s/server ${i}./# server ${i}./g" /etc/ntp.conf
    done
    sed -i "/# server 3./a\server ${ntpserverip} iburst" /etc/ntp.conf
    service ntpd restart &> /dev/null
    chkconfig ntpd on &> /dev/null
    echo -e "时间服务器设置完成\n"
    dot_line
fi

# 系统登录limits设置
if [ "${ulimit_set}x" = "yesx" ]; then 
    sed -i 's/^[^#]/#&/g' /etc/security/limits.conf &> /dev/null
    cat << EOF >> /etc/security/limits.conf
* hard core   0
* soft core   0
EOF
    echo -e "系统limits设置完成\n"
    dot_line
fi

# 修改audit配置
if [ "${audit_set}x" = "yesx" ]; then
    num_logs_set=$(cat /etc/audit/auditd.conf  | grep -v "^#" | grep num_logs | awk '{print $3}')
    max_file_set=$(cat /etc/audit/auditd.conf | grep max_log_file| head -n1 | awk '{print $3}')
    [[ ${num_logs_set} != 4 ]] && sed -i "s/num_logs = .*/num_logs = 4/g" /etc/audit/auditd.conf 
    [[ ${max_file_set} != 50 ]] && sed -i "s/max_log_file = .*/max_log_file = 50/g" /etc/audit/auditd.conf && \
    echo -e "auditd 已经设置\n" || echo -e "auditd 未作配置\n"
    service auditd restart &> /dev/null
    chkconfig auditd on &> /dev/null 
    dot_line
fi

# 修改ssh banner
if [ "${ssh_banner_set}x" = "yesx" ]; then
    [[ -f /etc/ssh_banner ]] && [[ -n $(egrep -v '^$|^#' /etc/ssh/sshd_config | grep 'Banner') ]] && \
        echo -e "ssh banner already set\n" && dot_line
    if ! egrep -v '^$|^#' /etc/ssh/sshd_config | grep -q 'Banner'; then
        echo 'Authorized only. All activity will be monitored and reported' > /etc/ssh_banner && \
        chown bin:bin /etc/ssh_banner && echo 'Banner /etc/ssh_banner' >> /etc/ssh/sshd_config
        service sshd restart
	    echo -e "ssh banner set finished\n"
        dot_line
    fi
fi

# 修改host.conf内容，关闭IP伪装和多IP功能
if [ "${host_conf_set}x" = "yesx" ]; then
    echo 'nospoof on' > /etc/host.conf && \
    echo 'multi off' >> /etc/host.conf && \
    echo -e "IP伪装和多IP功能已经设置\n" && \
    dot_line
fi

# 检查/etc/vsftpd/ftpusers文件中是否加入root用户，若未加入则将root加入
if [ "${ftpuser_set}x" = "yesx" ]; then
    if [ ! -f /etc/vsftpd/ftpusers ]; then
        echo -e "ftpusers文件未找到，请确认vsfptd已安装\n"
        dot_line
    elif [ -f /etc/vsftpd/ftpusers ] && [[ -n $(egrep -v '^$|^#' /etc/vsftpd/ftpusers | grep 'root') ]]; then
        echo -e "已限制root登录ftp，无需配置"
        dot_line
    elif [ -f /etc/vsftpd/ftpusers ] && [[ ! -n $(egrep -v '^$|^#' /etc/vsftpd/ftpusers | grep 'root') ]]; then
        echo root >> /etc/vsftpd/ftpusers && echo -e "限制root登录ftp配置完成\n"
        dot_line
    fi
fi

# 修改/etc/aliases内容，限制部分帐号别名
if [ "${aliases_set}x" = "yesx" ]; then
    for name in games: ingres: system: toor: uucp: manager: dumper: operator: decode: root:; do
        sed -i "s/^${name}/#${name}/g" /etc/aliases 
    done
    /usr/bin/newaliases
    if [ $? -eq 0 ]; then
        echo -e "aliases配置完成\n"
        dot_line
    else
        echo -e "aliases未配置成功\n"
        dot_line
    fi
fi


# 检查/etc/vsftpd/vsftpd.conf中是否配置禁用，若未配置则进行更改
if [ "${anonymous_set}x" = "yesx" ]; then
    if [ ! -f /etc/vsftpd/vsftpd.conf ]; then
        echo -e "vsftpd.conf文件未找到，请确认vsfptd已安装\n"
        dot_line
    elif [ -f /etc/vsftpd/vsftpd.conf ] && [[ -n $(egrep -v '^$|^#' /etc/vsftpd/vsftpd.conf | \
            grep 'anonymous_enable=NO') ]]; then
        echo -e "已限制匿名用户登录ftp，无需配置"
        dot_line
    else
        sed -i 's/^anonymous_enable=/#anonymous_enable=/g' /etc/vsftpd/vsftpd.conf && \
        echo anonymous_enable=NO >> /etc/vsftpd/vsftpd.conf 
        service vsftpd restart && echo -e "限制匿名用户登录ftp配置完成\n"
        dot_line
    fi
fi

# 新建用户家目录访问权限设置
if [ "${login_umask_set}x" = "yesx" ]; then
    UMASK_num=$(cat /etc/login.defs | grep -E "UMASK" | grep -v "#" |awk -F' ' '{print $2}')
    [[ ${UMASK_num} -ne ${UMASK_num_set} ]] && sed -i "/UMASK/s/${UMASK_num}/${UMASK_num_set}/g" /etc/login.defs
    if [ $? -eq 0 ]; then
        echo -e "已完成用户目录缺省访问权限设置\n"
        dot_line
    else
	    echo -e "用户目录缺省访问权限设置未作更改\n"
        dot_line
    fi
fi

# 内核参数更改并立即生效
if [ "${kernel_parm_set}x" = "yesx" ]; then
    accept_source_route=$(cat /proc/sys/net/ipv4/conf/all/accept_source_route)
    accept_redirects=$(cat /proc/sys/net/ipv4/conf/all/accept_redirects)
    send_redirects=$(cat /proc/sys/net/ipv4/conf/all/send_redirects)
    icmp_echo_ignore_broadcasts=$(cat /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts)
    ip_forward=$(cat /proc/sys/net/ipv4/ip_forward)
    [ "${accept_source_route}x" != "0x" ] && sed -i 's/^net.ipv4.conf.all.accept_source_route/#net.ipv4.conf.all.accept_source_route/g' /etc/sysctl.conf && \
        echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
    [ "${accept_redirects}x" != "0x" ] && sed -i 's/^net.ipv4.conf.all.accept_redirects/#net.ipv4.conf.all.accept_redirects/g' /etc/sysctl.conf && \
        echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
    [ "${send_redirects}x" != "0x" ] && sed -i 's/^net.ipv4.conf.all.send_redirects/#net.ipv4.conf.all.send_redirects/g' /etc/sysctl.conf && \
        echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
    [ "${icmp_echo_ignore_broadcasts}x" != "1x" ] && sed -i 's/^net.ipv4.icmp_echo_ignore_broadcasts/#net.ipv4.icmp_echo_ignore_broadcasts/g' /etc/sysctl.conf && \
        echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf
    [ "${ip_forward}x" != "0x" ] && sed -i 's/^net.ipv4.ip_forward/#net.ipv4.ip_forward/g' /etc/sysctl.conf && \
        echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf
    sysctl -p
    if [ $? -eq 0 ]; then
        echo -e "内核参数配置完成\n"
        dot_line
    else
        echo -e "内核参数配置失败\n"
        dot_line
    fi
fi

# 设定允许su为root的组wheel
if [ "${wheel_set}x" = "yesx" ]; then
    ROOTOK_set=$(grep -v "^[[:space:]]*#" /etc/pam.d/su | \
        grep "auth[[:space:]]*sufficient[[:space:]]*pam_rootok.so")
    WHEEL_group=$(grep -v "^[[:space:]]*#" /etc/pam.d/su | \
        grep "auth[[:space:]]*required[[:space:]]*pam_wheel.so[[:space:]]*group=wheel")
    pam_rootok="autu    sufficient    pam.rootok.so"
    pam_wheel_group="auth    required    pam_wheel.so    group=wheel"
    if [[ -n ${ROOTOK_set} && -n ${WHEEL_group} ]]; then
        echo -e "wheel组已设置\n"
        dot_line
    else
        [[ ! -n ${ROOTOK_set} ]] && sed -i "2 i ${pam_rootok}" /etc/pam.d/su
        [[ ! -n ${WHEEL_group} ]] && sed -i "3 i ${pam_wheel_group}" /etc/pam.d/su
        echo -e "wheel group设置完成\n"
        dot_line
    fi
fi
