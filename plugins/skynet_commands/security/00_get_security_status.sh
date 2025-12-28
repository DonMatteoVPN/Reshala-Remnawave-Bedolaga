#!/bin/bash
#
# TITLE: (System) Get Security Status
# SKYNET_HIDDEN: true
#
# Собирает статус ключевых компонентов безопасности и выводит в формате KEY=VALUE.

# SSH
SSH_PORT=$(grep -i "^Port " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
echo "SSH_PORT=${SSH_PORT:-22}"

if grep -qi "^PasswordAuthentication no" /etc/ssh/sshd_config; then
    echo "PASS_AUTH=no"
else
    echo "PASS_AUTH=yes"
fi

# UFW
if command -v ufw &>/dev/null; then
    if ufw status | grep -q "inactive"; then
        echo "UFW_STATUS=inactive"
    else
        echo "UFW_STATUS=active"
    fi
else
    echo "UFW_STATUS=not_installed"
fi

# Fail2Ban
if command -v fail2ban-client &>/dev/null; then
    if systemctl is-active --quiet fail2ban; then
        echo "FAIL2BAN_STATUS=active"
    else
        echo "FAIL2BAN_STATUS=inactive"
    fi
else
    echo "FAIL2BAN_STATUS=not_installed"
fi

# Kernel Hardening
if [[ -f "/etc/sysctl.d/99-reshala-hardening.conf" ]]; then
    if sysctl -n net.ipv4.tcp_syncookies | grep -q "1"; then
        echo "KERNEL_STATUS=applied"
    else
        echo "KERNEL_STATUS=mismatch"
    fi
else
    echo "KERNEL_STATUS=not_applied"
fi
