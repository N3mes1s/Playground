"""
benign_corpus.py -- a larger, realistic benign endpoint-telemetry corpus.

Calibration needs a real negative class that spans the whole probability range,
not just obviously-harmless commands. The interesting negatives are *dual-use*:
legitimate admin / IT / developer / CI activity that resembles attacker
behaviour (certutil hashing, PsExec by a sysadmin, base64 in a build script,
netstat, nltest, reg query, vssadmin list, curl|bash of a real installer,
SUID audits by the security team...). Those populate the mid/high bins with
genuine negatives, which is what makes "does p=0.7 mean 70% malicious?"
answerable.

Everything here is real administrative work. Nothing performs an attack.
Each entry is a Sysmon-EID-1-shaped process-creation event, same schema as
datasets.py, labelled benign with tactic None.
"""

from __future__ import annotations

from typing import Any, Dict, List

PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
CMD = r"C:\Windows\System32\cmd.exe"
EXPLORER = r"C:\Windows\explorer.exe"
SVC = r"C:\Windows\System32\services.exe"
CRON = "/usr/sbin/cron"
SSHD = "/usr/sbin/sshd"
BASH = "/bin/bash"


def _e(image, cmd, parent, user, integrity, note, channel="Sysmon"):
    return {"label": "benign", "technique_id": "NONE", "tactic": "None", "source": "benign-corpus",
            "test_name": note,
            "event": {"EventID": 1, "Channel": channel, "Image": image, "CommandLine": cmd,
                      "ParentImage": parent, "User": user, "IntegrityLevel": integrity}}


# (image, command, parent, user, integrity, note) -- Windows
_WIN = [
    (PS, "Get-Service | Where-Object Status -eq 'Running' | Select Name", EXPLORER, "CORP\\ops", "Medium", "listing running services"),
    (PS, "Get-Process | Sort-Object WS -Descending | Select -First 15", EXPLORER, "CORP\\ops", "Medium", "memory triage"),
    (PS, "Get-EventLog -LogName System -Newest 50 | Where EntryType -eq 'Error'", EXPLORER, "CORP\\ops", "High", "reviewing system errors"),
    (PS, "Get-ChildItem C:\\inetpub\\logs -Recurse | Measure-Object Length -Sum", EXPLORER, "CORP\\web", "High", "measuring IIS log size"),
    (PS, "certutil -hashfile C:\\downloads\\sdk.exe SHA256", CMD, "CORP\\dev", "Medium", "verifying a download hash"),
    (PS, "certutil -urlcache -split -f https://packages.corp.local/agent.msi C:\\temp\\agent.msi", CMD, "CORP\\sccm", "High", "internal package fetch by SCCM admin"),
    (CMD, "net user /domain", EXPLORER, "CORP\\helpdesk", "Medium", "helpdesk listing domain users"),
    (CMD, "net group \"Domain Admins\" /domain", EXPLORER, "CORP\\secops", "High", "quarterly DA membership review"),
    (CMD, "nltest /dclist:corp.local", EXPLORER, "CORP\\ops", "Medium", "listing domain controllers"),
    (CMD, "nltest /domain_trusts", EXPLORER, "CORP\\ops", "Medium", "auditing domain trusts"),
    (CMD, "netstat -anob | findstr ESTABLISHED", CMD, "CORP\\ops", "High", "checking established connections"),
    (CMD, "ipconfig /flushdns && ipconfig /all", EXPLORER, "CORP\\helpdesk", "Medium", "network troubleshooting"),
    (CMD, "arp -a", EXPLORER, "CORP\\helpdesk", "Medium", "checking ARP cache"),
    (CMD, "route print", EXPLORER, "CORP\\ops", "Medium", "reviewing routing table"),
    (CMD, "systeminfo", EXPLORER, "CORP\\helpdesk", "Medium", "gathering system info for a ticket"),
    (CMD, "tasklist /svc", EXPLORER, "CORP\\ops", "Medium", "mapping services to processes"),
    (CMD, "wmic product get name,version", EXPLORER, "CORP\\sccm", "High", "software inventory"),
    (PS, "Get-WmiObject Win32_QuickFixEngineering | Select HotFixID", r"C:\Windows\CCM\CcmExec.exe", "NT AUTHORITY\\SYSTEM", "System", "SCCM patch inventory"),
    (CMD, r'reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v ProductName', EXPLORER, "CORP\\ops", "Medium", "reading OS version from registry"),
    (CMD, r'reg query "HKLM\SYSTEM\CurrentControlSet\Services" /s /f Start', EXPLORER, "CORP\\ops", "High", "auditing service start types"),
    (CMD, "vssadmin list shadows", EXPLORER, "CORP\\backup", "High", "checking shadow copies before backup"),
    (CMD, "wbadmin get versions", EXPLORER, "CORP\\backup", "High", "listing backup versions"),
    (CMD, r'schtasks /create /tn "NightlyBackup" /tr "C:\scripts\backup.ps1" /sc daily /st 02:00 /ru SYSTEM', EXPLORER, "CORP\\backup", "High", "scheduling a backup job"),
    (CMD, "schtasks /query /fo LIST /v", EXPLORER, "CORP\\ops", "Medium", "auditing scheduled tasks"),
    (PS, "New-Service -Name CorpMonitor -BinaryPathName 'C:\\Program Files\\Mon\\agent.exe' -StartupType Automatic", SVC, "NT AUTHORITY\\SYSTEM", "System", "installing a monitoring agent"),
    (PS, "sc.exe query type= service state= all", CMD, "CORP\\ops", "Medium", "enumerating services"),
    (CMD, r"PsExec.exe \\WS-4021 -s cmd /c ipconfig /all", EXPLORER, "CORP\\helpdesk", "High", "remote troubleshooting with PsExec"),
    (CMD, r"PsExec.exe \\SQL-02 -u CORP\dba -p - powershell -c Get-Service MSSQL*", EXPLORER, "CORP\\dba", "High", "checking SQL service remotely"),
    (PS, "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((Get-Content .\\config.json -Raw)))", EXPLORER, "CORP\\dev", "Medium", "base64-encoding a config in a build"),
    (PS, "Invoke-WebRequest https://get.helm.sh/helm-v3.14.0-windows-amd64.zip -OutFile helm.zip", EXPLORER, "CORP\\dev", "Medium", "downloading a real tool"),
    (PS, "Invoke-WebRequest -Uri https://api.corp.local/health -UseBasicParsing", EXPLORER, "CORP\\ops", "Medium", "health check"),
    (PS, "Compress-Archive -Path C:\\logs\\* -DestinationPath \\\\fileserver\\share\\logs_$(Get-Date -f yyyyMMdd).zip", EXPLORER, "CORP\\ops", "High", "archiving logs to a share"),
    (PS, "Get-ADUser -Filter * -Properties LastLogonDate | Export-Csv C:\\reports\\users.csv -NoTypeInformation", EXPLORER, "CORP\\hr-it", "High", "HR access review export"),
    (PS, "Get-ADComputer -Filter * | Select Name,OperatingSystem", EXPLORER, "CORP\\ops", "High", "inventory of computers"),
    (PS, "dsquery user -limit 0 | dsget user -samid -disabled", CMD, "CORP\\iam", "High", "auditing disabled accounts"),
    (CMD, "gpresult /r /scope computer", EXPLORER, "CORP\\ops", "Medium", "checking applied group policy"),
    (CMD, "whoami /all", EXPLORER, "CORP\\helpdesk", "Medium", "checking own token for a ticket"),
    (CMD, "klist", EXPLORER, "CORP\\helpdesk", "Medium", "listing kerberos tickets"),
    (CMD, "chcp 65001", EXPLORER, "CORP\\dev", "Medium", "setting UTF-8 code page in a terminal"),
    (CMD, "fsutil volume diskfree C:", EXPLORER, "CORP\\ops", "Medium", "checking free disk"),
    (PS, "Test-NetConnection api.corp.local -Port 443", EXPLORER, "CORP\\ops", "Medium", "port connectivity test"),
]

# (image, command, parent, user, integrity, note) -- Linux
_LIN = [
    (BASH, "systemctl status nginx --no-pager", SSHD, "ops", "High", "checking a service"),
    (BASH, "journalctl -u api.service --since '1 hour ago' | tail -100", SSHD, "ops", "High", "reviewing service logs"),
    (BASH, "df -h && du -sh /var/log/*", SSHD, "ops", "High", "disk usage triage"),
    (BASH, "ss -tulpn", SSHD, "ops", "High", "listing listening sockets"),
    (BASH, "netstat -tnp | grep ESTABLISHED", SSHD, "ops", "High", "checking connections"),
    (BASH, "ps auxf | sort -nrk 3 | head", SSHD, "ops", "High", "cpu triage"),
    (BASH, "curl -fsSL https://get.docker.com | sh", SSHD, "root", "High", "installing docker on a fresh host"),
    (BASH, "curl -sS https://packages.corp.local/install.sh | bash", SSHD, "deploy", "High", "internal provisioning script"),
    (BASH, "find / -perm -4000 -type f 2>/dev/null", BASH, "secops", "High", "authorized SUID audit"),
    (BASH, "find /home -name '*.pem' -o -name 'id_rsa' 2>/dev/null", BASH, "secops", "High", "key-hygiene audit by security"),
    (BASH, "tar czf /backup/etc-$(date +%F).tgz /etc", CRON, "root", "High", "nightly /etc backup"),
    (BASH, "rsync -az /var/www/ backup@10.0.3.9:/backups/www/", CRON, "backup", "High", "scheduled offsite backup"),
    (BASH, "ssh -i ~/.ssh/deploy_key deploy@10.0.3.9 'systemctl restart api'", BASH, "deploy", "High", "CI deploy step"),
    (BASH, "openssl enc -aes-256-cbc -salt -in db.sql -out db.sql.enc -pass file:/etc/backup.key", CRON, "dba", "High", "encrypting a backup"),
    (BASH, "openssl s_client -connect api.corp.local:443 -servername api.corp.local </dev/null", BASH, "ops", "High", "checking a TLS cert"),
    (BASH, "base64 -w0 kubeconfig > kubeconfig.b64", BASH, "devops", "High", "encoding kubeconfig for a CI secret"),
    (BASH, "kubectl get pods -A -o wide", BASH, "devops", "High", "listing cluster pods"),
    (BASH, "kubectl logs deploy/api -n prod --tail=200", BASH, "devops", "High", "reading pod logs"),
    (BASH, "docker ps -a && docker stats --no-stream", BASH, "devops", "High", "container triage"),
    (BASH, "crontab -l", BASH, "ops", "High", "reviewing cron jobs"),
    (BASH, "cat /etc/passwd | cut -d: -f1", BASH, "ops", "High", "listing local usernames"),
    (BASH, "last -n 50", BASH, "secops", "High", "reviewing recent logins"),
    (BASH, "iptables -L -n -v", BASH, "ops", "High", "reviewing firewall rules"),
    (BASH, "nmap -sn 10.0.5.0/24", BASH, "netops", "High", "authorized subnet ping sweep by netops"),
    (BASH, "dig axfr @ns1.corp.local corp.local", BASH, "netops", "High", "authorized zone transfer test"),
    (BASH, "git clone https://git.corp.local/app && cd app && npm ci && npm run build", SSHD, "ci", "High", "CI build"),
    (BASH, "psql -h db.prod -U readonly -c 'SELECT count(*) FROM orders'", BASH, "analyst", "High", "read-only query"),
    (BASH, "aws s3 sync s3://corp-backups/db /mnt/restore --profile backup", BASH, "dba", "High", "restoring a backup"),
    (BASH, "chmod 600 ~/.ssh/authorized_keys && ssh-keygen -lf ~/.ssh/authorized_keys", BASH, "ops", "High", "hardening ssh keys"),
    (BASH, "wget -q https://releases.corp.local/tool.tar.gz -O - | tar xz -C /opt", SSHD, "ops", "High", "installing an internal tool"),
]


def generate() -> List[Dict[str, Any]]:
    out = [_e(i, c, p, u, g, n) for (i, c, p, u, g, n) in _WIN]
    out += [_e(i, c, p, u, g, n, channel="auditd") for (i, c, p, u, g, n) in _LIN]
    return out


if __name__ == "__main__":
    ev = generate()
    print(f"{len(ev)} benign events ({len(_WIN)} windows, {len(_LIN)} linux)")
