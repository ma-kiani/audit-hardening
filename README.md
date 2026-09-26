# Audit Hardening

This project provides scripts and tools for hardening the security of Windows and Linux systems through audits. The goal is to back up security policies and assess system configurations to ensure compliance with best practices.

## Windows

For Windows, the process varies depending on whether the system is domain-joined or not:

1. **Domain-Joined Systems**: We use a PowerShell script to back up the Group Policy Objects (GPOs) from the domain controller.
2. **Local Systems**: If the system is not domain-joined, we use LGPO (Local Group Policy Object) to back up the local policies.

After gathering the policies, we analyze the results using the **Policy Analyzer** tool to ensure they meet security standards.

- [PowerShell Script for GPO Backup](windows/gpo-script.ps1)
- [Policy Analyzer Guide](windows/policy-analyzer-guide.md)

## Linux

For Linux systems, we use the **Lynis** and **OpenSCAP** tools to perform security audits, identify misconfigurations, and assess compliance with security baselines.

- [Lynis Setup Guide](linux/lynis-setup-guide.md)
- [Lynis Scan Example](linux/lynis-scan-example.md)
- [OpenSCAP CIS audit operations guide (Persian)](linux_audit_hardening_by_openscap/MANUAL_FA.md)
- [Production-safe OpenSCAP audit on Ubuntu 24.04 (Persian)](linux_audit_hardening_by_openscap/OPERATIONAL_AUDIT_UBUNTU24_FA.md)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
