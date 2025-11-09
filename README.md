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

For Linux systems, we use the **Lynis** tool to perform security audits. Lynis helps identify misconfigurations, vulnerabilities, and provides recommendations to improve system security.

- [Lynis Setup Guide](linux/lynis-setup-guide.md)
- [Lynis Scan Example](linux/lynis-scan-example.md)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
