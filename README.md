# Trust Validator Tool

## Overview
This tool validates potential security issues in Active Directory trust relationships, focusing on inactive trusts and encryption configuration vulnerabilities. It performs safe validation without modifying domain objects or attempting exploitation.

## ⚠️ Important Notes
- This is a security testing tool - use only with explicit permission
- Run only in authorized test environments
- Some organizations may classify this as a security testing tool
- Always follow your organization's security testing policies
- Store tool outputs securely

## Features
- Validates inactive trust relationships
- Checks encryption configuration (AES vs RC4)
- Analyzes trust ticket properties
- Identifies potential ticket forgery vulnerabilities
- EDR-friendly validation methods

## Prerequisites
- Python 3.8+
- Network access to Domain Controller
- Domain user credentials
- Required Python packages:
  ```
  impacket>=0.10.0
  ldap3>=2.9
  pyasn1>=0.4.8
  ```

## Installation
```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
.\venv\Scripts\activate   # Windows

# Install requirements
pip install impacket>=0.10.0 ldap3>=2.9 pyasn1>=0.4.8
```

## Usage
Basic syntax:
```bash
python3 trust_validator.py -d <domain> -u <username> -p <password> --dc-ip <dc-ip> -t <trust-domain>
```

Example:
```bash
python3 trust_validator.py -d domain.local -u testuser -p mypassword --dc-ip 10.0.0.1 -t trusted.domain.com
```

## Arguments
```
-d, --domain        Domain name (e.g., domain.local)
-u, --username      Username for authentication
-p, --password      Password for authentication
--dc-ip            Domain Controller IP address
-t, --trust-domain  Trusted domain to validate
```

## Output Examples
Successful validation:
```
=== Trust Ticket Vulnerability Validator ===
[*] Validating trust ticket vulnerability...
[*] Getting initial TGT to analyze trust configuration...
[*] Requesting trust ticket for analysis from trusted.domain.com...
[*] Analyzing trust ticket properties...
[*] Validating server response to ticket requests...
[+] Trust configuration is vulnerable to ticket attacks!

Vulnerable configuration details:
- Trust using RC4 encryption (vulnerable to forgery)
- Trust tickets are forwardable
- Long ticket lifetime: 12.0 hours
```

Failed validation:
```
=== Trust Ticket Vulnerability Validator ===
[*] Validating trust ticket vulnerability...
[!] Trust validation failed - trust may be inactive
Trust appears inactive: KDC_ERR_S_PRINCIPAL_UNKNOWN
```

## NXC
```
# Interactive Console Output:
LDAP        192.168.1.10    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:corp.local) (signing:True) (SMBv1:False)
LDAP        192.168.1.10    445    DC01             [+] corp.local\administrator:Password123! 
LDAP        192.168.1.10    445    DC01             [*] Validating trust ticket configuration for dev.corp.local...
LDAP        192.168.1.10    445    DC01             [+] Saved TGT to /home/user/.nxc/workspaces/trust-validator/corp.local_dev.corp.local_20241218_143022/tgt.ccache
LDAP        192.168.1.10    445    DC01             [*] Analyzing trust ticket configuration...
LDAP        192.168.1.10    445    DC01             [+] Saved trust TGS to /home/user/.nxc/workspaces/trust-validator/corp.local_dev.corp.local_20241218_143022/trust.tgs
LDAP        192.168.1.10    445    DC01             [!] [Vulnerability] Trust using RC4 encryption (vulnerable to forgery)
LDAP        192.168.1.10    445    DC01             [!] [Vulnerability] Trust tickets are forwardable
LDAP        192.168.1.10    445    DC01             [!] [Vulnerability] Extended ticket lifetime: 12.5 hours
LDAP        192.168.1.10    445    DC01             [+] Saved evidence to /home/user/.nxc/workspaces/trust-validator/corp.local_dev.corp.local_20241218_143022/evidence.json

LDAP        192.168.1.10    445    DC01             [+] Potential Impact:
LDAP        192.168.1.10    445    DC01             [!] - Trust ticket forgery may be possible
LDAP        192.168.1.10    445    DC01             [!] - Unauthorized cross-domain access risk
LDAP        192.168.1.10    445    DC01             [!] - Potential for persistence

LDAP        192.168.1.10    445    DC01             [+] Evidence and tickets saved to: /home/user/.nxc/workspaces/trust-validator/corp.local_dev.corp.local_20241218_143022
LDAP        192.168.1.10    445    DC01             [*] Use these files to validate findings:
LDAP        192.168.1.10    445    DC01             [*] - TGT ccache: /home/user/.nxc/workspaces/trust-validator/corp.local_dev.corp.local_20241218_143022/tgt.ccache
LDAP        192.168.1.10    445    DC01             [*] - Trust TGS: /home/user/.nxc/workspaces/trust-validator/corp.local_dev.corp.local_20241218_143022/trust.tgs
LDAP        192.168.1.10    445    DC01             [*] - Evidence JSON: /home/user/.nxc/workspaces/trust-validator/corp.local_dev.corp.local_20241218_143022/evidence.json

# Contents of evidence.json:
{
  "timestamp": "2024-12-18T14:30:22.531642",
  "source_domain": "corp.local",
  "trust_domain": "dev.corp.local",
  "dc_ip": "192.168.1.10",
  "vulnerabilities": [
    "Trust using RC4 encryption (vulnerable to forgery)",
    "Trust tickets are forwardable",
    "Extended ticket lifetime: 12.5 hours"
  ],
  "ticket_details": {
    "encryption_type": 23,
    "ticket_flags": 262144,
    "lifetime_hours": 12.5
  }
}

# Example of commands to use saved tickets:
$ export KRB5CCNAME=/home/user/.nxc/workspaces/trust-validator/corp.local_dev.corp.local_20241218_143022/tgt.ccache
$ klist
Ticket cache: FILE:/home/user/.nxc/workspaces/trust-validator/corp.local_dev.corp.local_20241218_143022/tgt.ccache
Default principal: administrator@CORP.LOCAL

Valid starting       Expires              Service principal
12/18/2024 14:30:22  12/19/2024 00:30:22  krbtgt/CORP.LOCAL@CORP.LOCAL
```

## Security Considerations
The tool implements several safety measures:
- No modification of domain objects
- No actual ticket forging
- Uses only read operations
- Implements timeouts for requests
- Validates configurations without exploitation
- Designed to avoid triggering security alerts

## Troubleshooting
Common issues:
1. Connection failures
   - Verify network connectivity to DC
   - Check firewall rules
   - Ensure DNS resolution works

2. Authentication errors
   - Verify credentials
   - Check account isn't locked/expired
   - Ensure user has necessary permissions

3. Trust validation failures
   - Verify trust domain name
   - Check trust relationship status
   - Ensure DNS can resolve trust domain

## Limitations
- Cannot validate some advanced trust configurations
- May have limited functionality in locked-down environments
- Does not attempt actual trust exploitation
- Some results may require manual verification

## Contributing
- Report bugs via issue tracker
- Follow secure development practices
- Include tests with pull requests
- Document any new features

## License
For authorized security testing only. Check your organization's security policies before use.
