# Trust Validator Tool

## Overview
Trust Validator is a security testing tool that identifies potential vulnerabilities in Active Directory trust relationships. It focuses on validating trust ticket configurations without modifying domain objects or attempting actual exploitation, making it suitable for security assessments in production environments.

## ⚠️ Important Notes
- **Security Testing Tool** - Use only with explicit permission
- **Authorized Environments Only** - Run only in environments where you have authorization
- **Security Classification** - Some organizations may classify this as a security testing tool
- **Follow Security Policies** - Always adhere to your organization's security testing guidelines
- **Secure Storage** - Store tool outputs securely

## Features
- Validates inactive trust relationships
- Identifies vulnerable encryption configurations (AES vs RC4)
- Analyzes trust ticket properties (forwardable flags, lifetime, etc.)
- Detects potential ticket forgery vulnerabilities
- Provides service-specific impact analysis
- EDR-friendly validation methods
- Optional simulation mode for demonstrating potential exploitation paths

## Prerequisites
- Python 3.8+
- Network access to Domain Controller
- Domain user credentials
- Required Python packages:
  ```
  impacket
  ldap3
  pyasn1
  ```

## Installation
```bash
# Install dependencies
# Debian/Ubuntu
sudo apt-get install -y python3 python3-pip python3-dev pipx

# Then install packages:
pipx ensurepath
pipx install git+https://github.com/fortra/impacket.git --force
pipx install git+https://github.com/dirkjanm/ldapdomaindump.git --force 
pipx install git+https://github.com/CravateRouge/bloodyAD --force
```

## Usage
### Basic Syntax
```bash
python3 trust_validator.py -d <domain> -u <username> -p <password> --dc-ip <dc-ip> -t <trust-domain>
```

### Basic Vulnerability Checking
```bash
python3 trust_validator.py -d corp.local -u administrator@corp.local -p P@ssw0rd --dc-ip 192.168.1.10 -t trusted.local
```

### Automated Trust Domain Detection
```bash
python3 trust_validator.py -d corp.local -u administrator@corp.local -p P@ssw0rd --dc-ip 192.168.1.10 --spn ldap/dc.trusted.local
```

### Exploitation Simulation Mode
```bash
python3 trust_validator.py -d corp.local -u administrator@corp.local -p P@ssw0rd --dc-ip 192.168.1.10 -t trusted.local --spn ldap/dc.trusted.local --exploit
```

## Required Arguments
| Argument | Description |
|----------|-------------|
| `-d`, `--domain` | Source domain name (e.g., corp.local) |
| `-u`, `--username` | Username with domain access (e.g., user@corp.local) |
| `-p`, `--password` | Password for the provided username |
| `--dc-ip` | IP address of the domain controller |

## Optional Arguments
| Argument | Description |
|----------|-------------|
| `-t`, `--trust-domain` | Trusted domain name (e.g., trusted.local); can be auto-detected from SPN |
| `--spn` | Service Principal Name in the trusted domain (e.g., ldap/dc.trusted.local) |
| `--exploit` | Enable simulated exploitation mode (for demonstration purposes) |

## Vulnerability Detection
The tool checks for:

1. **RC4 Encryption** - Identifies if trusts are using weak RC4 encryption (vulnerable to forgery)
2. **Forwardable Tickets** - Detects if trust tickets are configured as forwardable
3. **Extended Lifetimes** - Checks for excessive ticket lifetimes that extend the vulnerability window

## Service-Specific Impact Analysis
For each vulnerable service type, the tool provides context-specific impact analysis:

- **LDAP**: Potential for unauthorized directory queries or modifications
- **CIFS**: File share access on domain controllers
- **HTTP**: Potential web service exploitation
- **krbtgt**: Implications for Golden Ticket attacks

## Output Examples
### Successful Vulnerability Validation
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

=== Results ===
Trust Vulnerable to Ticket Attacks: Yes
Evidence:
- Trust using RC4 encryption (vulnerable to forgery)
- Trust tickets are forwardable
- Long ticket lifetime: 12.0 hours
```

### Failed Validation
```
=== Trust Ticket Vulnerability Validator ===
[*] Validating trust ticket vulnerability...
[!] Trust validation failed - trust may be inactive

=== Results ===
Trust Vulnerable to Ticket Attacks: No
Evidence: Trust appears inactive: KDC_ERR_S_PRINCIPAL_UNKNOWN
```

### NXC Integration Output
```
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
```

## Evidence Collection
The tool saves evidence in JSON format:

```json
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
```

## Using Saved Tickets
Example of commands to use saved tickets:
```bash
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

## Implementation Details
- **Safe Validation**: Focuses on identifying vulnerable configurations without exploiting them
- **Ticket Analysis**: Examines Kerberos ticket properties to detect potential weaknesses
- **Trust Validation**: Verifies if trust relationships are active
- **Encryption Detection**: Identifies weak encryption algorithms that could be exploited

## Troubleshooting
Common issues:

1. **Connection failures**
   - Verify network connectivity to DC
   - Check firewall rules
   - Ensure DNS resolution works

2. **Authentication errors**
   - Verify credentials
   - Check account isn't locked/expired
   - Ensure user has necessary permissions

3. **Trust validation failures**
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
