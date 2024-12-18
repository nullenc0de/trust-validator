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
pip install -r requirements.txt
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
