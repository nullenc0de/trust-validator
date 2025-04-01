#!/usr/bin/env python3

import sys
import argparse
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS, sendReceive
from impacket.krb5 import constants
from impacket.krb5.types import Principal
import struct

# Define potential impacts for common services
SERVICE_IMPACTS = {
    'ldap': 'With this ticket, an attacker could perform LDAP queries or modifications, potentially escalating privileges if the user has sufficient rights.',
    'cifs': 'With this ticket, an attacker could access file shares on the domain controller, potentially reading sensitive files or executing code.',
    'http': 'With this ticket, an attacker could access web services on the domain controller, potentially exploiting web vulnerabilities.',
    'krbtgt': 'With a ticket for krbtgt and knowledge of the krbtgt hash, an attacker could create Golden Tickets to impersonate any user. However, this requires additional compromise.'
}

def extract_domain_from_spn(spn):
    """Extract the domain from an SPN (e.g., cifs/dc.trusted.local -> trusted.local)."""
    try:
        _, host = spn.split('/', 1)
        domain_parts = host.split('.')
        if len(domain_parts) > 1:
            return '.'.join(domain_parts[1:])
        return None
    except Exception:
        return None

class SafeTicketValidator:
    def __init__(self, domain, username, password, dc_ip, trust_domain):
        """Initialize the validator with domain credentials and trust details."""
        self.domain = domain
        self.username = username
        self.password = password
        self.dc_ip = dc_ip
        self.trust_domain = trust_domain

    def _send_tgs_request(self, server_name, domain, dc_ip, tgt, cipher, session_key):
        """Send a TGS request and return the response."""
        try:
            tgs, cipher, _, _ = getKerberosTGS(server_name, domain, dc_ip, tgt, cipher, session_key)
            return tgs
        except Exception as e:
            print(f"[!] Error sending TGS request: {str(e)}")
            return None

    def validate_ticket_forgability(self, exploit=False, spn=None):
        """Validate trust ticket vulnerabilities and optionally perform simulated exploitation."""
        print("[*] Validating trust ticket vulnerability...")
        try:
            # Step 1: Obtain a TGT for the source domain
            print("[*] Getting initial TGT to analyze trust configuration...")
            client = Principal(self.username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            tgt, cipher, _, session_key = getKerberosTGT(client, self.password, self.domain, 
                                                         None, None, None, self.dc_ip)

            # Step 2: Request a trust ticket (TGT for the trusted domain)
            print(f"[*] Requesting trust ticket for analysis from {self.trust_domain}...")
            server_name = Principal(f'krbtgt/{self.trust_domain}', 
                                    type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            tgs = self._send_tgs_request(server_name, self.domain, self.dc_ip, tgt, cipher, session_key)
            if tgs is None:
                return False, "Failed to obtain trust ticket for analysis"

            # Step 3: Analyze ticket properties for vulnerabilities
            print("[*] Analyzing trust ticket properties...")
            vulnerabilities = []
            enc_type = struct.unpack(">I", tgs[18:22])[0]
            flags = struct.unpack("<I", tgs[26:30])[0]
            if enc_type == 23:  # RC4_HMAC
                vulnerabilities.append("- Trust using RC4 encryption (vulnerable to forgery)")
            if flags & 0x40000:  # Forwardable flag
                vulnerabilities.append("- Trust tickets are forwardable")
            auth_time = struct.unpack(">I", tgs[30:34])[0]
            end_time = struct.unpack(">I", tgs[34:38])[0]
            lifetime = end_time - auth_time
            if lifetime > 36000:  # Over 10 hours
                vulnerabilities.append(f"- Long ticket lifetime: {lifetime/3600:.1f} hours")

            # Step 4: Validate server response
            print("[*] Validating server response to ticket requests...")
            messageLen = struct.pack('!i', len(tgs))
            response = sendReceive(messageLen + tgs, self.domain, self.dc_ip)

            # Step 5: Report findings and perform exploitation if enabled
            if response and len(vulnerabilities) > 0:
                print("[+] Trust configuration is vulnerable to ticket attacks!")
                print("\nVulnerable configuration details:")
                for vuln in vulnerabilities:
                    print(vuln)
                print("\nImpact Analysis:")
                print("- Trust ticket forgery is possible")
                print("- Unauthorized cross-domain access could be achieved")
                print("- Silent persistence might be established")
                evidence = "\n".join(vulnerabilities)

                # Simulated Exploitation with context-specific impact
                if exploit and spn:
                    print("\n[*] Performing simulated exploitation...")
                    service_type = spn.split('/')[0].lower()
                    impact = SERVICE_IMPACTS.get(service_type, "With this ticket, an attacker could access the specified service, potentially leading to further exploitation.")
                    service_name = Principal(spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
                    try:
                        tgs_service, _, _, _ = getKerberosTGS(service_name, self.trust_domain, self.dc_ip, 
                                                              tgs, cipher, session_key)
                        print(f"[+] Successfully obtained service ticket for {spn}")
                        print(f"[!] {impact}")
                        evidence += f"\n- Successfully obtained service ticket for {spn}\n- Potential impact: {impact}"
                    except Exception as e:
                        print(f"[!] Failed to obtain service ticket: {str(e)}")
                        evidence += f"\n- Failed to obtain service ticket for {spn}: {str(e)}"
                elif exploit:
                    print("[!] SPN not provided; skipping exploitation test")
                return True, evidence
            else:
                return False, "Trust ticket configuration appears secure"

        except Exception as e:
            if "KDC_ERR_S_PRINCIPAL_UNKNOWN" in str(e):
                print("[!] Trust validation failed - trust may be inactive")
                return False, f"Trust appears inactive: {str(e)}"
            return False, f"Validation failed: {str(e)}"

def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(description="Safe Trust Ticket Vulnerability Validator with Exploitation Simulation")
    parser.add_argument("-d", "--domain", required=True, help="Source domain name (e.g., corp.local)")
    parser.add_argument("-u", "--username", required=True, help="Username (e.g., user@corp.local)")
    parser.add_argument("-p", "--password", required=True, help="Password")
    parser.add_argument("--dc-ip", required=True, help="Domain Controller IP address")
    parser.add_argument("-t", "--trust-domain", help="Trusted domain (e.g., trusted.local); auto-detected from SPN if provided")
    parser.add_argument("--spn", help="Service Principal Name in the trusted domain (e.g., ldap/dc.trusted.local)")
    parser.add_argument("--exploit", action="store_true", help="Enable simulated exploitation mode")

    args = parser.parse_args()

    # Auto-detect trust domain from SPN if provided and trust-domain not explicitly set
    if args.spn and not args.trust_domain:
        detected_domain = extract_domain_from_spn(args.spn)
        if detected_domain:
            args.trust_domain = detected_domain
            print(f"[*] Auto-detected trust domain from SPN: {args.trust_domain}")
        else:
            parser.error("Could not detect trust domain from SPN; please specify --trust-domain explicitly.")
    elif not args.trust_domain:
        parser.error("--trust-domain is required unless auto-detectable from --spn.")

    # Safety warning for exploitation mode
    if args.exploit:
        print("[!] WARNING: Exploitation simulation is enabled. Ensure you have authorization to perform this test.")
        print("[!] This should only be done in a controlled test environment.")

    # Initialize and run the validator
    print("\n=== Trust Ticket Vulnerability Validator ===")
    validator = SafeTicketValidator(args.domain, args.username, args.password, args.dc_ip, args.trust_domain)
    is_vulnerable, evidence = validator.validate_ticket_forgability(exploit=args.exploit, spn=args.spn)
    
    # Display results
    print("\n=== Results ===")
    print(f"Trust Vulnerable to Ticket Attacks: {'Yes' if is_vulnerable else 'No'}")
    print(f"Evidence:\n{evidence}")

if __name__ == "__main__":
    main()
