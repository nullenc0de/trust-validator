#!/usr/bin/env python3

import sys
import argparse
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS, sendKerberosTGSRequest
from impacket.krb5 import constants
from impacket.krb5.types import Principal
from impacket.krb5.crypto import _enctype_table, Key, _HMACMD5
from datetime import datetime
import struct

class SafeTicketValidator:
    def __init__(self, domain, username, password, dc_ip, trust_domain):
        self.domain = domain
        self.username = username
        self.password = password
        self.dc_ip = dc_ip
        self.trust_domain = trust_domain

    def validate_ticket_forgability(self):
        """
        Safely validates if ticket forgery is possible without actual forgery
        """
        print("[*] Validating trust ticket vulnerability...")
        try:
            # Step 1: Get legitimate TGT first
            print("[*] Getting initial TGT to analyze trust configuration...")
            client = Principal(self.username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            tgt, cipher, _, session_key = getKerberosTGT(client, self.password, self.domain, None, None, None, self.dc_ip)

            # Step 2: Request legitimate trust ticket (no forgery)
            print(f"[*] Requesting trust ticket for analysis from {self.trust_domain}...")
            server_name = Principal(f'krbtgt/{self.trust_domain}', type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            
            try:
                # Get legitimate TGS for analysis
                tgs, cipher, _ = getKerberosTGS(server_name, self.domain, self.dc_ip, tgt, cipher, session_key)
                
                # Step 3: Analyze ticket properties
                print("[*] Analyzing trust ticket properties...")
                
                # Extract critical fields for vulnerability check
                enc_type = struct.unpack(">I", tgs[18:22])[0]
                flags = struct.unpack("<I", tgs[26:30])[0]
                
                vulnerabilities = []
                
                # Check for specific vulnerability conditions
                if enc_type == 23:  # RC4_HMAC
                    vulnerabilities.append("- Trust using RC4 encryption (vulnerable to forgery)")
                
                if flags & 0x40000:  # Forwardable flag
                    vulnerabilities.append("- Trust tickets are forwardable")
                    
                # Validate ticket lifetime
                auth_time = struct.unpack(">I", tgs[30:34])[0]
                end_time = struct.unpack(">I", tgs[34:38])[0]
                lifetime = end_time - auth_time
                
                if lifetime > 36000:  # Over 10 hours
                    vulnerabilities.append(f"- Long ticket lifetime: {lifetime/3600:.1f} hours")

                # Send a benign TGS request to verify server response
                print("[*] Validating server response to ticket requests...")
                response = sendKerberosTGSRequest(
                    tgs, 
                    self.dc_ip,
                    timeout=1  # Short timeout for safety
                )
                
                if response and len(vulnerabilities) > 0:
                    print("[+] Trust configuration is vulnerable to ticket attacks!")
                    print("\nVulnerable configuration details:")
                    for vuln in vulnerabilities:
                        print(vuln)
                    
                    print("\nImpact Analysis:")
                    print("- Trust ticket forgery is possible")
                    print("- Unauthorized cross-domain access could be achieved")
                    print("- Silent persistence might be established")
                    
                    return True, "\n".join(vulnerabilities)
                else:
                    return False, "Trust ticket configuration appears secure"

            except Exception as e:
                if "KDC_ERR_S_PRINCIPAL_UNKNOWN" in str(e):
                    print("[!] Trust validation failed - trust may be inactive")
                    return False, f"Trust appears inactive: {str(e)}"
                return False, str(e)

        except Exception as e:
            return False, f"Test failed: {str(e)}"

def main():
    parser = argparse.ArgumentParser(description="Safe Trust Ticket Vulnerability Validator")
    parser.add_argument("-d", "--domain", required=True, help="Domain name")
    parser.add_argument("-u", "--username", required=True, help="Username")
    parser.add_argument("-p", "--password", required=True, help="Password")
    parser.add_argument("--dc-ip", required=True, help="Domain Controller IP")
    parser.add_argument("-t", "--trust-domain", required=True, help="Trusted domain")

    args = parser.parse_args()

    print("\n=== Trust Ticket Vulnerability Validator ===")
    validator = SafeTicketValidator(args.domain, args.username, args.password, 
                                  args.dc_ip, args.trust_domain)
    
    is_vulnerable, evidence = validator.validate_ticket_forgability()
    
    print("\n=== Results ===")
    print(f"Trust Vulnerable to Ticket Attacks: {'Yes' if is_vulnerable else 'No'}")
    print(f"Evidence: {evidence}")

if __name__ == "__main__":
    main()
