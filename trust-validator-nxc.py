import sys
import os
import json
from datetime import datetime
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS, sendKerberosTGSRequest
from impacket.krb5 import constants
from impacket.krb5.types import Principal
from impacket.krb5.ccache import CCache
import struct
from nxc.paths import NXC_PATH

class NXCModule:
    """
    Safely validate AD trust tickets for potential vulnerabilities and save evidence
    Module by: Claude & Original by @shad0wcntr0ller
    """
    name = 'trust-validator'
    description = 'Check Active Directory trust tickets for potential vulnerabilities and save evidence'
    supported_protocols = ['ldap']
    opsec_safe = True
    multiple_hosts = False

    def options(self, context, module_options):
        '''
        TRUST_DOMAIN    Target trusted domain to validate
        SAVE_TICKET     Save the TGS ticket for further analysis (default: True)
        '''
        if 'TRUST_DOMAIN' in module_options:
            self.trust_domain = module_options['TRUST_DOMAIN']
        else:
            context.log.error('TRUST_DOMAIN option is required!')
            sys.exit(1)
            
        self.save_ticket = True
        if 'SAVE_TICKET' in module_options:
            self.save_ticket = module_options['SAVE_TICKET'].lower() == 'true'

    def on_login(self, context, connection):
        try:
            # Create output directory
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_dir = os.path.join(NXC_PATH, "workspaces", "trust-validator", 
                                    f"{connection.domain}_{self.trust_domain}_{timestamp}")
            os.makedirs(output_dir, exist_ok=True)

            context.log.info(f"Validating trust ticket configuration for {self.trust_domain}...")
            
            # Get initial TGT
            client = Principal(connection.username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            tgt, cipher, oldSessionKey, session_key = getKerberosTGT(
                client,
                connection.password,
                connection.domain,
                None, None, None,
                connection.host
            )

            # Save TGT
            if self.save_ticket:
                tgt_path = os.path.join(output_dir, "tgt.ccache")
                ccache = CCache()
                ccache.fromTGT(tgt, oldSessionKey, oldSessionKey)
                ccache.saveFile(tgt_path)
                context.log.success(f"Saved TGT to {tgt_path}")

            # Request trust ticket for analysis
            server_name = Principal(
                f'krbtgt/{self.trust_domain}',
                type=constants.PrincipalNameType.NT_PRINCIPAL.value
            )
            
            evidence = {
                "timestamp": datetime.now().isoformat(),
                "source_domain": connection.domain,
                "trust_domain": self.trust_domain,
                "dc_ip": connection.host,
                "vulnerabilities": [],
                "ticket_details": {}
            }

            try:
                tgs, cipher, _ = getKerberosTGS(
                    server_name,
                    connection.domain,
                    connection.host,
                    tgt,
                    cipher,
                    session_key
                )
                
                # Save TGS
                if self.save_ticket:
                    tgs_path = os.path.join(output_dir, "trust.tgs")
                    with open(tgs_path, 'wb') as f:
                        f.write(tgs)
                    context.log.success(f"Saved trust TGS to {tgs_path}")
                
                # Analyze ticket properties
                context.log.info("Analyzing trust ticket configuration...")
                
                # Extract and check critical fields
                enc_type = struct.unpack(">I", tgs[18:22])[0]
                flags = struct.unpack("<I", tgs[26:30])[0]
                auth_time = struct.unpack(">I", tgs[30:34])[0]
                end_time = struct.unpack(">I", tgs[34:38])[0]
                lifetime = end_time - auth_time

                evidence["ticket_details"] = {
                    "encryption_type": enc_type,
                    "ticket_flags": flags,
                    "lifetime_hours": lifetime/3600
                }
                
                # Check encryption type
                if enc_type == 23:  # RC4_HMAC
                    vuln = "Trust using RC4 encryption (vulnerable to forgery)"
                    evidence["vulnerabilities"].append(vuln)
                    context.log.highlight(f"[Vulnerability] {vuln}")
                
                # Check ticket flags
                if flags & 0x40000:  # Forwardable flag
                    vuln = "Trust tickets are forwardable"
                    evidence["vulnerabilities"].append(vuln)
                    context.log.highlight(f"[Vulnerability] {vuln}")
                    
                # Check ticket lifetime
                if lifetime > 36000:  # Over 10 hours
                    vuln = f"Extended ticket lifetime: {lifetime/3600:.1f} hours"
                    evidence["vulnerabilities"].append(vuln)
                    context.log.highlight(f"[Vulnerability] {vuln}")

                # Save evidence
                evidence_path = os.path.join(output_dir, "evidence.json")
                with open(evidence_path, 'w') as f:
                    json.dump(evidence, f, indent=2)
                context.log.success(f"Saved evidence to {evidence_path}")

                if len(evidence["vulnerabilities"]) > 0:
                    context.log.success("\nPotential Impact:")
                    context.log.highlight("- Trust ticket forgery may be possible")
                    context.log.highlight("- Unauthorized cross-domain access risk")
                    context.log.highlight("- Potential for persistence")
                    
                    if self.save_ticket:
                        context.log.success(f"\nEvidence and tickets saved to: {output_dir}")
                        context.log.info("Use these files to validate findings:")
                        context.log.info(f"- TGT ccache: {tgt_path}")
                        context.log.info(f"- Trust TGS: {tgs_path}")
                        context.log.info(f"- Evidence JSON: {evidence_path}")
                else:
                    context.log.info("Trust ticket configuration appears secure")

            except Exception as e:
                if "KDC_ERR_S_PRINCIPAL_UNKNOWN" in str(e):
                    context.log.fail(f"Trust validation failed - trust may be inactive: {e}")
                else:
                    context.log.fail(f"Error analyzing trust tickets: {e}")
                return False

            return True

        except Exception as e:
            context.log.fail(f"Module execution failed: {e}")
            return False
