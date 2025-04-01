import sys
import os
import json
from datetime import datetime
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS, sendReceive
from impacket.krb5 import constants
from impacket.krb5.types import Principal
from impacket.krb5.ccache import CCache
import struct
from nxc.paths import NXC_PATH

class NXCModule:
    """
    Safely validate AD trust tickets for vulnerabilities and simulate domain admin access with auto-detection
    Module by: Claude & Original by @shad0wcntr0ller, enhanced by Grok
    """
    name = 'trust-validator'
    description = 'Check Active Directory trust tickets for vulnerabilities and simulate domain admin access with automatic trust and SPN detection'
    supported_protocols = ['ldap']
    opsec_safe = True
    multiple_hosts = False

    def options(self, context, module_options):
        '''
        TRUST_DOMAIN    Target trusted domain to validate (optional; auto-detected if not provided)
        TARGET_SPN      Service Principal Name in the trusted domain to target (optional; defaults to ldap/<trust_domain>)
        SAVE_TICKET     Save tickets for further analysis (default: True)
        '''
        self.trust_domain = module_options.get('TRUST_DOMAIN') if module_options else None
        self.target_spn = module_options.get('TARGET_SPN') if module_options else None
        self.save_ticket = True
        if module_options and 'SAVE_TICKET' in module_options:
            self.save_ticket = module_options['SAVE_TICKET'].lower() == 'true'

    def _detect_trust_domain(self, context, connection):
        """Detect an outbound trusted domain via LDAP query."""
        try:
            ldap_conn = connection.conn
            search_base = f"CN=System,DC={connection.domain.replace('.', ',DC=')}"
            search_filter = "(objectClass=trustedDomain)"
            attributes = ["trustPartner", "trustDirection"]
            ldap_conn.search(search_base, search_filter, attributes=attributes)
            for entry in ldap_conn.entries:
                trust_partner = entry.entry_attributes_as_dict.get('trustPartner', [None])[0]
                trust_direction = entry.entry_attributes_as_dict.get('trustDirection', [0])[0]
                # trustDirection: 2 = Outbound, 1 = Inbound, 3 = Bidirectional
                if trust_direction in [2, 3] and trust_partner:
                    context.log.info(f"Detected outbound trust: {trust_partner}")
                    return trust_partner
            context.log.warning("No outbound trusts found; TRUST_DOMAIN must be specified manually.")
            return None
        except Exception as e:
            context.log.fail(f"Failed to detect trust domain: {e}")
            return None

    def _validate_tgs_response(self, tgs, domain, dc_ip):
        """Helper function to safely validate TGS response using sendReceive."""
        try:
            messageLen = struct.pack('!i', len(tgs))
            response = sendReceive(messageLen + tgs, domain, dc_ip)
            return response is not None
        except Exception:
            return False

    def on_login(self, context, connection):
        try:
            # Auto-detect trust domain if not provided
            if not self.trust_domain:
                self.trust_domain = self._detect_trust_domain(context, connection)
                if not self.trust_domain:
                    context.log.error("Could not auto-detect TRUST_DOMAIN and none provided!")
                    return False

            # Auto-set TARGET_SPN if not provided (default to LDAP service)
            if not self.target_spn:
                self.target_spn = f"ldap/{self.trust_domain}"
                context.log.info(f"Auto-set TARGET_SPN to: {self.target_spn}")

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
                "ticket_details": {},
                "exploitation": {}
            }

            try:
                # Get trust ticket using getKerberosTGS
                tgs, cipher, _, _ = getKerberosTGS(
                    server_name,
                    connection.domain,
                    connection.host,
                    tgt,
                    cipher,
                    session_key
                )

                # Validate TGS response
                if not self._validate_tgs_response(tgs, connection.domain, connection.host):
                    context.log.warning("Warning: Unexpected TGS response validation")

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

                # Check vulnerabilities
                if enc_type == 23:  # RC4_HMAC
                    vuln = "Trust using RC4 encryption (vulnerable to forgery)"
                    evidence["vulnerabilities"].append(vuln)
                    context.log.highlight(f"[Vulnerability] {vuln}")
                if flags & 0x40000:  # Forwardable flag
                    vuln = "Trust tickets are forwardable"
                    evidence["vulnerabilities"].append(vuln)
                    context.log.highlight(f"[Vulnerability] {vuln}")
                if lifetime > 36000:  # Over 10 hours
                    vuln = f"Extended ticket lifetime: {lifetime/3600:.1f} hours"
                    evidence["vulnerabilities"].append(vuln)
                    context.log.highlight(f"[Vulnerability] {vuln}")

                # Simulate exploitation with TARGET_SPN
                context.log.info(f"Simulating exploitation by targeting {self.target_spn}...")
                service_name = Principal(self.target_spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
                try:
                    service_tgs, _, _, _ = getKerberosTGS(
                        service_name,
                        self.trust_domain,
                        connection.host,
                        tgs,
                        cipher,
                        session_key
                    )
                    context.log.success(f"Successfully obtained service ticket for {self.target_spn}")

                    # Save service TGS
                    if self.save_ticket:
                        service_tgs_path = os.path.join(output_dir, "service.tgs")
                        with open(service_tgs_path, 'wb') as f:
                            f.write(service_tgs)
                        context.log.success(f"Saved service TGS to {service_tgs_path}")

                    # Determine potential impact
                    service_type = self.target_spn.split('/')[0].lower()
                    impacts = {
                        'ldap': "Could perform LDAP queries/modifications, potentially escalating to domain admin if permissions allow.",
                        'cifs': "Could access file shares on the DC, potentially extracting sensitive data or executing code.",
                        'http': "Could access web services on the DC, potentially exploiting vulnerabilities for further access."
                    }
                    impact = impacts.get(service_type, "Could access the specified service, potentially leading to further exploitation.")
                    context.log.highlight(f"[Impact] With this ticket: {impact}")

                    evidence["exploitation"] = {
                        "target_spn": self.target_spn,
                        "status": "Success",
                        "impact": impact,
                        "service_tgs_path": service_tgs_path if self.save_ticket else None
                    }
                except Exception as e:
                    context.log.fail(f"Failed to obtain service ticket for {self.target_spn}: {e}")
                    evidence["exploitation"] = {
                        "target_spn": self.target_spn,
                        "status": "Failed",
                        "error": str(e)
                    }

                # Save evidence
                evidence_path = os.path.join(output_dir, "evidence.json")
                with open(evidence_path, 'w') as f:
                    json.dump(evidence, f, indent=2)
                context.log.success(f"Saved evidence to {evidence_path}")

                if len(evidence["vulnerabilities"]) > 0:
                    context.log.success("\nPotential Impact of Trust Vulnerabilities:")
                    context.log.highlight("- Trust ticket forgery may be possible")
                    context.log.highlight("- Unauthorized cross-domain access risk")
                    context.log.highlight("- Potential for persistence")
                    if "exploitation" in evidence and evidence["exploitation"].get("status") == "Success":
                        context.log.success("\nExploitation Simulation:")
                        context.log.highlight(f"- Successfully obtained service ticket for {self.target_spn}")
                        context.log.highlight(f"- Potential escalation: {evidence['exploitation']['impact']}")
                    if self.save_ticket:
                        context.log.success(f"\nEvidence and tickets saved to: {output_dir}")
                        context.log.info("Use these files to validate findings:")
                        context.log.info(f"- TGT ccache: {tgt_path}")
                        context.log.info(f"- Trust TGS: {tgs_path}")
                        if "exploitation" in evidence and evidence["exploitation"].get("status") == "Success":
                            context.log.info(f"- Service TGS: {service_tgs_path}")
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
