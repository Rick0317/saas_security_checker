#!/usr/bin/env python3
"""
DNSSEC Enablement Helper Script
Helps users enable DNSSEC for their domains
"""

import argparse
import subprocess
import sys
from typing import Dict, List, Optional

def check_dnssec_status(domain: str) -> Dict:
    """Check current DNSSEC status for a domain"""
    status = {
        'domain': domain,
        'dnssec_enabled': False,
        'ds_record': None,
        'nameservers': [],
        'issues': []
    }
    
    try:
        # Check for RRSIG records (indicates DNSSEC)
        result = subprocess.run(
            ['dig', '+dnssec', '+short', domain],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if 'RRSIG' in result.stdout:
            status['dnssec_enabled'] = True
        
        # Get nameservers
        result = subprocess.run(
            ['dig', '+short', 'NS', domain],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            status['nameservers'] = [ns.strip() for ns in result.stdout.strip().split('\n') if ns.strip()]
        
        # Get DS record
        result = subprocess.run(
            ['dig', '+short', 'DS', domain],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0 and result.stdout.strip():
            status['ds_record'] = result.stdout.strip()
        
    except Exception as e:
        status['issues'].append(f"Error checking DNSSEC status: {str(e)}")
    
    return status

def get_dnssec_instructions(domain: str, dns_provider: str) -> List[str]:
    """Get DNSSEC enablement instructions for specific DNS provider"""
    
    instructions = {
        'cloudflare': [
            f"1. Log into Cloudflare dashboard",
            f"2. Select domain: {domain}",
            f"3. Go to 'DNS' tab",
            f"4. Click 'Settings' tab",
            f"5. Scroll to 'DNSSEC' section",
            f"6. Click 'Enable DNSSEC'",
            f"7. Copy the DS record provided",
            f"8. Add DS record to your domain registrar",
            f"9. Wait 24-48 hours for propagation"
        ],
        
        'route53': [
            f"1. Open Amazon Route 53 console",
            f"2. Create hosted zone for {domain}",
            f"3. Select your hosted zone",
            f"4. Click 'DNSSEC signing' tab",
            f"5. Click 'Enable DNSSEC signing'",
            f"6. Choose KMS key (create new if needed)",
            f"7. Click 'Enable DNSSEC signing'",
            f"8. Copy DS record information",
            f"9. Add to your domain registrar"
        ],
        
        'google': [
            f"1. Open Google Cloud Console",
            f"2. Go to 'Network Services' > 'Cloud DNS'",
            f"3. Create new zone for {domain}",
            f"4. Select your DNS zone",
            f"5. Click 'DNSSEC' tab",
            f"6. Click 'Enable DNSSEC'",
            f"7. Choose key type (RSASHA256 recommended)",
            f"8. Click 'Enable'",
            f"9. Copy DS record from Google Cloud",
            f"10. Add to your domain registrar"
        ],
        
        'azure': [
            f"1. Open Azure Portal",
            f"2. Go to 'DNS zones'",
            f"3. Create new DNS zone for {domain}",
            f"4. Select your DNS zone",
            f"5. Go to 'DNSSEC' in left menu",
            f"6. Click 'Enable DNSSEC'",
            f"7. Choose key type (RSASHA256)",
            f"8. Click 'Enable'",
            f"9. Copy DS record from Azure",
            f"10. Add to your domain registrar"
        ],
        
        'godaddy': [
            f"1. Log into GoDaddy account",
            f"2. Go to 'My Products'",
            f"3. Find domain: {domain}",
            f"4. Click 'DNS' or 'Manage'",
            f"5. Look for 'DNSSEC' section",
            f"6. Click 'Enable DNSSEC'",
            f"7. Follow the setup wizard",
            f"8. Note the DS record generated",
            f"9. Configure nameservers if using external DNS"
        ],
        
        'namecheap': [
            f"1. Log into Namecheap account",
            f"2. Go to 'Domain List'",
            f"3. Click 'Manage' next to {domain}",
            f"4. Go to 'Advanced DNS' tab",
            f"5. Look for 'DNSSEC' section",
            f"6. Click 'Enable DNSSEC'",
            f"7. Follow the setup process",
            f"8. Copy the DS record",
            f"9. Configure external DNS if needed"
        ]
    }
    
    return instructions.get(dns_provider.lower(), [
        f"1. Contact your DNS provider for DNSSEC enablement instructions",
        f"2. Ensure your DNS provider supports DNSSEC",
        f"3. Enable DNSSEC in your DNS provider's control panel",
        f"4. Get the DS record from your DNS provider",
        f"5. Add the DS record to your domain registrar",
        f"6. Wait 24-48 hours for propagation"
    ])

def verify_dnssec(domain: str) -> bool:
    """Verify DNSSEC is working correctly"""
    try:
        # Check for RRSIG records
        result = subprocess.run(
            ['dig', '+dnssec', '+short', domain],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if 'RRSIG' in result.stdout:
            print(f"✅ DNSSEC is enabled for {domain}")
            return True
        else:
            print(f"❌ DNSSEC is not enabled for {domain}")
            return False
            
    except Exception as e:
        print(f"❌ Error verifying DNSSEC: {str(e)}")
        return False

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="DNSSEC Enablement Helper")
    parser.add_argument("domain", help="Domain to check/enable DNSSEC for")
    parser.add_argument("--provider", help="DNS provider (cloudflare, route53, google, azure, godaddy, namecheap)")
    parser.add_argument("--check", action="store_true", help="Check current DNSSEC status")
    parser.add_argument("--verify", action="store_true", help="Verify DNSSEC is working")
    
    args = parser.parse_args()
    
    print(f"🔍 DNSSEC Helper for {args.domain}")
    print("=" * 50)
    
    if args.check or not args.provider:
        # Check current status
        status = check_dnssec_status(args.domain)
        
        print(f"Domain: {status['domain']}")
        print(f"DNSSEC Enabled: {'✅ Yes' if status['dnssec_enabled'] else '❌ No'}")
        
        if status['nameservers']:
            print(f"Nameservers: {', '.join(status['nameservers'])}")
        
        if status['ds_record']:
            print(f"DS Record: {status['ds_record']}")
        
        if status['issues']:
            print("Issues:")
            for issue in status['issues']:
                print(f"  - {issue}")
        
        if not status['dnssec_enabled']:
            print("\n⚠️  DNSSEC is not enabled. This is a critical security vulnerability!")
            print("   Enable DNSSEC immediately to prevent DNS hijacking attacks.")
    
    if args.provider:
        # Show enablement instructions
        print(f"\n📋 DNSSEC Enablement Instructions for {args.provider.upper()}:")
        print("-" * 60)
        
        instructions = get_dnssec_instructions(args.domain, args.provider)
        for i, instruction in enumerate(instructions, 1):
            print(f"{instruction}")
        
        print(f"\n🔍 After enabling DNSSEC, verify with:")
        print(f"   dig +dnssec {args.domain}")
        print(f"   dig DS {args.domain}")
    
    if args.verify:
        # Verify DNSSEC
        print(f"\n🔍 Verifying DNSSEC for {args.domain}...")
        verify_dnssec(args.domain)
    
    print(f"\n📚 For more information, see:")
    print(f"   - DNSSEC_ENABLEMENT_GUIDE.md")
    print(f"   - https://dnssec-analyzer.verisignlabs.com/")

if __name__ == "__main__":
    main()
