import time

import boto3

from src.dns_providers.dns_provider import DNSProvider


class Route53DNSProvider(DNSProvider):
    def create_dns_record(self, domain: str, dns_challenge_validation: str):
        route53 = boto3.client('route53')
        response = route53.change_resource_record_sets(
            HostedZoneId='AAAAAAAAA',
            ChangeBatch={
                'Changes': [
                    {
                        'Action': 'UPSERT',
                        'ResourceRecordSet': {
                            'Name': f"_acme-challenge.{domain}",
                            'Type': 'TXT',
                            'TTL': 300,
                            'ResourceRecords': [{'Value': '"{}"'.format(dns_challenge_validation)}],
                        }
                    },
                ]
            }
        )
        time.sleep(30)
