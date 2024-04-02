import requests
import whois
import re
import dns.resolver
import datetime

url = "https://usom.gov.tr/url-list.txt"

response = requests.get(url)

ioc_list = response.text.splitlines()

output_file = "usom_enriched.txt"


def find_similar_iocs(domain):
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 10
        a_records = resolver.resolve(domain, 'A')
        ip_addresses = [record.to_text() for record in a_records]

        ptr_records = []
        for ip_address in ip_addresses:
            ptr_records.extend(resolver.resolve(ip_address, 'PTR'))

        for ptr_record in ptr_records:
            similar_domain = ptr_record.to_text()
            if similar_domain != domain:
                print(f"Similar IOC found: {similar_domain}")

        # Pasif DNS analizi sadece DNS kaydı bulunan alan adları için yapılıyor
        passive_dns_analysis(domain)
    except dns.resolver.NoAnswer:
        print(f"DNS record not found: {domain}")
    except dns.resolver.NXDOMAIN:
        print(f"DNS record not found: {domain}")
    except dns.resolver.Timeout:
        print(f"DNS resolution timed out for domain: {domain}.")


def passive_dns_analysis(domain):
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5

        now = datetime.datetime.now()
        week_ago = now - datetime.timedelta(days=7)

        url = f"https://www.virustotal.com/api/v3/domains/{domain}/passive_dns"
        headers = {
            "x-apikey": "YOUR_API_KEY"
            "Content-Type": "application/json"
        }
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            if 'data' in data:
                dns_records = data['data']
                for record in dns_records:
                    last_resolved = datetime.datetime.strptime(record['attributes']['last_resolved'],
                                                               '%Y-%m-%dT%H:%M:%SZ')
                    if last_resolved >= week_ago:
                        print(
                            f"IP Address: {record['attributes']['ip_address']}, Last Resolved: {record['attributes']['last_resolved']}")
            else:
                print("No passive DNS records found.")
        else:
            print(f"No passive DNS records found for domain: {domain}")
    except Exception as e:
        print(f"Error occurred while fetching passive DNS records: {e}")


def perform_whois_analysis(domain):
    whois_info = whois.whois(domain)

    if whois_info is None:
        print(f"WHOIS information not available for domain: {domain}")
        return

    if all(value is None for value in whois_info.values()):
        print(f"No WHOIS information available for domain: {domain}")
        return

    common_criteria = [
        'registrant',
        'name_servers',
        'emails',
        'address'
    ]
    for criteria in common_criteria:
        if criteria in whois_info and whois_info[criteria] is not None:
            for whois_entry in whois_info[criteria]:
                for ioc in ioc_list:
                    escaped_ioc = re.escape(ioc)
                    if re.search(escaped_ioc, str(whois_entry), re.IGNORECASE):
                        print(f"Similar WHOIS entry found for IOC: {ioc}")

    with open(output_file, "a") as file:
        file.write(f"Domain: {domain}\n")
        file.write(f"WHOIS Info: {whois_info}\n\n")


for ioc in ioc_list:

    try:
        domain = ioc.strip()
        perform_whois_analysis(domain)
    except whois.parser.PywhoisError:
        print(f"WHOIS information couldn't be retrieved: {domain}")

    find_similar_iocs(domain)

    passive_dns_analysis(domain)

print("Analysis completed. Results have been saved to", output_file, "file.")
