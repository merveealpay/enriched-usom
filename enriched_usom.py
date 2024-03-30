import requests
import whois
import re
import dns.resolver

url = "https://usom.gov.tr/url-list.txt"

response = requests.get(url)

ioc_list = response.text.splitlines()

output_file = "usom_enriched.txt"

def find_similar_iocs(domain):
    try:
        a_records = dns.resolver.resolve(domain, 'A')
        ip_addresses = [record.to_text() for record in a_records]

        for ip_address in ip_addresses:
            ptr_records = dns.resolver.resolve(ip_address, 'PTR')
            for ptr_record in ptr_records:
                similar_domain = ptr_record.to_text()
                if similar_domain != domain:
                    print(f"Similar IOC found: {similar_domain}")
    except dns.resolver.NoAnswer:
        print(f"DNS record not found: {domain}")
    except dns.resolver.NXDOMAIN:
        print(f"DNS record not found: {domain}")

def perform_whois_analysis(domain):
    whois_info = whois.whois(domain)

    with open(output_file, "a") as file:
        file.write(f"Domain: {domain}\n")
        file.write(f"WHOIS Info: {whois_info}\n\n")

for ioc in ioc_list:
    domain = ioc.strip()

    try:
        perform_whois_analysis(domain)
    except whois.parser.PywhoisError:
        print(f"WHOIS information couldn't be retrieved: {domain}")

    find_similar_iocs(domain)

print("Analysis completed. Results have been saved to", output_file, "file.")
