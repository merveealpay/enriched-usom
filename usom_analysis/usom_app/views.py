from django.shortcuts import render
from django.http import HttpResponse
from .forms import DomainIPForm
import requests
import whois
import re
import dns.resolver
import datetime

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
                x = f"Similar IOC found: {similar_domain}"

        # Pasif DNS analizi sadece DNS kaydı bulunan alan adları için yapılıyor
        passive_dns_analysis(domain)
        return x, passive_dns_analysis(domain)
    except dns.resolver.NoAnswer:
        return f"DNS record not found: {domain}"
    except dns.resolver.NXDOMAIN:
        return f"DNS record not found: {domain}"
    except dns.resolver.Timeout:
        return f"DNS resolution timed out for domain: {domain}."

def passive_dns_analysis(domain):
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5

        now = datetime.datetime.now()
        week_ago = now - datetime.timedelta(days=7)

        url = f"https://www.virustotal.com/api/v3/domains/{domain}/passive_dns"
        headers = {
            "x-apikey": "YOUR_API_KEY",
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
                        return f"IP Address: {record['attributes']['ip_address']}, Last Resolved: {record['attributes']['last_resolved']}"
            else:
                return "No passive DNS records found."
        else:
            return f"No passive DNS records found for domain: {domain}"
    except Exception as e:
        return f"Error occurred while fetching passive DNS records: {e}"

def perform_whois_analysis(domain, ioc_list, analysis_results=None):
    try:
        whois_info = whois.whois(domain)
    except whois.parser.PywhoisError:
        return f"WHOIS information couldn't be retrieved: {domain}"
    similar_ioc_list = []
    if all(value is None for value in whois_info.values()):
        return f"No WHOIS information available for domain: {domain}"

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
                        similar_ioc_list.append(ioc)

    if whois_info is not None:
        analysis_results.append({
            "domain": domain,
            "whois_info": whois_info,
            "similar_ioc": "Simillar WHOIS entry found for IOC: {}".format(similar_ioc_list)
        })
        return analysis_results


def index(request):
    if request.method == 'POST':
        form = DomainIPForm(request.POST)
        if form.is_valid():
            domain = form.cleaned_data['domain']
            ip = form.cleaned_data['ip']
            url = "https://usom.gov.tr/url-list.txt"
            response = requests.get(url)
            ioc_list = response.text.splitlines()
            analysis_results = []
            a = perform_whois_analysis(domain, ioc_list, analysis_results)
            b = find_similar_iocs(domain)
            c = passive_dns_analysis(domain)
            return HttpResponse(f"Pivotlama işlemi tamamlandı, sonuçlar:<br>{a}<br>{b}<br>{c}")
    else:
        form = DomainIPForm()

    return render(request, 'index.html', {'form': form})