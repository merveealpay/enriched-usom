from django.shortcuts import render
from django.http import HttpResponse
from django.template.loader import render_to_string
from django.http import StreamingHttpResponse
from django.views.decorators.csrf import csrf_exempt

from .forms import DomainIPForm
import requests
import whois
import re
import dns.resolver
import datetime

def get_whois_info(domain):
    try:
        whois_info = whois.whois(domain)
        return whois_info
    except whois.parser.PywhoisError:
        return None

def compare_whois_info(whois_info1, whois_info2):
    common_criteria = ['name_servers']
    for criteria in common_criteria:
        if whois_info1 is not None and whois_info2 is not None:
            if criteria in whois_info1 and whois_info1[criteria] is not None and criteria in whois_info2 and whois_info2[criteria] is not None:
                if set(whois_info1[criteria]) & set(whois_info2[criteria]):
                    return True
    return False

def find_similar_iocs(ioc_list, target_domain):
    target_whois_info = get_whois_info(target_domain)
    for ioc in ioc_list:
        if ioc != target_domain:
            whois_info = get_whois_info(ioc)
            if compare_whois_info(target_whois_info, whois_info):
                yield ioc

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

@csrf_exempt
def stream_response(request):
    def content_generator():
        form = DomainIPForm(request.POST or None)
        if request.method == 'POST' and form.is_valid():
            domain = form.cleaned_data['domain']
            ip = form.cleaned_data['ip']
            url = "https://usom.gov.tr/url-list.txt"
            response = requests.get(url)
            ioc_list = response.text.splitlines()
            analysis_results = []
            a = perform_whois_analysis(domain, ioc_list, analysis_results)
            c = passive_dns_analysis(domain)

            # Write the initial part of the response
            yield render_to_string('results.html', {'a': a, 'c': c, 'b': []})

            # Stream the results of find_similar_iocs
            similar_iocs = []
            for ioc in find_similar_iocs(ioc_list, domain):
                similar_iocs.append(ioc)
                yield render_to_string('results.html', {'b': similar_iocs})  # Pass the entire list of similar IOCs

        # Render the form for GET requests
        else:
            yield render_to_string('index.html', {'form': form})

    return StreamingHttpResponse(content_generator())