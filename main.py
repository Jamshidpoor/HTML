import requests
from flask import Flask, render_template, request
from bs4 import BeautifulSoup
import socket
import whois
import re
from urllib.parse import urlparse

app = Flask(__name__)

def get_links(url, depth=2, visited=None):
    if visited is None:
        visited = set()

    links = []
    if depth == 0 or url in visited:
        return []

    visited.add(url)
    try:
        res = requests.get(url, timeout=3)
        soup = BeautifulSoup(res.text, 'html.parser')

        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        scheme = parsed_url.scheme
        port = parsed_url.port or (443 if scheme == "https" else 80)

        links.append({
            "url": url,
            "title": soup.title.string.strip() if soup.title else 'No Title',
            "status": res.status_code,
            "ip": socket.gethostbyname(hostname),
            "port": str(port)
        })

        for a in soup.find_all('a', href=True):
            link = a['href']
            if link.startswith('/'):
                link = url.rstrip('/') + link
            if link.startswith('http') and link not in visited:
                links.extend(get_links(link, depth-1, visited))
    except Exception:
        pass

    return links

def find_subdomains(domain):
    results = []
    try:
        with open("subdomains.txt") as file:
            for sub in file:
                sub = sub.strip()
                test_url = f"http://{sub}.{domain}"
                try:
                    res = requests.get(test_url, timeout=2)
                    if res.status_code < 400:
                        results.append(test_url)
                except:
                    continue
        if not results:
            results.append("ساب دامینی یافت نشد!")
    except:
        results.append("خطا در خواندن فایل ساب دامین‌ها.")
    return results

def extract_emails(text):
    pattern = r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'
    return list(set(re.findall(pattern, text)))

def extract_phones(text):
    pattern = r'\b09\d{9}\b|\+\d{11,13}|\b\d{8,12}\b'
    return list(set(re.findall(pattern, text)))

def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        info = {k: w.get(k, 'نامشخص') for k in ['domain_name', 'registrar', 'creation_date', 'expiration_date', 'name_servers', 'emails', 'status']}
        for k, v in info.items():
            if isinstance(v, (list, set, tuple)):
                info[k] = ', '.join(map(str, v))
            elif v is None:
                info[k] = 'نامشخص'
        return info
    except Exception as e:
        return {"error": f"خطا در دریافت اطلاعات WHOIS: {str(e)}"}

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form['domain']
        if not url.startswith('http'):
            url = 'http://' + url
        domain = url.split("//")[-1].split("/")[0]

        links = get_links(url)
        content = ''
        for link in links:
            try:
                res = requests.get(link['url'], timeout=3)
                content += res.text
            except:
                continue

        emails = extract_emails(content) or ["****.com"]
        phones = extract_phones(content) or ["*****"]
        subdomains = find_subdomains(domain)
        whois_info = get_whois_info(domain)

        return render_template('report.html',
                               links=links,
                               emails=emails,
                               phones=phones,
                               subdomains=subdomains,
                               whois_info=whois_info,
                               domain=domain)
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
