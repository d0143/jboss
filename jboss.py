import sys
import requests
from multiprocessing.dummy import Pool

requests.packages.urllib3.disable_warnings()

headers = {
    "User-Agent": "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:67.0) Gecko/20100101 Firefox/67.0"
}

vuls = ['/jmx-console', '/web-console', '/invoker/JMXInvokerServlet', '/admin-console',
        '/jbossmq-httpil/HTTPServerILServlet', '/invoker/readonly']

def poc(url):
    try:
        r = requests.get(url, headers=headers, timeout=3, verify=False)
        if r.status_code == 401:
            if "jmx" in url:
                result = "[+]jmx-console vulnerability may exist in " + url + "!"
            elif "web" in url:
                result = "[+]web-console vulnerability may exist in " + url + "!"
        elif r.status_code == 200:
            if "admin" in url:
                result = "[+]admin-console vulnerability may exist in " + url + "!"
            elif "JMXInvokerServlet" in url:
                result = "[+]JBoss JMXInvokerServlet(CVE-2015-7501) vulnerability may exist in " + url + "!"
            elif "jbossmq" in url:
                result = "[+]JBOSSMQ JMS(CVE-2017-7504) vulnerability may exist in " + url + "!"
        elif r.status_code == 500:
            if "readonly" in url:
                result = "[+]CVE-2017-12149 vulnerability may exist in " + url + "!"

        with open("result.txt", "a") as f:
            f.write(result + "\n")

    except Exception as e:
        pass

def main():
    pool = Pool(50)
    targets = [target.strip() for target in open("target.txt")]
    urls = []
    for target in targets:
        for vul in vuls:
            url = target + vul
            urls.append(url)
    pool.map(poc, urls)
    pool.close()
    pool.join()

if __name__ == "__main__":
    main()
