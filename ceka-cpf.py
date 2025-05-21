import requests
import random
from fake_useragent import UserAgent
from threading import Thread
from queue import Queue
import sys


def ceka_logo():    
	print("\n\n")                                                                                                                                                                        
	print(f"             \033[0;34m@@@@@@@@@@@@@@@@@                                 @@")                                                                          
	print(f"                                 \033[0;34m@@@@@@@@@                   @@")                                                                            
	print(f"                                         \033[0;34m@@@@@@@@           @@@")                                                                            
	print(f"                                               \033[0;34m@@@@@@      @@@")                                                                             
	print(f"                           \033[0;34m@@@@@@@@@@@@@@@@@@@@@@@@@@      @@@@@")                                                                           
	print(f"                 \033[0;34m@@@@@                              @      @@@@@")                                                                           
	print(f"           \033[0;34m@                            \033[0;34m@@@@@@@@@@@@@@       \033[0;34m@@@@@@@")                                                                       
	print(f"                                  @@@@@@@            \033[0;34m@   @ @@@@@  @@ ")                                                                      
	print(f"                             @@@@ @@        \033[0;34m@@@@@@@  @@@@ @@@@@@@   @@")                                                                     
	print(f"                          \033[0;34m@@    @@@    @        \033[0;34m@@@@@ @@@@@@@@@@@@     @@ ")                                                                 
	print(f"                      \033[0;34m@@       @@@    @@@@@@@@   \033[0;34m@@@@@@@@@@@@@@@@@@@@@@  @@")                                                                
	print(f"                    \033[0;34m@         @@@    @@@        \033[0;34m@@@@@@@@@@@@       @@@@@@@ @@")                                                              
	print(f"                             \033[0;37m@@@    @@@     \033[0;34m@@ @@@@@@ @@@ @@@@@        @@@@@@@")                                                             
	print(f"                            \033[0;37m@@@    @@@     \033[0;34m@@@@@@@@@@@@@@    @   @@@@@@   @@@@@ ")                                                           
	print(f"                           \033[0;37m@@@    @@@     \033[0;34m@ @@@@@@@  @@ @@@ @@@@@@@        @@@@@")                                                           
	print(f"                          \033[0;37m@@@    @@@         \033[0;34m@@@@@@           @@@         @@ @@@@@@ ")                                                       
	print(f"                         \033[0;37m@@@   @@@@           \033[0;34m@@@@@                        @@@  @@ ")                                                        
	print(f"                        \033[0;37m@@@   @@@@  @@@@@@@@@ \033[0;34m@@@@@         \033[0;31m@@@@@@@@@@@     \033[0;37m@@@ ")                                                           
	print(f"                       \033[0;37m@@@@   @@@   @@@@@@@@@ \033[0;34m@@@@@@@      \033[0;31m@@@@@@@@@@@@     \033[0;37m@@@")                                                            
	print(f"                        \033[0;37m@@@@   @@@             \033[0;34m@@@@@@@                     @@@  ")                                                           
	print(f"                          \033[0;37m@@@   @@@               \033[0;34m@@@@@@@                 @@@  ")                                                            
	print(f"                           \033[0;37m@@@   @@@@         @@@     \033[0;34m@@@@@@@@@@@@@@@@@  @@@   ")                                                            
	print(f"                            \033[0;37m@@@   @@@@         @@@   @@@        \033[0;34m@@@@@@@@@@@@   ")                                                            
	print(f"                             \033[0;37m@@@   @@@@         @@@   @@@             \033[0;34m@@@    @@ ")                                                           
	print(f"                              \033[0;37m@@@   @@@@         @@@   @@@            @@ \033[0;34m@@@    @@ ")                                                      
	print(f"                               \033[0;37m@@@   @@@@         @@@   @@@@         @@@   \033[0;34m@@     @ ")                                                       
	print(f"                                \033[0;37m@@@   @@@@         @@@@  @@@@       @@@      \033[0;34m@ ")                                                            
	print(f"                                 \033[0;37m@@@    @@@@@@@@@@  @@@@  @@@@     @@@        \033[0;34m@     @ ")                                                     
	print(f"                                  \033[0;37m@@@                             @@@          \033[0;34m@")                                                           
	print(f"                                   \033[0;37m@@@                          @@@@            \033[0;34m@ ")                                                         
	print(f"                                    \033[0;37m@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")                                                                        
	print(f"                                                                                 \033[0;34m@")                                                         
	print(f"                                     \033[0;37m@@@@@@ @@@@@@ @@ @@@    @@@                 \033[0;34m@ ")                                                        
	print(f"                                     \033[0;37m@      @@@@   @@@@     @@ @@ ")                                                                         
	print(f"                                     \033[0;37m@@@@@@ @@@@@@ @@  @@  @@@@@@@")  
	
	print("\n\n")


KEYWORDS = ['login', 'password', 'username', 'dashboard', 'admin']
MAX_THREADS = 10
WORDLIST_FILE = "cps.txt"
OUTPUT_FILE = "results_cps.txt"


def show_help_for_usage():
    help_message = """

[*] Admin Panel Scanner Tool
[*] Developed by: CEKA
[*] Version: 1.0
[*] Usage: Scan for admin panels using wordlist and proxy/Tor support

[+] Usage: python ceka-cpf.py [OPTIONS]

[+] Options:
    -h, --help              Show this help message and exit
    -u URL                  Specify the target URL directly
    -p PROXY, --proxy PROXY Use a proxy (e.g., http://127.0.0.1:8080)
    --tor                   Use Tor network (SOCKS5 on port 9050)

[+] Example:
    python ceka-cpf.py -u http://example.com --tor
    python ceka-cpf.py -u http://example.com -p http://127.0.0.1:8080

[+] Notes:
    - Make sure to have a wordlist named 'cps.txt' in the same directory.
    - Results will be saved in 'results_cps.txt'


* DEVELOP BY CEKA - ALMAHMOUDI *
    """
    print(help_message)
    sys.exit(0)


def load_admin_cp_wordlist(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"\n\033[0;33m[!] cps file '{file_path}' not found.\n")
        return []


def check_path(base_url, path, headers, results, proxies):
    full_url = f"{base_url.rstrip('/')}/{path}"
    try:
        response = requests.get(full_url, headers=headers, proxies=proxies, timeout=10)
        content = response.text.lower()

        keyword_found = any(keyword in content for keyword in KEYWORDS)

        if response.status_code == 200 and keyword_found:
            result = f"\033[0;32m[+] => [ACCESS] Found: {full_url}\033[0;37m"
            results.append(result)
        else:
            result = f"\033[0;33m[-] Not Found: {full_url} (Status: {response.status_code})\033[0;37m"
    except Exception as e:
        result = f"\033[0;33m[!] Error accessing {full_url}: {e}"

    print(result)
    return result


def worker(base_url, headers, q, results, proxies):
    while not q.empty():
        path = q.get()
        check_path(base_url, path, headers, results, proxies)
        q.task_done()


def scan_admin_panels(url, proxies):
    ua = UserAgent()
    headers = {'User-Agent': ua.random}
    print(f"\n\033[0;34m[*] Starting scan on {url}\033[0;37m\n")
    print(f"\033[0;34m[*] Using random User-Agent: {headers['User-Agent']}\n")

    wordlist = load_admin_cp_wordlist(WORDLIST_FILE)
    if not wordlist:
        print("\033[0;33m[-] No paths to scan. Exiting.")
        return []

    q = Queue()
    results = []

    for path in wordlist:
        q.put(path)

    threads = []
    for _ in range(MAX_THREADS):
        t = Thread(target=worker, args=(url, headers, q, results, proxies))
        t.daemon = True
        t.start()
        threads.append(t)

    q.join()

    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        for res in results:
            f.write(res + "\n")
    
    print(f"\n\033[0;34m[*] Scan completed. Results saved to '{OUTPUT_FILE}'")
    return results

if __name__ == "__main__":
    target_url = None
    proxy = None
    use_tor = False

    ceka_logo()

    i = 1
    while i < len(sys.argv):
        if sys.argv[i] in ['-h', '--help']:
            show_help_for_usage()
        elif sys.argv[i] == '-u':
            if i+1 < len(sys.argv):
                target_url = sys.argv[i+1]
                i += 1
            else:
                print("[!] Missing URL after -u option.")
                sys.exit(1)
        elif sys.argv[i] in ['-p', '--proxy']:
            if i+1 < len(sys.argv):
                proxy = sys.argv[i+1]
                i += 1
            else:
                print("[!] Missing proxy address after -p option.")
                sys.exit(1)
        elif sys.argv[i] == '--tor':
            use_tor = True
        else:
            print(f"[!] Unknown argument: {sys.argv[i]}")
            show_help_for_usage()
        i += 1

    if not target_url:
        target_url = input("\nCEKA > CPF $ ").strip()

    proxies = {}
    if use_tor:
        proxies = {
            'http': 'socks5h://127.0.0.1:9050',
            'https': 'socks5h://127.0.0.1:9050'
        }
        print("[+] Using Tor network via SOCKS5 proxy on port 9050")
    elif proxy:
        proxies = {
            'http': proxy,
            'https': proxy
        }
        print(f"[+] Using proxy: {proxy}")

    scan_results = scan_admin_panels(target_url, proxies)

    if scan_results:
        print("\n[*] CP Admin Found:\n")
        for res in scan_results:
            if "[+]" in res and "Found" in res:
                print(res)
    else:
        print("\n\033[0;33m[-] No admin panels found.\033[0;37m")