"""
Welcome to Alf's recon tool
Version: 1.0
Author: Alfreaca
"""
try:
    import nmap

except ImportError:
    print("Oops! You're missing the nmap module. Please install it, you can use pip install nmap for this.")
    exit()
    
print("""   
   _____  .__   _____                                            
  /  _  \ |  |_/ ____\______ _______   ____   ____  ____   ____  
 /  /_\  \|  |\   __\/  ___/ \_  __ \_/ __ \_/ ___\/  _ \ /    \ 
/    |    \  |_|  |  \___ \   |  | \/\  ___/\  \__(  <_> )   |  |
\____|__  /____/__| /____  >  |__|    \___  >\___  >____/|___|  /
        \/               \/               \/     \/           \/ 
  __                .__   
_/  |_  ____   ____ |  |  
\   __\/  _ \ /  _ \|  |  
 |  | (  <_> |  <_> )  |__
 |__|  \____/ \____/|____/

""")

def portscan():
    host = input("Input the target: ")
    port_range = input("Input the port range (syntax <port1>-<port2>): ")
    nm = nmap.PortScanner()
    nm.scan(host, port_range)

    for host in nm.all_hosts():
        print("State :", nm[host].state())
        for proto in nm[host].all_protocols():
            print("-----------------")
            print("Protocol : %s" % proto)

            lport = nm[host][proto].keys()
            for port in lport:
                print("port : %s\tstate : %s" % (port, nm[host][proto][port]['state']))


def menu():
    print("""This tool has many recon purposes. please select the option you would like:
                    1. Portscan (nmap)
                    2. Domain history, info and registered subdomains
                    3. URL Fuzzing
                    4. Exit
                    """)
    choice = str(input("Input your choice: "))

    if choice == '1':
        portscan()

    elif choice == '2':
        domainRecon()

    elif choice == '3':
        urlFuzzing()

    elif choice == '4':
        completeScan()

    elif choice == '5':
        exit()

menu()
