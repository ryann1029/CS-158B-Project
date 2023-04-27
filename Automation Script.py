import telnetlib
import getpass
import time

def change_rip(telnet_ip_address, port, password=None):
    network_rip_ip = []
    for i in range(2):
        network_ip = input("IP #{} for RIP protocol (enter nothing if none): ".format(i+1))
        if network_ip != "":
            network_rip_ip.append(str(network_ip))
    if len(network_rip_ip) < 1:
        raise Exception("No IPs to configure RIP")

    tn = telnetlib.Telnet(host=telnet_ip_address, port=port, timeout=60)
    print(tn)
    tn.write(b"\r\n")
    time.sleep(10)
    if password is not None:
        tn.read_until(b"Password:")
        tn.write(password.encode('ascii') + b"\r\n")
    tn.write(b"config t\r")
    tn.write(b"router rip\r")
    tn.write(b"version 2\r")
    tn.write(b"no auto-summary\r")
    for ip in network_rip_ip:
        network_command = "network {}\r".format(ip)
        tn.write(network_command.encode())
    tn.write(b"end\r")
    tn.write(b"wr mem\r")
    print("Building configuration...")
    time.sleep(10)
    tn.write(b"quit\r")
    time.sleep(10)
    tn.write(b"\r\n")
    tn.close()
    print("Successully sent commands.")
    
def change_ospf(telnet_ip_address, port, password=None):
    network_rip_ip = []
    for i in range(2):
        network_ip = input("IP #{} for OSPF protocol (enter nothing if none): ".format(i+1))
        if network_ip != "":
            network_rip_ip.append(str(network_ip))
    if len(network_rip_ip) < 1:
        raise Exception("No IPs to configure OSPF")

    tn = telnetlib.Telnet(host=telnet_ip_address, port=port, timeout=60)
    print(tn)
    tn.write(b"\r\n")
    time.sleep(10)
    if password is not None:
        tn.read_until(b"Password:")
        tn.write(password.encode('ascii') + b"\r\n")
    tn.write(b"config t\r")
    tn.write(b"router ospf 1\r")
    for ip in network_rip_ip:
        network_command = "network {} 0.0.0.255 area 0\r".format(ip)
        tn.write(network_command.encode())
    tn.write(b"end\r")
    tn.write(b"wr mem\r")
    print("Building configuration...")
    time.sleep(10)
    tn.write(b"quit\r")
    time.sleep(10)
    tn.write(b"\r\n")
    tn.close()
    print("Successully sent commands.")
    
def change_hostname(telnet_ip_address, port, new_hostname, password=None):
    tn = telnetlib.Telnet(host=telnet_ip_address, port=port, timeout=60)
    print(tn)
    tn.write(b"\r\n")
    print("Waiting for response...")
    time.sleep(10)
    if password is not None:
        tn.read_until(b"Password:")
        tn.write(password.encode('ascii') + b"\r\n")
        print("Password entered")
    tn.write(b"config t\r")
    tn.write(f"hostname {new_hostname}\r".encode())
    tn.write(b"exit\r")
    tn.write(b"wr mem\r")
    print("Building configuration...")
    time.sleep(10)
    tn.write(b"quit\r")
    time.sleep(10)
    tn.write(b"\r\n")
    tn.close()
    print("Host name successfully changed.")
    
def choice_message():
    print("Select number to do action:")
    print("1 -> Change Hostname")
    print("2 -> Change RIP IPs in a router")
    print("3 -> Change OSPF IPs in a router")

if __name__ == "__main__":
    valid_choices = [1, 2, 3]
    choice_message()
    
    choice = int(input("Choice: "))
    while choice not in valid_choices:
        choice_message()
        choice = int(input("Choice: "))
    
    telnet_ip_addr = input("IP Address for telnet: ")
    port_select = input("Port number which router: ")
    password = getpass.getpass("Router Password: ")
    
    if choice == 1:
        new_hostname = input("New Host Name: ")
        change_hostname(telnet_ip_address=telnet_ip_addr, port=port_select, new_hostname=new_hostname, password=password)
    elif choice == 2:
        change_rip(telnet_ip_address=telnet_ip_addr, port=port_select, password=password)
    elif choice == 3:
        change_ospf(telnet_ip_address=telnet_ip_addr, port=port_select, password=password)
