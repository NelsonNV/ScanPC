import getpass
import socket
import psutil
import nmap
import wmi
import cpuinfo
import datetime

class Computer():

    def __init__(self):
        self.computerName = socket.gethostname()
        self.adressIP = self.getAdressIp()
        self.userName = getpass.getuser()
        self.domain = self.getDomainName()
        self.fileName = f"{self.computerName}_Informe_{datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.md"

    def setEthernetIp(self, ip):
        self.adressIP = ip

    def setWirelessIp(self, ip):
        self.wirelessIP = ip
    def setFileName(self, ip):
        self.wirelessIP = ip
    def setUserName(self, user):
        self.userName = user

    def getComputerName(self):
        return self.computerName
    def getFileName(self):
        return self.fileName
    def getAdressIp(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))  # Conectarse a un servidor externo
            ip = s.getsockname()[0]
            s.close()
            return ip
        except socket.error:
            return None

    def getUserName(self):
        return self.userName
    def getAllMacAddress(self):
        interfaces = psutil.net_if_addrs()
        mac_addresses = {}
        
        for interface, addrs in interfaces.items():
            for addr in addrs:
                if addr.family == psutil.AF_LINK:  # Verifica que sea una dirección MAC
                    mac_addresses[interface] = addr.address
        
        return mac_addresses
    def getAllIpWithMAC(self):
        all_ips = {}
        interfaces = psutil.net_if_addrs()
        for interface, addrs in interfaces.items():
            ip_addresses = []
            mac_address = 'Unknown'
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    ip_addresses.append(addr.address)
                elif addr.family == psutil.AF_LINK:
                    mac_address = addr.address
            if ip_addresses:
                all_ips[interface] = {
                    'IPs': ip_addresses,
                    'MAC': mac_address
                }
        return all_ips
    def DisksInfoPsutil(self) -> dict:
        disk_info = []
        partitions = psutil.disk_partitions()

        for partition in partitions:
            try:
                partition_usage = psutil.disk_usage(partition.mountpoint)
                disk_info.append({
                    'Mount Point': partition.mountpoint,
                    'Device': partition.device,
                    'Total Size': partition_usage.total,
                    'Free Space': partition_usage.free,
                    'Used Space': partition_usage.used,
                    'File System Type': partition.fstype,
                })
            except Exception as e:
                print(f"Error obtaining information for {partition.mountpoint}: {e}")

        return disk_info

    def DisksInfoWMI(self) -> dict:
        # Conectarse a la clase Win32_LogicalDisk de WMI
        w = wmi.WMI()

        disk_info = []
        for disk in w.Win32_LogicalDisk():
            disk_info.append({
                'Volume Name': disk.VolumeName,
                'File System Type': disk.FileSystem,
                'DeviceID': disk.DeviceID,
                'Total Size': disk.Size ,
                'Free Space': disk.FreeSpace, 
                'Used Space': disk.Size,
                'serial_number': disk.VolumeSerialNumber,
                'Model': disk
            })
        return disk_info
    def getDisksInfo(self) -> dict:
        combined_info = []

        # Obtener información de psutil
        psutil_info = self.DisksInfoPsutil()

        # Obtener información de wmi
        wmi_info = self.DisksInfoWMI()

        # Combinar la información de psutil y wmi
        for psutil_disk in psutil_info:
            for wmi_disk in wmi_info:
                if psutil_disk['Mount Point'][:2] == wmi_disk['DeviceID']:
                    combined_info.append({
                        'Mount Point': psutil_disk['Mount Point'],
                        'Total Size': psutil_disk['Total Size'],
                        'Free Space': psutil_disk['Free Space'],
                        'Used Space': psutil_disk['Used Space'],
                        'File System Type': psutil_disk['File System Type'],
                        'Volume Name': wmi_disk['Volume Name'],
                        'DeviceID': wmi_disk['DeviceID'],
                        'Serial Number': wmi_disk['serial_number']
                    })
                    break

        return combined_info
    
    def GetPortsOpenLocal(self) -> dict:
        nm = nmap.PortScanner()
        nm.scan('127.0.0.1', arguments='-p- -sS')  # Escaneo rápido de puertos en la dirección IP local
        open_ports = {}

        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    if nm[host][proto][port]['state'] == 'open':
                        open_ports[port] = {
                            'service': nm[host][proto][port]['name'],
                            'state': nm[host][proto][port]['state'],
                            'reason': nm[host][proto][port]['reason']
                        }
        return open_ports
    def Resumendic(self) -> dict:
        resumen_info = {
            "Computer Name": self.getComputerName(),
            "Domain PC":self.domain,
            "IP Address": self.getAdressIp(),
            "User Name": self.getUserName(),
            "Disk Information": self.getDisksInfo()
        }
        return resumen_info


    def getCpuDetails(self)-> dict:
        info = cpuinfo.get_cpu_info()

        cpu_info = {
            "Model": info["brand_raw"],
            "Architecture": info["arch"],
            "Bits": info["bits"],
            "Cores": info["count"],
            "CPU Frequency": info["hz_actual_friendly"],
            "L2 Cache Size": info['l2_cache_size'],
            "L3 Cache Size": info['l3_cache_size']
        }
        return cpu_info

    def getDomainName(self):
        c = wmi.WMI()
        computer = c.Win32_ComputerSystem()
        domain = computer[0].Domain
        return domain

    def FullInfoDic(self) -> dict:
        full_info = {
            "Computer Name": self.getComputerName(),
            "IP Address": self.getAdressIp(),
            "User Name": self.getUserName(),
            "Domain PC":self.domain,
            "All IP Connections": self.getAllIpWithMAC(),
            "Disk Information": self.getDisksInfo(),
            "Open Ports Local": self.GetPortsOpenLocal(),
            "CPU Info": self.getCpuDetails()
        }
        return full_info


    def _get_size_info(self, size) -> str:
        size = int(size)
        if size < 1024:
            return f"{size} B"
        elif size < 1024 * 1024:
            return f"{size / 1024:.2f} KB"
        elif size < 1024 * 1024 * 1024:
            return f"{size / (1024 * 1024):.2f} MB"
        else:
            return f"{size / (1024 * 1024 * 1024):.2f} GB"
        
    def generar_informe(self) -> dict:
        try:
            file_name= self.getFileName()
            with open(file_name, 'w', encoding='utf-8') as file:
                full_info = self.FullInfoDic()

                # Sección del resumen
                file.write("# Resumen de Información\n\n")
                file.write(f"- **User Name:** {full_info['User Name']}\n")
                file.write(f"- **Computer Name:** {full_info['Computer Name']}\n")
                file.write(f"- **Model CPU:** {full_info['CPU Info']['Model']}\n")
                file.write(f"- **Domain PC:** {full_info['Domain PC']}\n")
                file.write(f"- **IP Address:** {full_info['IP Address']}\n")
                file.write("\n**Disk Information:**\n\n")
                file.write("| Mount Point | Total Size |\n")
                file.write("| --- | --- |\n")
                for disk in full_info['Disk Information']:
                    file.write(f"| {disk['Mount Point']} | {self._get_size_info(disk['Total Size'])} |\n")

                file.write("\n\n# Información Completa\n\n")
                
                # Información de todas las conexiones IP con sus MACs
                file.write("- **All IP Connections:**\n\n")
                file.write("| Interface Name | IP Address | MAC Address |\n")
                file.write("| --- | --- | --- |\n")
                for interface, info in full_info['All IP Connections'].items():
                    file.write(f"| {interface} | {info['IPs'][0]} | {info['MAC']} |\n")
                file.write("\n\n# CPU Information\n\n")
                file.write("| Property | Value |\n")
                file.write("| --- | --- |\n")
                for key, value in full_info['CPU Info'].items():
                    file.write(f"| {key} | {value} |\n")
                file.write(" \n\n# **Disk Information:**\n\n")
                file.write("| Mount Point | Total Size | Free Space | Used Space | File System Type | Volume Name | Serial Number |\n")
                file.write("| --- | --- | --- | --- | --- | --- | --- |\n")
                for disk in full_info['Disk Information']:
                    volume_name = volume_name = disk['Volume Name'] if disk.get('Volume Name') and disk['Volume Name'] != '' else 'N/A'
                    file.write(f"| {disk['Mount Point']} | {self._get_size_info(disk['Total Size'])} | {self._get_size_info(disk['Free Space'])} | {self._get_size_info(disk['Used Space'])} | {disk['File System Type']} | {volume_name} | {disk['Serial Number']} |\n")
                # Sección de los puertos abiertos
                file.write("\n\n# Open Ports Information\n\n")
                file.write("| Port | Service | State | Reason |\n")
                file.write("| --- | --- | --- | --- |\n")
                for port, info in full_info['Open Ports Local'].items():
                    if info['service'].lower() in ['http', 'https', 'ftp', 'ssh', 'telnet']:
                        file.write(f"| **{port}** | **{info['service']}** | **{info['state']}** | **{info['reason']}** |\n")
                    else:
                        file.write(f"| {port} | {info['service']} | {info['state']} | {info['reason']} |\n")
                            # Resto de la información detallada para el informe completo...

            return {
                'status': 'success',
                'description': f"Informe generado en '{file_name}'"
            }
        except FileNotFoundError as e:
            return {
                'status': 'error',
                'description': f"No se encontró el archivo: {str(e)}"
            }
        except PermissionError as e:
            return {
                'status': 'error',
                'description': f"Error de permisos al crear el archivo: {str(e)}"
            }
        except Exception as e:
            return {
                'status': 'error',
                'description': f"Error al generar el informe: {str(e)}"
            }