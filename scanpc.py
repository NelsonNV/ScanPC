import getpass
import socket
import psutil
import nmap
import wmi
class Computer():

    def __init__(self):
        self.computerName = socket.gethostname()
        self.adressIP = self.getAdressIp()
        self.userName = getpass.getuser()

    def setEthernetIp(self, ip):
        self.adressIP = ip

    def setWirelessIp(self, ip):
        self.wirelessIP = ip

    def setUserName(self, user):
        self.userName = user

    def getComputerName(self):
        return self.computerName

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
    def getAllIp(self) -> dict:
        """todos las conexiones del dispositivo

        Returns:
            all_ips: un diccionario con todas las direcciones ip y nombres de las interfaces
        """
        all_ips = {}
        interfaces = psutil.net_if_addrs()
        for interface, addrs in interfaces.items():
            ips = [addr.address for addr in addrs if addr.family == socket.AF_INET]
            if ips:
                all_ips[interface] = ips

        return all_ips
    
    def DisksInfoPsutil(self):
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
                    'File System Type': partition.fstype
                })
            except Exception as e:
                print(f"Error obtaining information for {partition.mountpoint}: {e}")

        return disk_info

    def DisksInfoWMI(self):
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
                'serial_number': disk.VolumeSerialNumber
            })
        return disk_info
    def getDisksInfo(self):
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
                        "serial_number": wmi_disk['serial_number']
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
            "IP Address": self.getAdressIp(),
            "User Name": self.getUserName(),
            "Disk Information": self.getDisksInfo()
        }
        return resumen_info

    def FullInfoDic(self) -> dict:
        full_info = {
            "Computer Name": self.getComputerName(),
            "IP Address": self.getAdressIp(),
            "User Name": self.getUserName(),
            "All IP Connections": self.getAllIp(),
            "Disk Information": self.getDisksInfo(),
            "Open Ports Local": self.GetPortsOpenLocal()
        }
        return full_info
    



    def generar_informe(self, file_name='informe_equipo.md') -> None:
        with open(file_name, 'w') as file:
            resumen = self.Resumendic()
            file.write("# Resumen de Información\n\n")
            for key, value in resumen.items():
                if key == "Disk Information":
                    disks_summary = [f"{disk['mountp oint']} ({self._get_size_info(disk['total_size'])})" for disk in value]
                    file.write(f"- **{key}:** {', '.join(disks_summary)}\n")
                else:
                    file.write(f"- **{key}:** {value}\n")
            file.write("\n\n")

            full_info = self.FullInfoDic()
            file.write("# Información Completa\n\n")
            
            for key, value in full_info.items():
                if key == "Disk Information":
                    file.write(f"## {key}\n\n")
                    file.write("| Device | Model | Total Size | Rotational | Mountpoint |\n")
                    file.write("| --- | --- | --- | --- | --- |\n")
                    for disk in value:
                        mountpoint = disk.get('mountpoint', 'Unknown')
                        total_size = self._get_size_info(disk['total_size'])
                        used_size = self._get_size_info(disk['used_size'])
                        free_size = self._get_size_info(disk['free_size'])
                        file.write(f"| {mountpoint} | {total_size} | {used_size} | {free_size} |\n")
                    file.write("\n")
                elif key == "All IP Connections":
                    file.write(f"## {key}\n\n")
                    file.write("| Interface Name | IP Address |\n")
                    file.write("| --- | --- |\n")
                    for interface, ips in value.items():
                        for ip in ips:
                            file.write(f"| {interface} | {ip} |\n")
                    file.write("\n")
                elif key == "Open Ports Local":
                    file.write(f"## {key}\n\n")
                    file.write("| Port | Service | State | Reason |\n")
                    file.write("| --- | --- | --- | --- |\n")
                    for port, info in value.items():
                        service_name = info['service'] if info['service'] and info['service'].isascii() else "Desconocido"
                        file.write(f"| {port} | {service_name} | {info['state']} | {info['reason']} |\n")
                    file.write("\n")
                else:
                    file.write(f"## {key}\n\n")
                    if isinstance(value, list) or isinstance(value, dict):
                        for k, v in value.items() if isinstance(value, dict) else enumerate(value):
                            if isinstance(v, dict):
                                file.write(f"### {k}\n")
                                for inner_k, inner_v in v.items():
                                    file.write(f"- **{inner_k}:** {inner_v}\n")
                                file.write("\n")
                            else:
                                file.write(f"- **{k}:** {v}\n")
                        file.write("\n")
                    else:
                        file.write(f"- **{value}**\n\n")

        print(f"Informe generado en '{file_name}'")

    def _get_size_info(self, size):
        size = int(size)
        if size < 1024:
            return f"{size} B"
        elif size < 1024 * 1024:
            return f"{size / 1024:.2f} KB"
        elif size < 1024 * 1024 * 1024:
            return f"{size / (1024 * 1024):.2f} MB"
        else:
            return f"{size / (1024 * 1024 * 1024):.2f} GB"

mi_equipo = Computer()
ls = mi_equipo.getDisksInfo()

print(ls)
# mi_equipo.generar_informe('informenuevo.md')