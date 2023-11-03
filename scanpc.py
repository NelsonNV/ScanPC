import getpass
import socket
import psutil
import nmap

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
    
    def getDisksInfo(self) -> dict:
        partitions = psutil.disk_partitions()
        disk_info = []

        for partition in partitions:
            try:
                partition_usage = psutil.disk_usage(partition.mountpoint)
                disk_info.append({
                    "device": partition.device,
                    "mountpoint": partition.mountpoint,
                    "total_size": partition_usage.total,
                    "used_size": partition_usage.used,
                    "free_size": partition_usage.free
                })
            except PermissionError:
                # Manejar errores de permisos al acceder a las particiones
                pass

        return disk_info

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
                    disks_summary = [f"{disk['device']} ({self._get_size_info(disk['total_size'])})" for disk in value]
                    file.write(f"- **{key}:** {', '.join(disks_summary)}\n")
                else:
                    file.write(f"- **{key}:** {value}\n")
            file.write("\n\n")

            full_info = self.FullInfoDic()
            file.write("# Información Completa\n\n")
            
            for key, value in full_info.items():
                if key == "Disk Information":
                    file.write(f"## {key}\n\n")
                    file.write("| Device | Mountpoint | Total Size | Used Size | Free Size |\n")
                    file.write("| --- | --- | --- | --- | --- |\n")
                    for disk in value:
                        file.write(f"| {disk['device']} | {disk['mountpoint']} | {self._get_size_info(disk['total_size'])} | {self._get_size_info(disk['used_size'])} | {self._get_size_info(disk['free_size'])} |\n")
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
        if size < 1024:
            return f"{size} B"
        elif size < 1024 * 1024:
            return f"{size / 1024:.2f} KB"
        elif size < 1024 * 1024 * 1024:
            return f"{size / (1024 * 1024):.2f} MB"
        else:
            return f"{size / (1024 * 1024 * 1024):.2f} GB"

mi_equipo = Computer()
mi_equipo.generar_informe('informe_mi_equipo3.md')
