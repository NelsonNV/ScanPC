from computer import Computer
import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QTableWidget, QTableWidgetItem,QTabWidget,QHBoxLayout
from PyQt5.QtGui import QIcon

class ComputerGUI(QWidget):
    def __init__(self, computer):
        super().__init__()

        self.computer = computer

        # Cuadro principal para mostrar los detalles del resumen
        self.summary_label = QLabel()
        self.update_summary_label()

        # Campo para mostrar el dominio
        self.domain_label = QLabel()
        self.update_domain_label()

        # Campo para cambiar el nombre del archivo
        self.filename_label = QLabel("Nombre del archivo a exportar:")
        self.filename_input = QLineEdit()
        self.filename_input.setText(self.computer.getFileName())

        # Botón para generar el informe
        self.generate_report_button = QPushButton("Generar Informe")
        self.generate_report_button.clicked.connect(self.generate_report)

        # Crear pestañas para las tablas
        self.table_tabs = QTabWidget()

        self.ip_connections_table = QTableWidget()
        self.disk_info_table = QTableWidget()
        self.open_ports_table = QTableWidget()
        self.cpu_info_table = QTableWidget()

        self.populate_ip_connections_table()
        self.populate_disk_info_table()
        self.populate_open_ports_table()
        self.populate_cpu_info_table()

        # Agregar las tablas a las pestañas
        self.table_tabs.addTab(self.ip_connections_table, "Conexiones IP")
        self.table_tabs.addTab(self.disk_info_table, "Información del Disco")
        self.table_tabs.addTab(self.open_ports_table, "Puertos Abiertos")
        self.table_tabs.addTab(self.cpu_info_table, "Información de la CPU")

        # Establecer tamaño fijo de la ventana
        self.setFixedSize(720, 400)

        layout = QVBoxLayout()
        layout.addWidget(self.summary_label)
        layout.addWidget(self.domain_label)

        # Agrupar el campo de nombre de archivo y el botón
        filename_layout = QHBoxLayout()
        filename_layout.addWidget(self.filename_label)
        filename_layout.addWidget(self.filename_input)
        filename_layout.addWidget(self.generate_report_button)

        layout.addLayout(filename_layout)
        layout.addWidget(self.table_tabs)

        self.setLayout(layout)
        self.setWindowTitle("Información del Equipo")

    def update_summary_label(self):
        summary_text = f"Nombre de Equipo: {self.computer.getComputerName()}\nUsuario: {self.computer.getUserName()}\nDirección IP: {self.computer.getAdressIp()}"
        self.summary_label.setText(summary_text)

    def update_domain_label(self):
        domain_text = f"Dominio: {self.computer.getDomainName()}"
        self.domain_label.setText(domain_text)

    def populate_ip_connections_table(self):
        ip_connections = self.computer.getAllIpWithMAC()
        self.ip_connections_table.setColumnCount(3)
        self.ip_connections_table.setHorizontalHeaderLabels(["Interface Name", "IP Address", "MAC Address"])
        self.ip_connections_table.setRowCount(len(ip_connections))
        for row, (interface, info) in enumerate(ip_connections.items()):
            ip_address = info['IPs'][0] if info['IPs'] else "N/A"
            mac_address = info['MAC']
            self.ip_connections_table.setItem(row, 0, QTableWidgetItem(interface))
            self.ip_connections_table.setItem(row, 1, QTableWidgetItem(ip_address))
            self.ip_connections_table.setItem(row, 2, QTableWidgetItem(mac_address))

    def populate_disk_info_table(self):
        disk_info = self.computer.getDisksInfo()
        self.disk_info_table.setColumnCount(7)
        self.disk_info_table.setHorizontalHeaderLabels(
            ["Mount Point", "Total Size", "Free Space", "Used Space", "File System Type", "Volume Name", "Serial Number"]
        )
        self.disk_info_table.setRowCount(len(disk_info))
        for row, disk in enumerate(disk_info):
            volume_name = disk.get('Volume Name', 'N/A')
            serial_number = disk.get('Serial Number', 'N/A')
            if not volume_name or volume_name == '': volume_name = 'N/A'
            self.disk_info_table.setItem(row, 0, QTableWidgetItem(disk['Mount Point']))
            self.disk_info_table.setItem(row, 1, QTableWidgetItem(str(disk['Total Size'])))
            self.disk_info_table.setItem(row, 2, QTableWidgetItem(str(disk['Free Space'])))
            self.disk_info_table.setItem(row, 3, QTableWidgetItem(str(disk['Used Space'])))
            self.disk_info_table.setItem(row, 4, QTableWidgetItem(disk['File System Type']))
            self.disk_info_table.setItem(row, 5, QTableWidgetItem(volume_name))
            self.disk_info_table.setItem(row, 6, QTableWidgetItem(serial_number))

    def populate_open_ports_table(self):
        open_ports = self.computer.GetPortsOpenLocal()
        self.open_ports_table.setColumnCount(4)
        self.open_ports_table.setHorizontalHeaderLabels(["Port", "Service", "State", "Reason"])
        self.open_ports_table.setRowCount(len(open_ports))
        for row, (port, info) in enumerate(open_ports.items()):
            service = info['service']
            state = info['state']
            reason = info['reason']
            if not service or service == '': service = 'Desconocido'
            self.open_ports_table.setItem(row, 0, QTableWidgetItem(str(port)))
            self.open_ports_table.setItem(row, 1, QTableWidgetItem(service))
            self.open_ports_table.setItem(row, 2, QTableWidgetItem(state))
            self.open_ports_table.setItem(row, 3, QTableWidgetItem(reason))  # Corrección: cerrar paréntesis


    def populate_cpu_info_table(self):
        cpu_info = self.computer.getCpuDetails()
        properties = ['Model', 'Architecture', 'Bits', 'Cores', 'CPU Frequency', 'L2 Cache Size', 'L3 Cache Size']
        self.cpu_info_table.setColumnCount(len(properties))
        self.cpu_info_table.setRowCount(1)  # Una fila para mostrar los datos

        for col, prop in enumerate(properties):
            if prop in cpu_info:
                self.cpu_info_table.setHorizontalHeaderItem(col, QTableWidgetItem(prop))
                self.cpu_info_table.setItem(0, col, QTableWidgetItem(str(cpu_info[prop])))
            else:
                self.cpu_info_table.setHorizontalHeaderItem(col, QTableWidgetItem(prop))
                self.cpu_info_table.setItem(0, col, QTableWidgetItem("N/A"))




    def generate_report(self):
        new_filename = self.filename_input.text()
        self.computer.setFileName(new_filename)
        report_status = self.computer.generar_informe()
        # Puedes mostrar el estado del informe en la interfaz, por ejemplo, en una etiqueta

if __name__ == '__main__':
    app = QApplication(sys.argv)

    # Crear una instancia de la clase Computer
    computer_instance = Computer()  # Asegúrate de pasar los argumentos necesarios si hay alguna configuración específica
    window = ComputerGUI(computer_instance)
    window.setWindowIcon(QIcon('icon_scanpc.ico'))
    window.setWindowTitle('ScanPC')
    window.show()

    sys.exit(app.exec_())
