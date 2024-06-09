import sys,os
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QLineEdit, QPushButton, QTextEdit, QVBoxLayout, QComboBox
from PyQt5.QtCore import pyqtSignal, pyqtSlot, QThread, QMutex, QWaitCondition,Qt
from PyQt5.QtGui import QFont,QColor
from scapy.all import sniff, get_if_list, get_if_hwaddr
from datetime import datetime
from scapy.layers.inet import IP, TCP, UDP
try:
    import win32com.client
    is_windows = True
except ImportError:
    is_windows = False

def get_active_ifaces():
    active_interfaces = set()
    wmi = win32com.client.GetObject("winmgmts:")
    for nic in wmi.InstancesOf("Win32_NetworkAdapter"):
        if nic.NetEnabled and nic.NetConnectionStatus == 2:
            active_interfaces.add(nic.Description)
    return active_interfaces
    
class PacketSniffer(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Packet Sniffer")
        self.init_ui()
        self.sniff_thread = None
        self.is_sniffing = False

    def init_ui(self):
        layout = QVBoxLayout()

        # Interface selection
        self.interface_label = QLabel("NIC Selection: ")
        self.interface_combo = QComboBox()
        self.interfaces()
        layout.addWidget(self.interface_label)
        layout.addWidget(self.interface_combo)

        # Protocol selection
        self.protocol_label = QLabel("Protocol Selection:")
        self.protocol_combo = QComboBox()
        self.protocol_combo.addItems(["TCP", "UDP", "TCP or UDP"])
        layout.addWidget(self.protocol_label)
        layout.addWidget(self.protocol_combo)

        # Port input
        self.port_label = QLabel("Port to listen on: (ex: 80, 443)")
        self.port_input = QLineEdit()
        layout.addWidget(self.port_label)
        layout.addWidget(self.port_input)

        # Start button
        self.start_button = QPushButton("Start")
        self.start_button.clicked.connect(self.start_sniffing)
        layout.addWidget(self.start_button)

        # Stop button
        self.stop_button = QPushButton("Stop")
        self.stop_button.clicked.connect(self.stop_sniffing)
        self.stop_button.setEnabled(False)
        layout.addWidget(self.stop_button)

        # Log display
        self.log_label = QLabel("Packet Log:")
        layout.addWidget(self.log_label)
        self.log_display = QTextEdit()
        self.log_display.setReadOnly(True)
        layout.addWidget(self.log_display)

        self.setLayout(layout)
        self.resize(1280, 720)
    

    def interfaces(self):
        wmi = win32com.client.GetObject("winmgmts:")
        active_interfaces = get_active_ifaces()
        for nic in wmi.InstancesOf("Win32_NetworkAdapter"):
            interface_name = nic.Name
            interface_description = nic.Description
            combo_item = interface_description
            if interface_description in active_interfaces:
                combo_item += " (Active)"
                # Set text color to red and make it bold for active interface
                self.interface_combo.addItem(combo_item, interface_name)
                item_index = self.interface_combo.count() - 1
                self.interface_combo.setItemData(item_index, QColor("green"), role=Qt.ForegroundRole)
                font = QFont()
                font.setBold(True)
                self.interface_combo.setItemData(item_index, font, role=Qt.FontRole)
            else:
                combo_item += " (Inactive)"
                # Set text color to red for active interface
                self.interface_combo.addItem(combo_item, interface_name)
                self.interface_combo.setItemData(self.interface_combo.count() - 1, QColor("red"), role=Qt.ForegroundRole)

    def int_desc(self, iface):
        wmi = win32com.client.GetObject("winmgmts:")
        for nic in wmi.InstancesOf("Win32_NetworkAdapter"):
            if nic.NetConnectionID == iface:
                return f"{nic.Name} ({iface})"
        return iface

    def start_sniffing(self):
        interface = self.interface_combo.currentData()
        protocol = self.protocol_combo.currentText()
        ports = self.port_input.text().split(",")

        ports = [port.strip() for port in ports if port.strip()]

        if protocol == "TCP":
            if not ports:
                filter_str = "tcp"
                self.log_display.append("All TCP Port Listening...")
            else:
                if all(port.isdigit() for port in ports):
                    filter_str = "tcp and (" + " or ".join(f"port {port}" for port in ports) + ")"
                    self.log_display.append(f"Listened TCP ports: {', '.join(ports)}")
                else:
                    self.log_display.append("Enter valid TCP port number.")
                    return
        elif protocol == "UDP":
            if not ports:
                filter_str = "udp"
                self.log_display.append("All UDP Port Listening...")
            else:
                if all(port.isdigit() for port in ports):
                    filter_str = "udp and (" + " or ".join(f"port {port}" for port in ports) + ")"
                    self.log_display.append(f"Listened UDP ports: {', '.join(ports)}")
                else:
                    self.log_display.append("Enter valid UDP port number.")
                    return
        else:  # TCP or UDP
            if not ports:
                filter_str = "tcp or udp"
                self.log_display.append("All TCP and UDP ports are listened.")
            else:
                filters = []
                if all(port.isdigit() for port in ports):
                    filters.append("tcp and (" + " or ".join(f"port {port}" for port in ports) + ")")
                    filters.append("udp and (" + " or ".join(f"port {port}" for port in ports) + ")")
                    filter_str = " or ".join(filters)
                    self.log_display.append(f"Listened TCP Ports: {', '.join(ports)} and UDP Ports: {', '.join(ports)}")
                else:
                    self.log_display.append("Enter Valid Port Number")
                    return

        documents_directory = os.path.join(os.path.expanduser("~"), "Documents")
        if not os.path.exists(documents_directory):
            os.makedirs(documents_directory)
        
        filename = os.path.join(documents_directory, "NIC_Dump_" + datetime.now().strftime("%Y-%m-%d_%H-%M-%S") + ".txt")
        self.log_display.append(f"<font color='red'><b>Listened packets will be saved in {filename} file.\n</b></font>")
        self.sniff_thread = SniffThread(interface, filter_str, filename)
        self.sniff_thread.packet_received.connect(self.handle_packet_received)
        self.sniff_thread.finished.connect(self.sniff_thread.deleteLater)
        self.sniff_thread.start()

        self.is_sniffing = True
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)

    def stop_sniffing(self):
        if self.sniff_thread and self.is_sniffing:
            self.sniff_thread.stop_sniffing()
            self.is_sniffing = False
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)

    @pyqtSlot(str)
    def handle_packet_received(self, packet_summary):
        packet_info = packet_summary.split(" - ")
        if len(packet_info) >= 2:
            packet_type = packet_info[0]
            packet_details = packet_info[1]
            if "Source IP" in packet_details:
                log_message = "<font color='green'><b>Incoming:</b></font> " + packet_details
            elif "Destination IP" in packet_details:
                log_message = "<font color='blue'><b>Outgoing:</b></font> " + packet_details
            else:
                log_message = "<font color='black'><b>Unknown:</b></font> " + packet_details
            self.log_display.append(log_message)
        else:
            self.log_display.append("Received incomplete packet information.")

class SniffThread(QThread):
    packet_received = pyqtSignal(str)

    def __init__(self, interface, filter_str, filename):
        super().__init__()
        self.interface = interface
        self.filter_str = filter_str
        self.filename = filename
        self.mutex = QMutex()
        self.condition = QWaitCondition()
        self.running = True

    def run(self):
        while self.running:
            sniff(filter=self.filter_str, prn=lambda packet: self.write_to_file(packet), timeout=1)
        self.packet_received.emit("\nListening has been terminated.")

    def write_to_file(self, packet):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            packet_type = "TCP"
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            packet_type = "UDP"
        if not os.path.exists(self.filename):
            with open(self.filename, "a", encoding='utf-8') as file:
                file.write("Packet Type, Src IP, Src Port, Dest IP, Dest Port\n")

        with open(self.filename, "a", encoding='utf-8') as file:
            file.write(f"{packet_type}, {src_ip}, {src_port}, {dst_ip}, {dst_port}\n")
        self.packet_received.emit(f"{packet_type} packet - Source IP: {src_ip}, Source Port: {src_port}, Destination IP: {dst_ip}, Destination Port: {dst_port}\n")

    def stop_sniffing(self):
        self.mutex.lock()
        self.running = False
        self.mutex.unlock()
        self.condition.wakeAll()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PacketSniffer()
    window.show()
    sys.exit(app.exec_())
