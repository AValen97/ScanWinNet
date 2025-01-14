import socket
import sys
import requests
from scapy.all import ARP, Ether, srp
from concurrent.futures import ThreadPoolExecutor, as_completed
import tkinter as tk
from tkinter import scrolledtext
from icmplib import ping

# Mapa de puertos a protocolos
puerto_protocolos = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP (Alternativo)",
}

def verificar_dependencias():
    """Verifica que todas las bibliotecas necesarias estén instaladas."""
    try:
        import requests
        from scapy.all import ARP, Ether, srp
        from icmplib import ping
    except ImportError as e:
        print(f"Error: No se pudo importar {e.name}.")
        print("Asegúrate de que todas las dependencias estén instaladas.")
        print("Puedes instalar las dependencias necesarias usando:")
        print("pip install requests scapy icmplib")
        sys.exit(1)

verificar_dependencias()

def obtener_ip_privada():
    """Obtiene la IP privada del sistema."""
    hostname = socket.gethostname()
    return socket.gethostbyname(hostname)

def obtener_ip_publica():
    """Obtiene la IP pública usando un servicio web."""
    response = requests.get('https://api.ipify.org')
    return response.text

def comprobar_conexion():
    """Verifica el estado de la conexión a Internet."""
    try:
        requests.get('https://www.google.com', timeout=5)
        return True
    except requests.ConnectionError:
        return False

def escanear_puerto(ip, port):
    """Escanea un puerto específico para verificar si está abierto y devuelve el protocolo."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex((ip, port))
    sock.close()
    
    if result == 0:
        return port, puerto_protocolos.get(port, "Desconocido") # Devuelve el puerto y el protocolo
    return None

def puertos_abiertos(ip):
    """Verifica los puertos abiertos en la IP especificada."""
    open_ports = []
    total_ports = 1024
    
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(escanear_puerto, ip, port): port for port in range(1, total_ports + 1)}
        
        for future in as_completed(futures):
            result = future.result()
            if result is not None:
                open_ports.append(result) # Agrega tupla (puerto, protocolo)
    
    return open_ports

def obtener_fabricante(mac):
    """Obtiene el fabricante a partir de la dirección MAC."""
    oui_database = {
        '00:1A:2B': 'Apple',
        '00:1B:44': 'Cisco',
        '00:1C:BF': 'Intel',
        '00:1D:A1': 'Samsung',
        '00:1E:67': 'Sony',
        '00:1F:16': 'Microsoft',
        # Agrega más fabricantes según sea necesario.
    }
    
    prefix = mac.upper()[:8]
    return oui_database.get(prefix, 'Desconocido')

def detectar_sistema_operativo(ip):
    """Detecta el sistema operativo basado en el TTL."""
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, verbose=False)
        
        for _, r in ans:
            ttl = r[IP].ttl
            
            if ttl <= 64:
                return "Linux/Unix"
            elif ttl <= 128:
                return "Windows"
            else:
                return "Desconocido"
    
    except Exception as e:
        print(f"Error al detectar SO para {ip}: {e}")
        return "Desconocido"

def dispositivos_conectados():
    """Detecta dispositivos conectados a la red local."""
    ip_range = f"{obtener_ip_privada()[:-1]}0/24"
    
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    
    packet = ether/arp
    result = srp(packet, timeout=3, verbose=False)[0]
    
    dispositivos = []
    
    for _, received in result:
        ip = received.psrc
        mac = received.hwsrc
        fabricante = obtener_fabricante(mac)
        so = detectar_sistema_operativo(ip)
        
        try:
            nombre = socket.gethostbyaddr(ip)[0]
        except socket.herror:
            nombre = "Desconocido"
        
        dispositivos.append({'ip': ip, 'mac': mac, 'fabricante': fabricante, 'so': so, 'nombre': nombre})
    
    return dispositivos

def detectar_dispositivo(ip):
   """Detecta información de un dispositivo específico."""
   try:
       ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, verbose=False)
       
       for _, r in ans:
           mac = r[Ether].src
           fabricante = obtener_fabricante(mac)
           so = detectar_sistema_operativo(ip)
           
           try:
               nombre = socket.gethostbyaddr(ip)[0]
           except socket.herror:
               nombre = "Desconocido"
           
           return {'ip': ip, 'mac': mac, 'fabricante': fabricante, 'so': so, 'nombre': nombre}
   except Exception as e:
       print(f"Error al detectar dispositivo {ip}: {e}")
       return None

# Funciones para la interfaz gráfica
def mostrar_ip():
   """Muestra la IP privada y pública en el área de texto."""
   output.insert(tk.END, f"IP Privada: {obtener_ip_privada()}\n")
   output.insert(tk.END, f"IP Pública: {obtener_ip_publica()}\n")

def mostrar_conexion():
   """Muestra el estado de la conexión a Internet."""
   if comprobar_conexion():
       output.insert(tk.END, "Conexión a Internet: Conectado\n")
   else:
       output.insert(tk.END, "Conexión a Internet: No conectado\n")

def escanear_puertos():
   """Escanea los puertos abiertos y muestra los resultados en el área de texto."""
   output.insert(tk.END, "Escaneando puertos abiertos en localhost...\n")
   ip = obtener_ip_privada()
   open_ports = puertos_abiertos(ip)
   
   for port, protocolo in open_ports:
       output.insert(tk.END, f"Puerto {port} está abierto (Protocolo: {protocolo})\n")

def detectar_dispositivos():
   """Detecta dispositivos conectados a la red local y muestra los resultados en el área de texto."""
   output.insert(tk.END, "Detectando dispositivos conectados a la red local...\n")
   dispositivos = dispositivos_conectados()
   output.insert(tk.END, "Dispositivos conectados:\n")
   
   for dispositivo in dispositivos:
       output.insert(tk.END,
                     f"Nombre: {dispositivo['nombre']}, IP: {dispositivo['ip']}, "
                     f"MAC: {dispositivo['mac']}, Fabricante: {dispositivo['fabricante']}, "
                     f"SO: {dispositivo['so']}\n")

def escanear_ip():
   """Escanea una dirección IP específica y muestra la información en el área de texto."""
   ip = ip_entry.get()
   dispositivo = detectar_dispositivo(ip)
   
   if dispositivo:
       output.insert(tk.END,
                     f"Información del dispositivo ({ip}):\n"
                     f"Nombre: {dispositivo['nombre']}, IP: {dispositivo['ip']}, "
                     f"MAC: {dispositivo['mac']}, Fabricante: {dispositivo['fabricante']}, "
                     f"SO: {dispositivo['so']}\n")
       
       # Escanear puertos de la IP específica
       output.insert(tk.END, f"Escaneando puertos abiertos en {ip}...\n")
       open_ports = puertos_abiertos(ip)
       
       for port, protocolo in open_ports:
           output.insert(tk.END,
                         f"Puerto {port} está abierto (Protocolo: {protocolo})\n")
   else:
       output.insert(tk.END,
                     f"No se pudo detectar el dispositivo en la IP {ip}\n")

def hacer_ping():
   """Hace ping a servidores comunes y muestra el tiempo de respuesta."""
   servidores = [
       "8.8.8.8", # Google DNS
       "1.1.1.1", # Cloudflare DNS
       "9.9.9.9", # Quad9 DNS
       "208.67.222.222", # OpenDNS
       "1.0.0.1", # Cloudflare DNS secundario
   ]
   
   output.insert(tk.END, "Haciendo ping a servidores comunes...\n")
   
   for servidor in servidores:
       host = ping(servidor, count=1, timeout=1)
       
       if host.is_alive:
           output.insert(tk.END,
                         f"Ping a {servidor}: {host.avg_rtt:.2f} ms\n")
       else:
           output.insert(tk.END,
                         f"No se pudo hacer ping a {servidor}\n")

# Crear la ventana principal
root = tk.Tk()
root.title("Estado de la Red")
root.geometry("600x750")
root.configure(bg="#f0f0f0")

# Crear un área de texto para mostrar los resultados
output = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=70, height=25)
output.pack(pady=10)

# Crear botones para cada funcionalidad
button_frame = tk.Frame(root, bg="#f0f0f0")
button_frame.pack(pady=10)

button_ip = tk.Button(button_frame,
                      text="Mostrar IP",
                      command=mostrar_ip,
                      bg="#4CAF50", fg="white", width=15)
button_ip.grid(row=0,column=0,padx=5,pady=5)

button_conexion = tk.Button(button_frame,
                            text="Comprobar Conexión",
                            command=mostrar_conexion,
                            bg="#2196F3", fg="white", width=15)
button_conexion.grid(row=0,column=1,padx=5,pady=5)

button_puertos = tk.Button(button_frame,
                           text="Escanear Puertos",
                           command=escanear_puertos,
                           bg="#FF9800", fg="white", width=15)
button_puertos.grid(row=1,column=0,padx=5,pady=5)

button_dispositivos = tk.Button(button_frame,
                                 text="Detectar Dispositivos",
                                 command=detectar_dispositivos,
                                 bg="#9C27B0", fg="white", width=15)
button_dispositivos.grid(row=1,column=1,padx=5,pady=5)

button_ping = tk.Button(button_frame,
                        text="Hacer Ping",
                        command=hacer_ping,
                        bg="#E91E63", fg="white", width=15)
button_ping.grid(row=2,column=0,padx=5,pady=5)

# Crear campo de texto y botón para escanear IP específica
ip_frame = tk.Frame(root,bg="#f0f0f0")
ip_frame.pack(pady=10)

ip_label=tk.Label(ip_frame,text="Escanear IP:",bg="#f0f0f0")
ip_label.grid(row=0,column=0,padx=5)

ip_entry=tk.Entry(ip_frame)
ip_entry.grid(row=0,column=1,padx=5)

button_escanear_ip=tk.Button(ip_frame,
                              text="Escanear",
                              command=escanear_ip,
                              bg="#E91E63", fg="white", width=10)
button_escanear_ip.grid(row=0,column=2,padx=5)

# Ejecutar la aplicación
root.mainloop()