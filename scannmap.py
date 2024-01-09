import os
import ctypes
import re
import nmap

def definir_objetivos():
    ip_objetivo = "127.0.0.1"
    puertos_objetivo = "1-1024"
    return ip_objetivo, puertos_objetivo

def nmap_scan(ip, puertos):
    scanner = nmap.PortScanner()
    resultado = scanner.scan(ip, arguments=f'-p {puertos} --open -sV -Pn')
    return resultado['scan'][ip]['tcp']

def analizar_registros():
    print("[*] Analizando registros del sistema en Windows...")

    ruta_logs = os.path.join(os.environ['SystemRoot'], 'System32', 'Winevt', 'Logs', 'Security.evtx')

    try:
        if not os.path.exists(ruta_logs):
          raise FileNotFoundError(f"El archivo de registros {ruta_logs} no existe.")
        
        palabras_clave = ["ataque", "intrusión", "seguridad comprometida", "acceso no autorizado",
                          "ataque de red", "malware", "denegación de servicio", "cuenta comprometida"]
        
        patron_evento = re.compile(fr'.*?({"|".join(palabras_clave)}).*?', re.IGNORECASE)

        amenaza_detectada = False

        with open(ruta_logs, 'r', encoding='utf-8', errors='ignore') as logfile:
            for line in logfile:
                if patron_evento.search(line):
                    notificar_alertas("Se ha detectado un posible ataque en los registros.")
                    amenaza_detectada = True
                    break 

        if not amenaza_detectada:
            print("[*] No se encontraron amenazas en los registros del sistema.")

    except FileNotFoundError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"Error al analizar registros: {e}")

def notificar_alertas(mensaje):
    ctypes.windll.user32.MessageBoxW(0, mensaje, "Alerta de Seguridad", 1)

def mostrar_resultados_nmap(resultado_nmap):
    print("[+] Resultados del escaneo de nmap:")
    for puerto, info in resultado_nmap.items():
        print(f"Puerto {puerto}: Estado {info['state']} - Servicio {info['name']} - Versión {info['version']}")

def main():
    try:
        ip_objetivo, puertos_objetivo = definir_objetivos()

        print(f"[*] Escaneando puertos en {ip_objetivo}...")
        resultado_nmap = nmap_scan(ip_objetivo, puertos_objetivo)

        mostrar_resultados_nmap(resultado_nmap)

        analizar_registros()

    except KeyboardInterrupt:
        print("\n[*] Escaneo interrumpido por el usuario.")
    except Exception as e:
        print(f"Error general: {e}")

if __name__ == "__main__":
    main()

