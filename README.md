# DesafioScapy
Este proyecto intenta simular un ataque DoS simple.

Para esto se realiza:

1. Un escaneo de la red interna para detectar IPs disponibles(rango acotado de IPs)
2. A cada IP encontrada se realiza un escaneo de puerto, para determinar si están disponibles. Los puertos
   consultados son el 80, 8080 y 8100 (puertos por defecto para IIS, Apache tomcat y Wildfly) 
3. A cada puerto disponible se realiza un envío de paquetes para intentar denegar el servicio.
