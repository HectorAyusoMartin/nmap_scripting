nmap_scanner.py | Cyber Scripting | IA data process


===Descripción===


        Pequeño script para realizar analisis de puertos usando la libreria python-nmap. Integrar NMAP con Python tiene sentido cuando hacemos un escaner que devuelve mucha información.
        Para procesar la información, este Script hace uso de un algoritmo de Inteligencia Artifical para elaborar el proceso.





===Ejemplo de uso de la libreria Python-Nmap===

        1- Importamos nmap.
        2- Definimos un cliente.    nm=nmap.PortScanner().
        3- Definimos el segmento de red a escanear, y las opciones de escaneo. Guardamos los resultados en una var.  resultados=nm.scan(hosts="192.1681.0/24", arguments="-sn").
        4- Los resultados en la variable se encuentran en formarto JSON.
        5- En la variable nm(instancia de clase) tenemos estos mismos resultados en estreucturas de Python que podemos acceder.
        6- Para obtener con nm, por ejemplo, todos los hosts que el escanner detectó: nm.all_hosts().
        7- Todo los métodos disponibles para el objeto nm:   dir(nm)
        

===Funciones dentro de nmap_scanner.py===

        1- hosts_scan() --> Escanea todos los host que se encuentren activos dentro de la red(network) porporcionada como argumento. Utiliza una bandera -sn
        2- service_scan()  --> Escanea los puertos de los hosts encontrados, y proporciona información sobre que servicios corren en ellos y su versión. 
                               Se procesa toda la información recibida haciendo uso de un algortimo de Inteligencia Artifical.





