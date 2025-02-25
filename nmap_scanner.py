import nmap


def hosts_scan(network):
    """
    Realiza un escaneo de hosts usando nmap y nos devuelve un JSON con todos los datos
    """
    
    #nm = nmap.PortScanner()
    nm = nmap.PortScanner(nmap_search_path=('C:/Program Files (x86)/Nmap/nmap.exe',))

    nm.scan(hosts=network, arguments='-sn')
    #print('Comando nmap: ', nm.command_line())
    
    #Salida completa de nmap
    #for host in nm.all_hosts():
        #print(f'{host}: {nm[host]}')
    
    #Comprobamos que los hosts que nos devuelve están todos activos
    active_hosts = [host for host in nm.all_hosts() if nm[host]['status']['state'] == 'up']
    #Explicación del comprehension list de arriba: Para cada host dentro de nm.all_host, en el caso de que para ese host su estado sea 'up'(activo), entonces concatenalo a la lista active_hosts
    return print('Host activos en la Red'),active_hosts
    
def service_scan(network):
    """
    Escanea los puertos y los servicios que se están ejecutando con su correspondiente versión. Después procesa los resultados.
    """
    nm = nmap.PortScanner()
    nm.scan(hosts=network, arguments='-sV')
    #Diccionario donde guardar todos los resultados que nos devuelve nmap
    network_data = {}
    #Recorrer/iterar todos los hosts que haya identificado y todos los puertos que estén abiertos y su servicio ejecutandose.
    for host in nm.all_hosts():
        #if nm[host]['status']['state'] == 'up':
        if nm[host].state() == 'up':
            network_data[host] = {} #Ek diccionario va a recibir tanto los servicios y puertos como las versiones
            for proto in nm[host].all_protocols():
                network_data[host][proto] = {}
                ports = nm[host][proto].keys()
                for port in ports:
                    service = nm[host][proto][port]['name']
                    version =nm[host][proto][port]['product'] + ' ' + nm[host][proto][port]['version']
                    network_data[host][proto][port] = {'service': service , 'version': version}
    return network_data              
                    
                    
                
            
    
    





if __name__ == '__main__':
    
    #hosts_activos = hosts_scan('192.168.1.0/24')
    #if not hosts_activos:
        #print('No Se encontraron Hosts en la red')
    #else:
        #print(hosts_activos)
        
        
    servicios_activos= service_scan('192.168.1.0/24')
    if servicios_activos:
        print(servicios_activos)
    
    

    
