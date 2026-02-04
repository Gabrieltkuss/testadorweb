from django.shortcuts import render
import socket

def check_port(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    result = sock.connect_ex((ip, int(port)))
    sock.close()
    return result == 0

def port_scanner(request):
    status = None
    target_ip = ""
    target_port = ""

    # Captura o IP do usuário
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        user_ip = x_forwarded_for.split(',')[0]
    else:
        user_ip = request.META.get('REMOTE_ADDR')

    if request.method == "POST":
        target_ip = request.POST.get('ip')
        target_port = request.POST.get('port')
        
        if check_port(target_ip, target_port):
            status = "Aberta"
        else:
            status = "Fechada ou Filtrada"

    return render(request, 'scanner.html', {
        'status': status, 
        'ip': target_ip, 
        'port': target_port,
        'user_ip': user_ip  # Enviando o IP para o HTML
    })