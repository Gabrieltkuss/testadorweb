import socket
import subprocess
import time
import re
import platform
from django.shortcuts import render
from django.http import StreamingHttpResponse

# --- UTILITÁRIOS ---

def check_port(ip, port, timeout=1):
    try:
        # Trava de Segurança: Converte e valida o range real de portas TCP
        port_int = int(port)
        if not (1 <= port_int <= 65535):
            return False, 0
            
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        start = time.perf_counter()
        # connect() é necessário para medir RTT real (handshake completo)
        sock.connect((ip, port_int))
        end = time.perf_counter()
        
        sock.close()
        latency = (end - start) * 1000
        return True, round(latency, 2)
    except:
        return False, 0

def tcp_ping_generator(ip, port):
    try:
        p_int = int(port)
        if not (1 <= p_int <= 65535):
            yield f"Erro: Porta {port} fora do limite (1-65535).\n"
            return
    except:
        yield "Erro: Porta inválida.\n"
        return

    yield f"--- Iniciando Ping TCP em {ip}:{p_int} ---\n\n"
    for i in range(1, 21):
        success, ms = check_port(ip, p_int)
        status = "ABERTA" if success else "FALHA/TIMEOUT"
        yield f"Seq {i}: Resposta de {ip} | Status={status} | Tempo={ms}ms\n"
        time.sleep(0.5)
    yield "\n--- Teste Concluído ---"

def get_route_fast(ip):
    is_windows = platform.system().lower() == 'windows'
    
    if is_windows:
        cmd = f"tracert -d -h 15 -w 200 {ip}"
    else:
        # No Linux, tentamos o traceroute padrão. 
        # Se falhar, o fallback será o próprio IP.
        cmd = f"traceroute -n -m 15 -q 1 -w 1 {ip}"

    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)
        output, _ = process.communicate(timeout=15)
        
        # Regex mais robusta para pegar IPs de cada linha do salto
        hops = []
        lines = output.splitlines()
        for line in lines:
            if any(char.isdigit() for char in line[:3]): # Verifica se a linha começa com o número do salto
                match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                if match:
                    ip_found = match.group(1)
                    if ip_found not in hops:
                        hops.append(ip_found)
                elif "*" in line:
                    hops.append(f"Unknown-{len(hops)+1}")

        if not hops:
            return [ip]
        return hops
    except:
        return [ip]
    
# --- GERADORES (STREAMING) ---

def check_node_life(ip, timeout=400):
    """
    Versão compatível com Linux e Windows para servidores de deploy.
    """
    is_windows = platform.system().lower() == 'windows'
    # No Linux, usamos -W (segundos), no Windows -w (ms)
    t_val = str(timeout) if is_windows else str(max(1, timeout // 1000))
    param = '-n' if is_windows else '-c'
    t_param = '-w' if is_windows else '-W'
    
    cmd = ['ping', param, '1', t_param, t_val, ip]
    
    start = time.perf_counter()
    try:
        # shell=False é mais seguro e rápido em produção
        subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
        ms = (time.perf_counter() - start) * 1000
        return True, int(ms)
    except:
        return False, 0
    
def mtr_generator(target_ip):
    hops = get_route_fast(target_ip)
    if not hops:
        yield "Erro: Destino inalcançável."
        return

    stats = {ip: [0, 0, 9999, 0, 0] for ip in hops}
    
    # Cabeçalho com larguras fixas para alinhamento perfeito
    header = f"{'Hostname (IP)':<20} | {'Loss%':>5} | {'Sent':>5} | {'Recv':>5} | {'Best':>5} | {'Avrg':>5} | {'Wrst':>5}\n"
    separator = "-" * 75 + "\n"

    for _ in range(500):
        # O caractere \x1b[H ajuda o frontend a identificar o início do bloco
        output = "\x1b[H" + header + separator
        
        for ip in hops:
            stats[ip][0] += 1 # Sent
            is_alive, ms = (False, 0) if "Unknown" in ip else check_node_life(ip)
            
            if is_alive:
                stats[ip][1] += 1
                stats[ip][4] += ms
                if ms < stats[ip][2]: stats[ip][2] = ms
                if ms > stats[ip][3]: stats[ip][3] = ms
            
            sent, recv = stats[ip][0], stats[ip][1]
            loss_pct = int(((sent - recv) / sent) * 100)
            avrg = int(stats[ip][4] / recv) if recv > 0 else 0
            best = stats[ip][2] if recv > 0 else 0
            worst = stats[ip][3] if recv > 0 else 0
            
            name = "No response" if "Unknown" in ip else ip
            
            # Formatação com preenchimento (:< esquerda, :> direita)
            output += f"{name:<20} | {str(loss_pct)+'%':>5} | {sent:>5} | {recv:>5} | {best:>5} | {avrg:>5} | {worst:>5}\n"
        
        yield output
        time.sleep(0.5)
                    
# --- VIEW PRINCIPAL ---

def port_scanner(request):
    # Lógica de POST idêntica, chamando as funções validadas acima
    user_ip = request.META.get('HTTP_X_FORWARDED_FOR', request.META.get('REMOTE_ADDR')).split(',')[0]
    if request.method == "POST":
        target_ip = request.POST.get('ip')
        target_port = request.POST.get('port', 80)
        test_type = request.POST.get('test_type')
        if test_type == "ping_tcp":
            return StreamingHttpResponse(tcp_ping_generator(target_ip, target_port), content_type='text/plain')
        if test_type == "mtr":
            return StreamingHttpResponse(mtr_generator(target_ip), content_type='text/plain')
        
        # Teste Único: Valida antes de renderizar
        success, _ = check_port(target_ip, target_port)
        status = "Aberta" if success else "Fechada ou Filtrada"
        return render(request, 'scanner.html', {'status': status, 'ip': target_ip, 'port': target_port, 'user_ip': user_ip})
    return render(request, 'scanner.html', {'user_ip': user_ip})