import socket
import subprocess
import time
import re
import platform
from django.shortcuts import render
from django.http import StreamingHttpResponse

# --- UTILITÁRIOS ---

def check_port(ip, port, timeout=1):
    """
    Versão aprimorada com medição de tempo de alta precisão.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        # Início da medição de precisão
        start = time.perf_counter()
        result = sock.connect_ex((ip, int(port)))
        end = time.perf_counter()
        
        sock.close()
        # Retorna o resultado e o tempo em milissegundos
        latency = round((end - start) * 1000, 2)
        return result == 0, latency
    except:
        return False, 0

def get_route_fast(ip):
    if platform.system().lower() == 'windows':
        cmd = f"tracert -d -h 15 -w 200 {ip}" # -w 200 acelera se houver perda
    else:
        cmd = f"traceroute -n -m 15 -w 1 {ip}"

    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)
        output, _ = process.communicate(timeout=20)
        lines = output.splitlines()
        
        hops = []
        for line in lines:
            # Ignora a linha de cabeçalho que contém o IP de destino
            if "Rastreando" in line or "Tracing" in line or not line.strip():
                continue
            
            # Captura o IP apenas se a linha começar com um número (o número do salto)
            # Isso evita pegar o IP do cabeçalho
            match_hop_num = re.search(r'^\s*(\d+)', line)
            if match_hop_num:
                match_ip = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                if match_ip:
                    ip_found = match_ip.group(1)
                    if ip_found not in hops:
                        hops.append(ip_found)
                else:
                    # Se houver o número do salto mas não o IP (* * *), marca como desconhecido
                    hops.append(f"Unknown-{len(hops)+1}")
        
        # Garante que o IP de destino esteja no final se o tracert falhar em listar tudo
        if ip not in hops:
            hops.append(ip)
            
        return hops
    except Exception:
        return [ip]
    
# --- GERADORES (STREAMING) ---

def tcp_ping_generator(ip, port):
    yield f"--- Iniciando Ping TCP em {ip}:{port} ---\n\n"
    for i in range(1, 21):
        # A função check_port agora já retorna a latência medida internamente
        success, ms = check_port(ip, port)
        
        status = "ABERTA" if success else "FALHA/TIMEOUT"
        yield f"Seq {i}: Resposta de {ip} | Status={status} | Tempo={ms}ms\n"
        time.sleep(0.5)
    yield "\n--- Teste Concluído ---"

def check_node_life(ip, timeout=400):
    """
    Usa o comando PING do sistema para medir a latência real.
    Retorna (is_alive, ms)
    """
    # Define o parâmetro de contagem baseado no SO
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    # Define o timeout (no Windows é em ms, no Linux em segundos)
    timeout_param = '-w' if platform.system().lower() == 'windows' else '-W'
    
    cmd = ['ping', param, '1', timeout_param, str(timeout), ip]
    
    start = time.time()
    try:
        # Executa silenciosamente
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, shell=True)
        ms = int((time.time() - start) * 1000)
        
        # Tenta extrair o tempo real do output do ping se quiser precisão absoluta
        match = re.search(r"tempo[=<](\d+)ms|time[=<](\d+)", output)
        if match:
            ms = int(match.group(1) or match.group(2))
            
        return True, ms
    except Exception:
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
    user_ip = request.META.get('HTTP_X_FORWARDED_FOR', request.META.get('REMOTE_ADDR')).split(',')[0]
    
    if request.method == "POST":
        target_ip = request.POST.get('ip')
        target_port = request.POST.get('port', 80)
        test_type = request.POST.get('test_type')

        if test_type == "ping_tcp":
            return StreamingHttpResponse(tcp_ping_generator(target_ip, target_port), content_type='text/plain')
        
        if test_type == "mtr":
            return StreamingHttpResponse(mtr_generator(target_ip), content_type='text/plain')

        # Porta Única (Síncrono)
        status = "Aberta" if check_port(target_ip, target_port) else "Fechada ou Filtrada"
        return render(request, 'scanner.html', {
            'status': status, 'ip': target_ip, 'port': target_port, 'user_ip': user_ip, 'test_type': 'port'
        })

    return render(request, 'scanner.html', {'user_ip': user_ip, 'test_type': 'port'})