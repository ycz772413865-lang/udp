import socket
import random
import datetime
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
LOG_FILE = SCRIPT_DIR / 'run_log_udp_server.txt'

def log_event(role, event):
    with open(LOG_FILE, 'a', encoding='utf-8') as f:
        f.write(f"{datetime.datetime.now().isoformat()} [{role}] {event}\n")

def main():
    host = '0.0.0.0'
    port = 12346
    
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind((host, port))
    
    drop_rate = 0.3
    print(f"UDP服务端已启动，监听端口 {port}")
    print(f"丢包率设置为 {drop_rate * 100}%")
    log_event('UDP_SERVER', f"start port={port} drop_rate={drop_rate}")
    
    expected_seqs = {}  # map client addr -> expected seq
    
    while True:
        data, addr = server.recvfrom(1024)
        
        if len(data) < 8:
            continue
        
        seq_num = int.from_bytes(data[0:4], 'big')
        type_field = int.from_bytes(data[4:8], 'big')
        # ensure per-client expected sequence number
        client_key = addr
        if client_key not in expected_seqs:
            expected_seqs[client_key] = 0

        if type_field == 1:
            if len(data) < 10:
                print(f"{addr} 收到SYN报文，但报文长度不足，忽略")
                log_event('UDP_SERVER', f"recv SYN invalid len={len(data)} from {addr}")
                continue
            student_id = int.from_bytes(data[8:10], 'big')
            original = student_id ^ 0x5A3C
            if original < 0 or original > 9999:
                print(f"{addr} 收到SYN报文，StudentID 校验失败：received={student_id}, decoded={original}，拒绝连接")
                log_event('UDP_SERVER', f"recv SYN invalid student_id={student_id} decoded={original} from {addr}")
                continue
            log_event('UDP_SERVER', f"recv SYN seq={seq_num} student_id={student_id} decoded={original} from {addr}")
            if random.random() < drop_rate:
                print(f"[丢包] {addr} 收到SYN报文，seq={seq_num}，已丢弃")
                log_event('UDP_SERVER', f"drop SYN seq={seq_num} from {addr}")
                continue

            # initialize expected seq for this client
            expected_seqs[client_key] = 0
            time_bytes = datetime.datetime.now().strftime('%H-%M-%S').encode('ascii')
            syn_ack = seq_num.to_bytes(4, 'big') + (2).to_bytes(4, 'big') + time_bytes
            server.sendto(syn_ack, addr)
            log_event('UDP_SERVER', f"send SYN-ACK seq={seq_num} time={time_bytes.decode('ascii')} to {addr}")
            print(f"{addr} 收到SYN报文，seq={seq_num}，已回复SYN-ACK")

        elif type_field == 3:
            log_event('UDP_SERVER', f"recv DATA seq={seq_num} from {addr}")
            if random.random() < drop_rate:
                print(f"[丢包] {addr} 收到数据报文，seq={seq_num}，已丢弃")
                log_event('UDP_SERVER', f"drop DATA seq={seq_num} from {addr}")
                continue

            expected = expected_seqs.get(client_key, 0)
            if seq_num == expected:
                time_bytes = datetime.datetime.now().strftime('%H-%M-%S').encode('ascii')
                ack = (seq_num + 1).to_bytes(4, 'big') + (4).to_bytes(4, 'big') + time_bytes
                server.sendto(ack, addr)
                expected_seqs[client_key] = expected + 1
                log_event('UDP_SERVER', f"send ACK ack={seq_num+1} time={time_bytes.decode('ascii')} to {addr}")
                print(f"{addr} 收到数据报文，seq={seq_num}，已回复ACK time={time_bytes.decode('ascii')}")
            else:
                time_bytes = datetime.datetime.now().strftime('%H-%M-%S').encode('ascii')
                ack = expected.to_bytes(4, 'big') + (4).to_bytes(4, 'big') + time_bytes
                server.sendto(ack, addr)
                log_event('UDP_SERVER', f"send ACK ack={expected} time={time_bytes.decode('ascii')} to {addr} (retransmit)")
                print(f"{addr} 收到重复/乱序报文，seq={seq_num}，期望seq={expected}，重发ACK time={time_bytes.decode('ascii')}")

        elif type_field == 5:
            print(f"{addr} 收到FIN报文，seq={seq_num}")
            log_event('UDP_SERVER', f"recv FIN seq={seq_num} from {addr}")
            time_bytes = datetime.datetime.now().strftime('%H-%M-%S').encode('ascii')
            fin_ack = (seq_num + 1).to_bytes(4, 'big') + (6).to_bytes(4, 'big') + time_bytes
            server.sendto(fin_ack, addr)
            log_event('UDP_SERVER', f"send FIN-ACK seq={seq_num+1} time={time_bytes.decode('ascii')} to {addr}")
            # 清理客户端状态
            if client_key in expected_seqs:
                del expected_seqs[client_key]
            print(f"{addr} 已回复FIN-ACK，并清除状态")

if __name__ == "__main__":
    main()