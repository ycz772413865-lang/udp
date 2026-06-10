import socket
import sys
import time
import threading
import datetime
from pathlib import Path
import pandas as pd
import portalocker
# math 未使用

SCRIPT_DIR = Path(__file__).resolve().parent
LOG_FILE = SCRIPT_DIR / 'run_log.txt'

def log_event(role, event):
    with open(LOG_FILE, 'a', encoding='utf-8') as f:
        portalocker.lock(f, portalocker.LOCK_EX)
        f.write(f"{datetime.datetime.now().isoformat()} [{role}] {event}\n")
        f.flush()
        portalocker.unlock(f)

class UDPClient:
    def __init__(self, server_ip, server_port):
        self.server_ip = server_ip
        self.server_port = server_port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(0.3)
        
        self.WINDOW_SIZE = 5
        self.PACKET_SIZE = 80
        self.TIMEOUT = 0.3
        self.CONNECT_RETRIES = 5
        self.FIN_RETRIES = 5
        
        self.base = 0
        self.next_seq = 0
        self.packets = []
        self.ack_received = []
        self.rtt_list = []
        self.send_count = 0
        self.total_packets = 0
        
        self.lock = threading.Lock()
        self.condition = threading.Condition(self.lock)
        self.running = True
    
    def connect(self):
        print("开始TCP三次握手模拟...", flush=True)
        student_number = 2111
        student_id = (student_number ^ 0x5A3C).to_bytes(2, 'big')
        syn = (0).to_bytes(4, 'big') + (1).to_bytes(4, 'big') + student_id
        self.sock.sendto(syn, (self.server_ip, self.server_port))
        log_event('UDP_CLIENT', f"send SYN seq=0 student_id={int.from_bytes(student_id, 'big')}")
        retries = 0
        while retries < self.CONNECT_RETRIES:
            try:
                data, _ = self.sock.recvfrom(1024)
                if len(data) >= 8:
                    seq = int.from_bytes(data[0:4], 'big')
                    type_field = int.from_bytes(data[4:8], 'big')
                    if type_field == 2:
                        print("收到SYN-ACK")
                        log_event('UDP_CLIENT', f"recv SYN-ACK seq={seq}")
                        ack = (seq + 1).to_bytes(4, 'big') + (4).to_bytes(4, 'big')
                        self.sock.sendto(ack, (self.server_ip, self.server_port))
                        log_event('UDP_CLIENT', f"send ACK seq={seq+1}")
                        print("发送ACK，连接建立成功", flush=True)
                        return True
            except socket.timeout:
                retries += 1
                print(f"SYN超时，重传... (第{retries}次)")
                log_event('UDP_CLIENT', f"timeout SYN retransmit attempt={retries}")
                try:
                    self.sock.sendto(syn, (self.server_ip, self.server_port))
                    log_event('UDP_CLIENT', f"retransmit SYN seq=0 attempt={retries}")
                except Exception:
                    pass

        print("握手失败：重试次数达到上限")
        return False
    
    def disconnect(self):
        print("开始断开连接...")
        # 停止接收线程，避免与 FIN 收发产生竞态
        self.running = False
        if hasattr(self, 'recv_thread') and self.recv_thread.is_alive():
            self.recv_thread.join(timeout=0.5)

        fin = (self.next_seq).to_bytes(4, 'big') + (5).to_bytes(4, 'big')
        log_event('UDP_CLIENT', f"send FIN seq={self.next_seq}")
        retries = 0
        try:
            self.sock.sendto(fin, (self.server_ip, self.server_port))
        except Exception:
            pass

        while retries < self.FIN_RETRIES:
            try:
                data, _ = self.sock.recvfrom(1024)
                if len(data) >= 8:
                    type_field = int.from_bytes(data[4:8], 'big')
                    if type_field == 6:
                        print("收到FIN-ACK，连接已断开")
                        self.running = False
                        return
            except socket.timeout:
                retries += 1
                print(f"FIN超时，重传... (第{retries}次)")
                log_event('UDP_CLIENT', f"timeout FIN retransmit attempt={retries}")
                try:
                    self.sock.sendto(fin, (self.server_ip, self.server_port))
                    log_event('UDP_CLIENT', f"retransmit FIN seq={self.next_seq} attempt={retries}")
                except Exception:
                    pass

        print("断开连接失败：重试次数达到上限")
        self.running = False

    def read_file(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            self.packets = []
            offset = 0
            while offset < len(content):
                end = min(offset + self.PACKET_SIZE, len(content))
                self.packets.append({
                    'data': content[offset:end],
                    'offset': offset,
                    'end': end,
                    'sent_time': None,
                    'rtt': None
                })
                offset = end
            
            self.total_packets = len(self.packets)
            self.ack_received = [False] * self.total_packets
            print(f"文件已读取，共 {self.total_packets} 个数据包", flush=True)
        except FileNotFoundError:
            print(f"错误：文件 {file_path} 不存在")
            sys.exit(1)
    
    def send_packet(self, seq_num):
        if seq_num >= self.total_packets:
            return
        
        packet = self.packets[seq_num]
        header = seq_num.to_bytes(4, 'big') + (3).to_bytes(4, 'big')
        data = header + packet['data']
        
        # 不在此处再次获取 self.lock，避免与调用方（持锁）产生死锁
        packet['sent_time'] = time.time()
        self.send_count += 1
        try:
            self.sock.sendto(data, (self.server_ip, self.server_port))
            log_event('UDP_CLIENT', f"send DATA seq={seq_num} len={len(packet['data'])}")
        except Exception as e:
            print(f"发送报文错误: {e}", flush=True)
            log_event('UDP_CLIENT', f"send DATA error seq={seq_num} error={e}")
            return
        print(f"第{seq_num+1}个（第{packet['offset']}~{packet['end']}字节）客户端已经发送", flush=True)
    
    def recv_handler(self):
        while self.running:
            try:
                data, _ = self.sock.recvfrom(1024)
                if len(data) >= 8:
                    ack_num = int.from_bytes(data[0:4], 'big')
                    type_field = int.from_bytes(data[4:8], 'big')
                    
                    if type_field == 4:
                        # parse optional server time appended after header (8 bytes header + 8 bytes time)
                        server_time = None
                        if len(data) >= 16:
                            try:
                                server_time = data[8:16].decode('ascii')
                            except Exception:
                                server_time = None
                        log_event('UDP_CLIENT', f"recv ACK ack_num={ack_num} server_time={server_time}")
                        with self.lock:
                            if ack_num > self.base and ack_num <= self.total_packets:
                                for i in range(self.base, ack_num):
                                    if not self.ack_received[i]:
                                        self.ack_received[i] = True
                                        if self.packets[i]['sent_time']:
                                            rtt = (time.time() - self.packets[i]['sent_time']) * 1000
                                            self.packets[i]['rtt'] = rtt
                                            self.rtt_list.append(rtt)
                                            if server_time:
                                                print(f"第{i+1}个（第{self.packets[i]['offset']}~{self.packets[i]['end']}字节）server端已经收到，RTT是{rtt:.2f} ms server_time={server_time}")
                                            else:
                                                print(f"第{i+1}个（第{self.packets[i]['offset']}~{self.packets[i]['end']}字节）server端已经收到，RTT是{rtt:.2f} ms")
                                self.base = ack_num
                                self.condition.notify_all()
                                
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    print(f"接收线程错误: {e}")
                    log_event('UDP_CLIENT', f"recv error {e}")
    
    def run(self):
        self.recv_thread = threading.Thread(target=self.recv_handler)
        self.recv_thread.start()
        print("recv线程已启动，准备发送数据...", flush=True)
        while self.base < self.total_packets:
            with self.lock:
                # 发送窗口内的新报文
                while self.next_seq < min(self.base + self.WINDOW_SIZE, self.total_packets):
                    self.send_packet(self.next_seq)
                    self.next_seq += 1
                old_base = self.base
                # 等待 ACK 或超时
                self.condition.wait(self.TIMEOUT)
                # 如果在超时等待期间 base 没有推进，则进行重传
                if self.base == old_base:
                    print(f"超时重传：重传窗口内未确认的数据包 (base={self.base})")
                    log_event('UDP_CLIENT', f"timeout data retransmit base={self.base} next_seq={self.next_seq}")
                    for i in range(self.base, min(self.next_seq, self.total_packets)):
                        if not self.ack_received[i]:
                            print(f"重传第{i+1}个（第{self.packets[i]['offset']}~{self.packets[i]['end']}字节）数据包")
                            self.send_packet(i)
        df = pd.DataFrame({'rtt': self.rtt_list})
        
        if self.send_count == 0:
            loss_rate = 0.0
        else:
            loss_rate = (self.send_count - self.total_packets) / self.send_count * 100
        max_rtt = df['rtt'].max()
        min_rtt = df['rtt'].min()
        avg_rtt = df['rtt'].mean()
        std_rtt = df['rtt'].std()
        
        print("\n===== 数据统计 =====")
        print(f"丢包率: {loss_rate:.2f}%")
        print(f"实际发送报文总数: {self.send_count}")
        print(f"RTT最大值: {max_rtt:.2f} ms")
        print(f"RTT最小值: {min_rtt:.2f} ms")
        print(f"平均RTT: {avg_rtt:.2f} ms")
        print(f"RTT标准差: {std_rtt:.2f} ms")
        print("====================")

def main():
    if len(sys.argv) != 3:
        print("Usage: python udp_client.py <server_ip> <server_port>")
        sys.exit(1)
    
    server_ip = sys.argv[1]
    server_port = int(sys.argv[2])
    
    client = UDPClient(server_ip, server_port)
    
    if client.connect():
        client.read_file('test.txt')
        client.run()
        client.disconnect()
    
    client.sock.close()

if __name__ == "__main__":
    main()