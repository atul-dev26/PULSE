import socket
import sys
import time

def send_syslog():
    # Target ULPF's background UDP listener running alongside FastAPI
    TARGET_IP = "127.0.0.1"
    TARGET_PORT = 5514
    
    # Real RFC3164 Syslog message format 
    # Example: <34>Oct 11 22:14:15 firewall kernel: DROP TCP 192.168.1.100 -> 10.0.0.5:80
    syslog_msg = "<34>Oct 11 22:14:15 myfirewall kernel: DROP TCP 192.168.1.100 -> 10.0.0.5:80"
    
    print(f"[*] Simulating real firewall transmission...")
    print(f"[*] Sending raw UDP Syslog message to {TARGET_IP}:{TARGET_PORT}")
    print(f"[*] Payload: {syslog_msg}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    try:
        sock.sendto(syslog_msg.encode('utf-8'), (TARGET_IP, TARGET_PORT))
        print("[+] Message sent successfully.")
    except Exception as e:
        print(f"[-] Failed to send message: {e}")
        sys.exit(1)
    finally:
        sock.close()

if __name__ == "__main__":
    send_syslog()
