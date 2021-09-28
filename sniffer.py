import socket
from networking.ethernet import Ethernet
from networking.ipv4 import IPv4
from networking.icmp import ICMP
from networking.tcp import TCP
from networking.udp import UDP
from networking.pcap import Pcap
from networking.http import HTTP
from networking.arp import ARP
import argparse
import time
import sys
from utilities import *

class Sniffer:
    pacotesTotais = 0
    pacotesTCP = 0
    pacotesUDP = 0
    pacotesICMP = 0
    pacotesARP = 0
    pacotesHTTP = 0
    pacotesFTP = 0
    pacotesSMTP = 0
    pacotesHTTPS = 0
    outros = 0
    filtros = {
        'TCP': True,
        'UDP': True,
        'ICMP': True,
        'ARP': True,
        'HTTP': False,
        'FTP': False,
        'SMTP': False,
        'HTTPS': False
    }

    def __init__(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("-man" , default='0'               , help="abrir manual do aplicativo 1: sim, 2: nao")
        parser.add_argument("-s"   , default='1'               , help="salvar pcap 1: sim, 2: nao")
        parser.add_argument("-f"   , default='0'               , help="escolher filtros 1: sim, 2: nao")
        parser.add_argument("-nome", default=self.getDateTime(), help="nome do arquivo pcap a ser salvado")
        args = parser.parse_args()

        self.s = args.s
        self.nome = args.nome
        self.man = args.man
        self.f = args.f

        if self.s == '1':
            self.pcap = Pcap("./Pcaps/%s.pcap" %(self.nome))
        if self.man == '1':
            self.abrirManual()
        if self.f == '1':
            self.escolherFiltros()
        else:
            self.iniciar()

    def iniciar(self):
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        try:
            while True:
                raw_data, addr = conn.recvfrom(65535)
                # print(print(raw_data))
                # print(sys.getsizeof(raw_data))
                self.pacotesTotais += 1
                self.pcap.write(raw_data)
                eth = Ethernet(raw_data)

                print('-' * 90 + '\n', end='\r')

                self.printEthernet(eth)

                # IPv4
                if eth.proto == 8:
                    ipv4 = IPv4(eth.data)
                    self.printIPv4(ipv4)
                    # ICMP
                    if ipv4.proto == 1:
                        self.pacotesICMP += 1
                        icmp = ICMP(ipv4.data)
                        self.printICMP(icmp)
                    # TCP
                    elif ipv4.proto == 6:
                        self.pacotesTCP += 1
                        tcp = TCP(ipv4.data)
                        self.printTCP(tcp)

                    # UDP
                    elif ipv4.proto == 17:
                        self.pacotesUDP += 1
                        udp = UDP(ipv4.data)
                        self.printUDP(udp)

                    # Other IPv4
                    else:
                        self.outros += 1
                        self.printOtherIPv4(ipv4)

                # ARP
                elif eth.proto == 1544:
                    self.pacotesARP += 1
                    arp = ARP(eth.data)
                    self.printARP(arp)

                else:
                    self.outros += 1
                    self.printOutros(eth)

                self.printStats()

        except KeyboardInterrupt:
            self.printFinalStats()
            if self.s == '1':
                self.pcap.close()

    def abrirManual(self):
        print(colorizar('   _______  __    _  _______  ___      ___   _______  _______  ______   _______  ______\n'
                '  |   _   ||  |  | ||   _   ||   |    |   | |       ||   _   ||      | |       ||    _ |  \n'
                '  |  |_|  ||   |_| ||  |_|  ||   |    |   | |  _____||  |_|  ||  _    ||   _   ||   | ||  \n'
                '  |       ||       ||       ||   |    |   | | |_____ |       || | |   ||  | |  ||   |_||_ \n'
                '  |       ||  _    ||       ||   |___ |   | |_____  ||       || |_|   ||  |_|  ||    __  |\n'
                '  |   _   || | |   ||   _   ||       ||   |  _____| ||   _   ||       ||       ||   |  | |\n'
                '  |__| |__||_|  |__||__| |__||_______||___| |_______||__| |__||______| |_______||___|  |_|\n', 'cyan'))
        print(colorizar('Sniffer de pacotes\n', 'grey'))
        print(colorizar('> digite o argumento --help para objer ajuda sobre os argumentos\n', 'white'))
        print(colorizar('Após o inicio da captura de pacotes o software automaticamente\n'
                        'capturará pacotes com bases nos filtros estabelecidos, se o usuário\n'
                        'optar os 4 filtros já são pre-estabelecidos\n'
                        '\n 1. TCP \n 2. UDP \n 3. ICMP \n 4. ARP\n\n'
                        'para começar a captura de pacotes o usuário precisa simplesmente\n'
                        'iniciar o aplicativo, ou iniciar escolhendo a opção disponível após\n'
                        'a seleção de filtros.\n\n'
                        'A captura de filtros pode ser interrompida através de qualquer das\n'
                        'teclas CTRL + C, ou qualquer outro comando de interrupção.\n\n'
                        'Os pacotes serão salvados no caminho Pcaps/.., o nome do arquivo \n'
                        'de Pcap poderá ser modificado utilizando uma das opções de argumentos,\n'
                        'caso o nome não tenha sido escolhido, o sistema autómaticamente \n'
                        'atribuirá o nome do arquivo como sendo o horário atual do sistema.\n', 'magenta'))
        input('Pressione qualquer tecla para sair')
        sys.exit()

    def escolherFiltros(self):
        self.printFiltros()
        while(True):
            op = input('Escolha uma opção: ')
            if (op == '1'):
                self.filtros['TCP'] = True
            elif(op == '2'):
                self.filtros['UDP'] = True
            elif (op == '3'):
                self.filtros['ICMP'] = True
            elif (op == '4'):
                self.filtros['ARP'] = True
            elif (op == '5'):
                self.filtros['HTTP'] = True
            elif (op == '6'):
                self.filtros['HTTPS'] = True
            elif (op == '7'):
                self.filtros['FTP'] = True
            elif (op == '8'):
                self.filtros['SMTP'] = True
            elif (op == '9'):
                break
            self.printFiltros()
        self.iniciar()

    def printFiltros(self):
        caixas = {
            'TCP': '',
            'UDP': '',
            'ICMP': '',
            'ARP': '',
            'HTTP': '',
            'FTP': '',
            'SMTP': '',
            'HTTPS': ''
        }
        for proto in self.filtros:
            if self.filtros[proto] == True:
                caixas[proto] = 'x'
            else:
                caixas[proto] = ' '

        print('\n 1> [{}]TCP \n 2> [{}]UDP \n 3> [{}]ICMP \n 4> [{}]ARP \n 5> [{}]HTTP \n 6> [{}]HTTPS \n 7> [{}]FTP \n 8> [{}]SMTP\n\n 9> INICIAR\n'
              .format(caixas['TCP'], caixas['UDP'], caixas['ICMP'], caixas['ARP'], caixas['HTTP'], caixas['HTTPS'], caixas['FTP'], caixas['SMTP']))

    def printEthernet(self, eth):
        print('|' + colorizar('[ Ethernet ]', 'blue'))
        print(TAB_1 + 'Destino: {}, Origem: {}, Protocolo: {}'.format(eth.dest_mac, eth.src_mac, eth.proto))

    def printIPv4(self, ipv4):
        print(TAB_1 + (colorizar('[ IPv4 ]', 'blue')))
        print(TAB_2 + 'Versão: {}, Tamanho do Cabeçalho: {}, TTL: {},'.format(ipv4.version, ipv4.header_length, ipv4.ttl))
        print(TAB_2 + 'Protocolo: {}, Origem: {}, Destino: {}'.format(ipv4.proto, ipv4.src, ipv4.target))

    def printICMP(self, icmp):
        print(TAB_1 + (colorizar('[ ICMP ]', 'blue')))
        print(TAB_2 + 'Tipo: {}, Código: {}, Soma de Verificação: {},'.format(icmp.type, icmp.code, icmp.checksum))
        print(TAB_2 + 'Dados ICMP:')
        print(format_multi_line(DATA_TAB_3, icmp.data))

    def printTCP(self, tcp):
        print(TAB_1 + (colorizar('[ TCP ]', 'blue')))
        print(TAB_2 + 'Porta de Origem: {}, Porta de Destino: {}'.format(tcp.src_port, tcp.dest_port))
        print(TAB_2 + 'Sequência: {}, Número de ACK: {}'.format(tcp.sequence, tcp.acknowledgment))
        print(TAB_2 + 'Flags:')
        print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}'.format(tcp.flag_urg, tcp.flag_ack, tcp.flag_psh))
        print(TAB_3 + 'RST: {}, SYN: {}, FIN:{}'.format(tcp.flag_rst, tcp.flag_syn, tcp.flag_fin))
        if len(tcp.data) > 0:
            # HTTP
            if tcp.src_port == HTTP_PORTA or tcp.dest_port == HTTP_PORTA:
                self.pacotesHTTP += 1
                print(TAB_2 + 'Dados HTTP:')
                try:
                    http = HTTP(tcp.data)
                    http_info = str(http.data).split('\n')
                    for line in http_info:
                        print(DATA_TAB_3 + str(line))
                except:
                    print(format_multi_line(DATA_TAB_3, tcp.data))
            elif tcp.src_port == HTTPS_PORTA or tcp.dest_port == HTTPS_PORTA:
                self.pacotesHTTPS += 1
                print(TAB_2 + 'Dados HTTPs:')
                print(format_multi_line(DATA_TAB_3, tcp.data))
            # FTP
            elif tcp.src_port in FTP_PORTA or tcp.dest_port in FTP_PORTA:
                self.pacotesFTP += 1
                print(TAB_2 + 'Dados FTP:')
                print(format_multi_line(DATA_TAB_3, tcp.data))

            ###P2P

            else:
                print(TAB_2 + 'Dados TCP:')
                print(format_multi_line(DATA_TAB_3, tcp.data))

    def printUDP(self, udp):
        print(TAB_1 + colorizar('[ UDP ]', 'blue'))
        print(TAB_2 + 'Porta de Origem: {}, Porta de Destino: {}, Tamanho: {}'.format(udp.src_port, udp.dest_port, udp.size))

    def printOtherIPv4(self, ipv4):
        print(TAB_1 + 'Dados:')
        print(format_multi_line(DATA_TAB_2, ipv4.data))

    def printARP(self, arp):
        print(TAB_1 + colorizar('[ ARP ]', 'blue'))
        print(TAB_2 + 'Hardware: {}, Tipo de Protocolo: {}'.format(arp.hardwareType, arp.protocolType))
        print(TAB_2 + 'Hardware(tamanho): {}, Protocolo(tamanho): {}'.format(arp.hardwareSize, arp.protoSize))
        print(TAB_2 + 'Opcode: {}'.format(arp.opcode))
        print(TAB_2 + 'Source MAC: {}, Dest MAC: {}'.format(arp.sourceMAC, arp.destMAC))
        print(TAB_2 + 'Source IP: {}, Dest IP: {}'.format(arp.sourceIP, arp.destIP))

    def printOutros(self, eth):
        print(colorizar('|[ Other ]', 'blue'))
        print(format_multi_line(DATA_TAB_1, eth.data))

    def printStats(self):
        print('-' * 90 + '\n', end='\r')
        print(colorizar('[%s]' % loading[self.pacotesTotais % 4], 'grey') +
              colorizar(' Total de Pacotes: %d' % self.pacotesTotais, 'red') +
              colorizar(' Pacotes TCP: %d' % self.pacotesTCP, 'yellow') +
              colorizar(' Pacotes UDP: %d' % self.pacotesUDP, 'cyan') +
              colorizar(' Pacotes ARP: %d' % self.pacotesARP, 'cyan') +
              colorizar(' Outros Pacotes: %d' % self.outros, 'magenta'), end='\r')

    def printFinalStats(self):
        print(colorizar('\n\n[+] PACOTES ENCONTRADOS:', 'grey') +
              '\n' + '-' * 90 +
              colorizar('\n' + '{:25}'.format('\t1. Total de Pacotes:') + '%d' % self.pacotesTotais, 'red') +
              colorizar('\n' + '{:25}'.format('\t2. TCP:')              + '%d' % self.pacotesTCP, 'yellow') +
              colorizar('\n' + '{:25}'.format('\t3. UDP:')              + '%d' % self.pacotesUDP, 'cyan') +
              colorizar('\n' + '{:25}'.format('\t4. ARP:')              + '%d' % self.pacotesARP, 'green') +
              colorizar('\n' + '{:25}'.format('\t4. Outros:')           + '%d\n' % self.outros, 'magenta') +
              colorizar('\n[+] IPV4:', 'grey') +
              '\n' + '-' * 90 +
              colorizar('\n' + '{:25}'.format('\t1. HTTP:')             + '%d' % self.pacotesHTTP, 'yellow') +
              colorizar('\n' + '{:25}'.format('\t1. HTTPS:')            + '%d' % self.pacotesHTTPS, 'yellow') +
              colorizar('\n' + '{:25}'.format('\t2. FTP:')              + '%d\n' % self.pacotesFTP, 'cyan') +
              colorizar('\n' + 'Agradecimentos a:\nBucky Roberts, thenewboston.com\n', 'cyan'))

    def getDateTime(self):
        return str(time.localtime().tm_year) + str(time.localtime().tm_mon) + str(time.localtime().tm_mday) + str(time.localtime().tm_hour) + str(time.localtime().tm_min) + str(time.localtime().tm_sec)

Sniffer()
