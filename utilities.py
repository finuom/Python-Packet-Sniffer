import textwrap
from termcolor import colored

TAB_1 = '|\t - '
TAB_2 = '|\t\t - '
TAB_3 = '|\t\t\t - '
TAB_4 = '|\t\t\t\t - '

DATA_TAB_1 = '|\t   '
DATA_TAB_2 = '|\t\t   '
DATA_TAB_3 = '|\t\t\t   '
DATA_TAB_4 = '|\t\t\t\t   '

END_LINE = '{:50}'.format('|')

loading = ['-', '-', '-', 'x']

HTTP_PORTA = 80
HTTPS_PORTA = 443
FTP_PORTA = [20, 21]
SMTP_PORTA = [25, 2525, 2526, 336, 465, 587, 143, 220, 993, 995, 109, 110]

def colorizar(text, color):
    return colored(text, color=color, attrs=['bold'])

# Returns MAC as string from bytes (ie AA:BB:CC:DD:EE:FF)
def get_mac_addr(mac_raw):
    byte_str = map('{:02x}'.format, mac_raw)
    mac_addr = ':'.join(byte_str).upper()
    return mac_addr

# Formats multi-line data
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


