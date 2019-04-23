# -*- coding: utf-8 -*-
"""
	INJECTOR v1.6 
	Created by Marcone 2018

	INSTRUCTIONS:

	CONNECTION MODE OPTIONS:
		1 = Proxy
		2 = Direct
		3 = Proxy when Client not Support Proxy.
		4 = Direct when Client not Support Proxy.
		5 = ICMP with Proxy.
		6 = ICMP Direct.
		7 = SSL Direct.
		8 = SSL with Proxy.

	ACCEPTED PAYLOAD TAG'S:
		[crlf] = Carriage Return + Line Feed.
		[lfcr] = Line Feed + Carriage Return.
		[cr] = Carriage Return.
		[lf] = Line Feed.
		[crlf*2] = [crlf][crlf]
		[host] = Destination host.
		[port] = Destination port.
		[method] = HTTP Method.
		[host_port] = Destination host and port.
		[protocol] = HTTP Protocol.
		[split] = Split Payload and send separately to server.
		[delay_split] = Split Payload and send separately to server with 1 second time delay.
		[netData] or [netdata] or [raw] = Request data from the Client. this command not contain with double CR LF. 
		[realData] or [realdata] or [real_raw] = Real Request data from Client. this command contain with double CR LF. 
		[ssh] = Real SSH request from Client.
		[ua] = Real User Agent.
"""
import socket, threading, select, time, ssl

# Configurations:
LISTEN = '127.0.0.1:8080'
PROXY = '163.172.29.224:80'
SERVER = "m.sg3.ssl.ipmy.co:443"
PAYLOAD = "CONNECT [host_port] HTTP/1.0[crlf][crlf]"
#PAYLOAD = '[method] [host_port] HTTP/1.1[crlf]Host: [host][crlf]User-Agent: [ua][crlf][crlf]'
SNI = "m.youtube.com"
MODE = 7

def formated_payload(payload, request):
	try:
		host = request.split(':')[0].split()[-1]
		port = request.split(':')[-1].split()[0]
		method = request.split()[0]
		protocol = request.split(':')[-1].split()[1]

		tags = {
			'[crlf*2]':'\r\n\r\n',
			'[crlf]':'\r\n',
			'[lfcr]':'\n\r',
			'[cr]':'\r',
			'[lf]':'\n',
			'[host]':host,
			'[port]':port,
			'[method]':method,
			'[host_port]':'{}:{}'.format(host, port),
			'[protocol]':protocol,
			'[netData]':request.strip(),
			'[netdata]':request.strip(),
			'[raw]':request.strip(),
			'[realData]':request,
			'[realdata]':request,
			'[real_raw]':request,
			'[ssh]':'{}:{}'.format(host, port),
			'[ua]':socket.gethostname()
		}

		for i in tags:
			try:
				payload = payload.replace(i, tags[i])
				print payload
			except:
				print('[!] Can not replace Payload TAG: {}'.format(i))
				raise
		return payload
	except:
		print('[!] Can not format Payload!')
		print request
		return request

def conecta(c, a):
	try:
		print('[+] Client {} Received!'.format(a[-1]))
		print c
		print a
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(30)

		DOWNLOAD_BUFFER_SIZE = 8192
		UPLOAD_BUFFER_SIZE = 8192

		if (MODE == 1):
			# Proxy
			pi, pp = PROXY.split(':')
			print "Proxy: %s:%s ", pi,pp
			print('[#] Client {} Connecting via Proxy: {}:{}'.format(a[-1], pi, pp))
			s.connect((pi, int(pp)))
			request = c.recv(8192)
			ri, rp = request.split(':')[0].split()[-1], request.split(':')[-1].split()[0]
			request_text = formated_payload(PAYLOAD, request)
			#print('[#] Payload:\n{}'.format(request_text.replace('\r','\r').replace('\n','\n').replace('[split]','\n')))
			if (request_text.find('[split]')!=-1 or request_text.find('[delay_split]')!=-1):
				request_text = request_text.split('[split]')
				for iten in request_text:
					if(iten.find('[delay_split]')!=-1):
						delay = iten.split('[delay_split]')
						s.send(b"{}".format(delay[0]))
						del delay[0]
						for dl in delay:
							time.sleep(1)
							s.send(b"{}".format(dl))
					else:
						s.send(b"{}".format(iten)) # Payload.
			else:
				s.send(b"{}".format(request_text)) # Payload.

			print(s.recv(8192).strip())
			c.send(b"HTTP/1.1 200 Established\r\n\r\n") # Replace 200 OK.
		elif (MODE == 2):
			# Direta
			print('[#] Client {} Connecting Directly!'.format(a[-1]))
			request = c.recv(8192)
			di, dp = request.split(':')[0].split()[-1], request.split(':')[-1].split()[0]
			s.connect((di, int(dp)))
			c.send(b"HTTP/1.1 200 Established\r\n\r\n")
		elif (MODE == 3):
			# Cliente Nao Suporta Proxy - Usando Proxy.
			pi, pp = PROXY.split(':')
			ri, rp = SERVER.split(':')
			print('[#] Client {} Connecting to {}:{} via Proxy: {}:{}'.format(a[-1], ri, rp, pi, pp))
			s.connect((pi, int(pp)))
			request_text = formated_payload(PAYLOAD, "CONNECT {}:{} HTTP/1.0\r\n\r\n".format(ri, rp))
			#print('[#] Payload:\n{}'.format(request_text.replace('\r','\r').replace('\n','\n').replace('[split]','\n')))
			if (request_text.find('[split]')!=-1 or request_text.find('[delay_split]')!=-1):
				request_text = request_text.split('[split]')
				for iten in request_text:
					if(iten.find('[delay_split]')!=-1):
						delay = iten.split('[delay_split]')
						s.send(b"{}".format(delay[0]))
						del delay[0]
						for dl in delay:
							time.sleep(1)
							s.send(b"{}".format(dl))
					else:
						s.send(b"{}".format(iten)) # Payload.
			else:
				s.send(b"{}".format(request_text)) # Payload.
			print(s.recv(8192).strip())
		elif (MODE == 4):
			# Cliente Nao Suporta Proxy - Conexao Direta.
			ri, rp = SERVER.split(':')
			print('[#] Client {} Connecting Directly to {}:{}'.format(a[-1], ri, rp))
			s.connect((ri, int(rp)))
		elif (MODE == 5):
			# ICMP Com Proxy.
			UPLOAD_BUFFER_SIZE = 32
			pi, pp = PROXY.split(':')
			print('[#] Client {} Connecting via Proxy: {}:{}'.format(a[-1], pi, pp))
			s.connect((pi, int(pp)))
		elif (MODE == 6):
			# ICMP Direto.
			print('[#] Client {} Connecting Directly!'.format(a[-1]))
			request = c.recv(8192)
			di, dp = request.split(':')[0].split()[-1], request.split(':')[-1].split()[0]
			s.connect((di, int(dp)))
			c.send(b"HTTP/1.1 200 Established\r\n\r\n")
			UPLOAD_BUFFER_SIZE = 32
		elif (MODE == 7):
			# SSL Direta.
			print('[#] Client {} Connecting Directly!'.format(a[-1]))
			request = c.recv(8192)
			print "------REQUESTS-------"
			print requests
			di, dp = request.split(':')[0].split()[-1], request.split(':')[-1].split()[0]
			print "Proxy: ", di, dp
			print "---------------------"
			s.connect((di, int(dp)))
			ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
			s = ctx.wrap_socket(s, server_hostname=str(SNI))
			print "Socket to SSL Analyzing"
			c.send(b"HTTP/1.1 200 Established\r\n\r\n")
		elif (MODE == 8):
			# SSL com Proxy.
			pi, pp = PROXY.split(':')
			print('[#] Client {} Connecting via Proxy: {}:{}'.format(a[-1], pi, pp))
			s.connect((pi, int(pp)))
			ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
			s = ctx.wrap_socket(s, server_hostname=str(SNI))
			s.send(c.recv(8192))
			s.recv(8192)
			c.send(b"HTTP/1.1 200 Established\r\n\r\n")
		else:
			print('[!] Error! Please Select a Valid Connection MODE!')
			raise

		print('[*] Client {} Successfully connected to server!'.format(a[-1]))
		s.settimeout(None)
		try:
			while True:
				r, w, x = select.select([c,s], [], [c,s], 3)
				if x: raise
				for i in r:
					try:
						if i is s:
							# Raise if not ddata.
							ddata = i.recv(DOWNLOAD_BUFFER_SIZE)
							if not ddata: raise
							# Download.
							c.send(ddata)
						else:
							# Raise if not udata.
							udata = i.recv(UPLOAD_BUFFER_SIZE)
							print uudata
							if not udata: raise
							# Upload.
							s.send(udata)
					except:
						raise
		except:
			pass
		try:
			c.close()
		except:
			print('[!] Can not close Client: {}'.format(a[-1]))
		try:
			s.close()
		except:
			print('[!] Can not close Server!')
		print('[!] Client {} Disconnected!'.format(a[-1]))
	except:
		try:
			c.close()
		except:
			pass
		try:
			s.close()
		except:
			pass
		print('[!] Client Closed!')

print('-*-*-*-*-*-TheGrapevine Injector v1.6-*-*-*-*-*-\n-*-*-*-*-*-Created by Marcone 2018-*-*-*-*-*-\n')
print('CONFIGURATIONS:\n\nLISTEN: {}\nPROXY: {}\nSERVER: {}\nPAYLOAD: {}\nSNI: {}\nMODE: {}\n'.format(LISTEN, PROXY, SERVER, PAYLOAD, SNI, MODE))
# Listen
try:
	l = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	try:
		li, lp = LISTEN.split(':')
	except:
		print('[!] Error! Please check LISTEN Configuration Information!')
		raise
	try:
		l.bind((str(li), int(lp)))
	except:
		print('[!] Error! Listen Port: {}:{} is Alread in Use!'.format(li, lp))
		raise
	l.listen(0)
	print('[#] Running on Listen IP and Port: {}:{}'.format(li, lp))
	while True:
		try:
			c, a = l.accept()
		except:
			print('[!] Error! Can not accept Client!')
			continue
		else:
			try:
				atendimento = threading.Thread(target=conecta, args=(c, a))
				atendimento.daemon = True
				atendimento.start()
			except:
				print('[!] Error! Can not thread client!')
				continue
	try:
		l.close()
	except:
		print('[!] Error! can not close Listen Port! ')
	print('[!] Program Closed!')
except:
	try:
		l.close()
	except:
		pass
	print('[!] Error! Can not create Local Listen Port!')