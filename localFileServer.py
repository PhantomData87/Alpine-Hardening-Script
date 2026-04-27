import ssl
import socket
import subprocess
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
# Written by: Alonzo Ortiz-Sanchez
# This was written to avoid relying on an insecured "python3 -m http.server 27036" using HTTP.

# Modified original: https://danieldusek.com/starting-python-server-with-https-enabled-quickly.html

# Generating key
# https://superuser.com/questions/226192/avoid-password-prompt-for-keys-and-prompts-for-dn-information

# Backdoor signature concerns:
# https://security.stackexchange.com/questions/256088/is-the-elliptic-curve-secp256r1-without-a-backdoor
# https://security.stackexchange.com/questions/78621/which-elliptic-curve-should-i-use

# Define port to bind to locally
serverHttpsPort=27036
certPath="/tmp/hardenLocalScript.pem"

# Obtain local IP without having to specify (otherwise feel free to delete this section and specify the localIP)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("9.9.9.9", 53))
localIP = s.getsockname()[0]
s.close()

# Generate key
subprocess.run(["openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:secp521r1", "-x509", "-nodes", "-days", "30", "-subj", "/", "-out", certPath, "-keyout", certPath])

# Start "HTTPS" alike server
httpd = ThreadingHTTPServer((localIP, serverHttpsPort), SimpleHTTPRequestHandler)
context = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile=certPath)
httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

# Greet and start server
print("Serving HTTPS on "+localIP+" port "+str(serverHttpsPort)+" (https://"+localIP+":"+str(serverHttpsPort)+"/)")
try:
	httpd.serve_forever()
except KeyboardInterrupt:
	print("\nStopping HTTPS server")
