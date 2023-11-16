import http.server
import socketserver
 
PORT = 8000
DIRECTORY = "../"
 
Handler = http.server.SimpleHTTPRequestHandler
Handler.directory = DIRECTORY
Handler.extensions_map[".html"] = "text/html"
 
with socketserver.TCPServer(("", PORT), Handler) as httpd:
    print("Server started at localhost:" + str(PORT))
    httpd.serve_forever()