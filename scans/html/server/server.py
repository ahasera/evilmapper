import http.server
import socketserver
 
PORT = 8000
DIRECTORY = "../"

class QuietHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        # Override to prevent logging
        pass

Handler = QuietHTTPRequestHandler
Handler.directory = DIRECTORY
Handler.extensions_map[".html"] = "text/html"
 
with socketserver.TCPServer(("", PORT), Handler) as httpd:
    httpd.serve_forever()