# Plugboard_Proxy_Network_Security
Develop a "plugboard" proxy for adding an extra layer of protection to publicly accessible network services

Consider for example the case of an SSH server with a public IP address. No
matter how securely the server has been configured and how strong the keys
used are, it might suffer from a "pre-auth" zero day vulnerability that allows
remote code execution even before the completion of the authentication
process. This could allow attackers to compromise the server even without
providing proper authentication credentials. The Heartbleed OpenSSL bug is an
example of such a serious vulnerability against SSL/TLS.

The plugboard proxy adds an extra layer of encryption to connections towards TCP services. Instead of connecting
directly to the service, clients connect to pbproxy (running on the same
server), which then relays all traffic to the actual service. Before relaying
the traffic, pbproxy *always* decrypts it using a static symmetric key. This
means that if the data of any connection towards the protected server is not
properly encrypted, then it will turn into garbage before reaching the
protected service.
