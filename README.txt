Man in the Middle HTTPS proxy
03/15/2016

This server will forward(and allow the user to read) any HTTP requests and responses from the client to the server and vice versa.
This also extends to HTTPS requests but only consistently for yelp. It may even require a few trys. This only runs with Python 3.4.

To start ninstall the given CA(cacert.pem) on the mobile phone that is going to be used. The server certificate is already signed by the CA and therefore doesnt require one to install a new one everytime a new domain is used. Then set the proxy server on the phones wifi to the IP address of the machine this will be ran on and whatever port is wanted. Run the server using the following format:
"python mproxy.py"
use "-h" or "--help" for more options