# DNS
Golang Implementation of a DNS server based on RFC 1035 and RFC 8484, supporting both traditional DNS over UDP and DNS over HTTPS (DOH).

This implementation attempts to create the simplest architecture shown below:

                                               Local Host          |  Foreign
                                                                   |
    +---------+               +----------+           +----------+  |  +--------+
    |         | user queries  |          |queries    |  filter  |  |  |        |
    |  User   |-------------->|          |---------->|  blocked |--|->|Foreign |
    | Program |               | Resolver |           +----------+  |  |  Name  |
    |         |<--------------|          |<------------------------|--| Server |
    |         | user responses|          |responses                |  |        |
    +---------+               +----------+                         |  +--------+
                                |     A                            |
                cache additions |     | references                 |
                                V     |                            |
                              +----------+                         |
                              |  cache   |                         |
                              +----------+                         |

## Features

- **Traditional DNS**: Uses Google's 8.8.8.8 name server as the foreign server via UDP (RFC 1035)
- **DNS over HTTPS (DOH)**: Supports RFC 8484 with both GET and POST methods via HTTPS
- **Domain Blocking**: Use block.txt to add a list of URLs to block, add each entry on a new line, only exact match supported
- **Caching**: Intelligent DNS response caching to improve performance
- **Logging**: Logs written to dns-{date}.log file

## Usage

```bash
# Start both UDP and HTTPS servers (default)
./dns-server

# Start only UDP DNS server on port 53
./dns-server -enable-doh=false

# Start only DOH server on port 8443
./dns-server -enable-udp=false

# Custom ports
./dns-server -udp-port=:5353 -https-port=:9443
```

### Command Line Options

- `-enable-doh`: Enable DNS over HTTPS (default: true)
- `-enable-udp`: Enable traditional UDP DNS (default: true)
- `-https-port`: HTTPS port for DOH (default: ":8443")
- `-udp-port`: UDP port for traditional DNS (default: ":53")

## DNS over HTTPS (DOH) - RFC 8484

The server supports DOH with both methods specified in RFC 8484:

### GET Method
```
GET /dns-query?dns=<base64url-encoded-dns-query>
Accept: application/dns-message
```

### POST Method
```
POST /dns-query
Content-Type: application/dns-message
Accept: application/dns-message

<binary-dns-query-in-body>
```

### Example DOH Requests

Using curl with the server:

```bash
# POST method
curl -X POST https://localhost:8443/dns-query \
  -H "Content-Type: application/dns-message" \
  -H "Accept: application/dns-message" \
  --data-binary @query.bin \
  -k

# GET method
curl "https://localhost:8443/dns-query?dns=<base64url-encoded-query>" \
  -H "Accept: application/dns-message" \
  -k
```

Note: The server uses a self-signed certificate for HTTPS, so `-k` flag is needed for curl to skip certificate verification in testing.

## Security Note

The implementation generates a self-signed certificate for HTTPS. In production environments, you should replace this with proper certificates from a trusted Certificate Authority.
