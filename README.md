# DNS
Golang Implementation of a dns server based on the RFC doc https://www.ietf.org/rfc/rfc1035.txt

This implementation is attempts to create the simplest architecture shown below:

                 Local Host                        |  Foreign
                                                   |
    +---------+               +----------+         |  +--------+
    |         | user queries  |          |queries  |  |        |
    |  User   |-------------->|          |---------|->|Foreign |
    | Program |               | Resolver |         |  |  Name  |
    |         |<--------------|          |<--------|--| Server |
    |         | user responses|          |responses|  |        |
    +---------+               +----------+         |  +--------+
                                |     A            |
                cache additions |     | references |
                                V     |            |
                              +----------+         |
                              |  cache   |         |
                              +----------+         |

I'm using Google's 8.8.8.8 name server as my foreign server.

## Outstanding items
- I still need to implement a cache
- There's a logging bug where some cases of RData arne'n't uncompressed correctly when trying to display. This doesn't affect the core working of the DNS server is superficial.
- Load a config file to set an output for the logs, different foreign name server and enable/disable using go routines.
