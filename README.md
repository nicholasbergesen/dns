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

Google's 8.8.8.8 name server is used as the foreign server.
