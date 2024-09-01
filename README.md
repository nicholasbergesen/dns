# DNS
Golang Implementation of a dns server based on the RFC doc https://www.ietf.org/rfc/rfc1035.txt

This implementation attempts to create the simplest architecture shown below:

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

- Uses Google's 8.8.8.8 name server as the foreign server.
- Use block.txt to add a list of urls to block, add each entry on a new line, only exact match supported.
- Logs written to dns-{date}.log file
