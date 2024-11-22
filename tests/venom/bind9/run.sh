docker build -t bind9 .
docker run -d -it --name bind9.1 -p 10053:53/udp -p 10053:53/tcp -p 10853:853/tcp -p 10443:443/tcp bind9
docker exec -it bind9.1 /bin/bash 