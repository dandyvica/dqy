docker build -t bind9 .
docker run -d -it --name bind9.1 -p 10053:53 -p 10053:53/udp bind9
# docker inspect --format "{{.NetworkSettings.IPAddress}}" bin9.1
docker exec -it bind9.1 /bin/bash 