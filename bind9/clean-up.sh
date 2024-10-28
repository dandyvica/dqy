docker stop bind9.1
docker rm $(docker ps -a -q)
docker rmi $(docker images -a -q)
docker system prune -a -f
