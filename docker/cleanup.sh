# delete all containers and images
docker stop -f $(docker ps -qa)
docker rm -v -f $(docker ps -qa)
docker rmi $(docker images -qa)