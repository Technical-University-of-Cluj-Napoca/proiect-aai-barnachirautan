FROM ubuntu:latest
LABEL authors="Razvan"

ENTRYPOINT ["top", "-b"]