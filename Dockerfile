FROM scratch
MAINTAINER Dragon Hartzler <dragon@cryptopanic.org>
ADD k8s-killc /k8s-killc
ENTRYPOINT ["/k8s-killc"]
