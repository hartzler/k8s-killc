# k8s-killc
Simple kubernetes controller that kills unsigned pods.

## Build
Install golang and glide:

```bash
brew install go
brew install glide
```

Install [minikube](https://github.com/kubernetes/minikube/releases) and setup docker-env `eval $(minkube docker-env)`

Bring down the deps:

```bash
glide install
```

Finally build the container:
```bash
./build-controller
```

## Deploy
```bash
kubectl apply -f resources/
```
