.RECIPEPREFIX := >
TARGETS := $(shell ls scripts)

DAPPER_IMAGE ?= pasturestack-overlay-network-dapper:ubuntu26
DAPPER_HOST_ARCH ?= amd64
DOCKER_VERSION ?= 29.5.2
DOCKER_BUILD_NETWORK ?= host
UBUNTU_MIRROR ?= http://archive.ubuntu.com/ubuntu
DAPPER_SOURCE ?= /go/src/github.com/PastureStack/ipsec-vxlan-overlay-network

.dapper:
>docker build \
>  --pull \
>  --build-arg DAPPER_HOST_ARCH=$(DAPPER_HOST_ARCH) \
>  --build-arg DOCKER_VERSION=$(DOCKER_VERSION) \
>  --build-arg UBUNTU_MIRROR=$(UBUNTU_MIRROR) \
>  --network $(DOCKER_BUILD_NETWORK) \
>  -t $(DAPPER_IMAGE) \
>  -f Dockerfile.dapper .

$(TARGETS): .dapper
>docker run --rm \
>  -v $(CURDIR):$(DAPPER_SOURCE) \
>  -v /var/run/docker.sock:/var/run/docker.sock \
>  -e DAPPER_UID=$$(id -u) \
>  -e DAPPER_GID=$$(id -g) \
>  -e ARCH=$(DAPPER_HOST_ARCH) \
>  -e TAG \
>  -e REPO \
>  -e IMAGE_NAMESPACE \
>  -e IMAGE_REVISION \
>  -e VERSION_OVERRIDE \
>  -e RELEASE_VERSION \
>  -e SOURCE_DATE_EPOCH \
>  -e METADATA_CNI_IPAM_BINARY \
>  -e METADATA_CNI_IPAM_URL \
>  -e METADATA_CNI_IPAM_SHA256 \
>  -e PER_HOST_SUBNET_BINARY \
>  -e PER_HOST_SUBNET_URL \
>  -e PER_HOST_SUBNET_SHA256 \
>  -e HOST_LOCAL_CNI_IPAM_BINARY \
>  -e HOST_LOCAL_CNI_IPAM_URL \
>  -e HOST_LOCAL_CNI_IPAM_SHA256 \
>  -e FLAT_CNI_IPAM_BINARY \
>  -e FLAT_CNI_IPAM_URL \
>  -e FLAT_CNI_IPAM_SHA256 \
>  -e MOUNT_PROPAGATION_BINARY \
>  -e MOUNT_PROPAGATION_URL \
>  -e MOUNT_PROPAGATION_SHA256 \
>  -e DOCKER_BUILD_NETWORK=$(DOCKER_BUILD_NETWORK) \
>  -e UBUNTU_MIRROR=$(UBUNTU_MIRROR) \
>  $(DAPPER_IMAGE) $@

trash: deps

trash-keep: deps

deps: .dapper
>docker run --rm \
>  -v $(CURDIR):$(DAPPER_SOURCE) \
>  -e DAPPER_UID=$$(id -u) \
>  -e DAPPER_GID=$$(id -g) \
>  -e ARCH=$(DAPPER_HOST_ARCH) \
>  -e VERSION_OVERRIDE \
>  -e SOURCE_DATE_EPOCH \
>  $(DAPPER_IMAGE) /bin/bash -lc 'echo "vendor directory is committed; no dependency bootstrap required"'

.DEFAULT_GOAL := ci

.PHONY: .dapper $(TARGETS) trash trash-keep deps
