# syntax = docker/dockerfile:1.2

FROM alpine:3.16

RUN --mount=type=cache,target=/var/cache \
	--mount=type=cache,target=/root/.cache \
	set -ex \
	&& apk add \
		g++~=11.2 \
		boost-dev~=1.78 \
		cmake~=3.23 \
		samurai~=1.2\
	&& rm -rf /var/tmp/* /tmp/*
