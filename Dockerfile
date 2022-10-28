# syntax = docker/dockerfile:1.2

FROM alpine:3.16 as builder
# hadolint ignore=DL3019
RUN --mount=type=cache,target=/var/cache \
	set -ex \
	&& apk add \
		boost-dev~=1.78 \
		cmake~=3.23 \
		g++~=11.2 \
		samurai~=1.2


FROM builder as devel
# hadolint ignore=DL3019
RUN --mount=type=cache,target=/var/cache \
	set -ex \
	&& apk add \
        gdb~=11.2 \
		valgrind~=3.19 \
