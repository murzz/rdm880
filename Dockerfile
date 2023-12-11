# syntax = docker/dockerfile:1.2

FROM alpine:3.19 as builder-alpine
# hadolint ignore=DL3019
RUN --mount=type=cache,target=/var/cache \
  set -ex \
  && apk add \
    boost-dev~=1.78 \
    clang~=13.0 \
    cmake~=3.23 \
    cppcheck~=2.8 \
    g++~=11.2 \
    git~=2.36 \
    samurai~=1.2


FROM builder-alpine as devel-alpine
# hadolint ignore=DL3019
RUN --mount=type=cache,target=/var/cache \
  set -ex \
  && apk add \
    gdb~=11.2 \
    valgrind~=3.19


FROM ubuntu:22.04 as builder-ubuntu
# hadolint ignore=DL3009
RUN --mount=type=cache,target=/var/cache \
  set -ex \
  && apt-get --yes update \
  && apt-get --yes --no-install-recommends install \
    ca-certificates=20211016 \
    clang=1:14\* \
    cmake=3.22\* \
    cppcheck=2.7\* \
    g++=4:11.2\* \
    git=1:2.34\* \
    libboost-all-dev=1.74\* \
    ninja-build=1.10\*


FROM builder-ubuntu as devel-ubuntu
# hadolint ignore=DL3009
RUN --mount=type=cache,target=/var/cache \
  set -ex \
  && apt-get --yes update \
  && apt-get --yes --no-install-recommends install \
    gdb=12.1\* \
    valgrind=1:3.18\* \
