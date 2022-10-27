FROM atlassian/default-image:3

RUN \
	set -ex \
	&& apt-get -qq -y update \
	&& apt-get -qq -y --no-install-recommends install \
		g++=4:9.3.0-1ubuntu2 \
		libboost-log-dev=1.71.0.0ubuntu2 \
		libboost-test-dev=1.71.0.0ubuntu2 \
		ninja-build=1.10.0-1build1 \
		python3-pip=20.0.2-5ubuntu1.6 \
	&& pip3 --no-cache-dir install \
	   cmake~=3.24 \
	&& apt-get clean \
	&& rm -rf /var/lib/apt/lists/* /var/tmp/* /tmp/* \
