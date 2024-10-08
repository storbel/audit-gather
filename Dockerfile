FROM quay.io/openshift/origin-cli
COPY ./scripts/* /usr/bin/
COPY ./scripts/* /usr/tmp/

# Install Python 3 and pip
RUN yum update -y && \
    yum install -y python3 python3-pip && \
    yum clean all
# Upgrade pip
RUN python3 -m pip install --upgrade pip && \
    python3 -m pip install --no-cache-dir -r /usr/tmp/requirements.txt

ENTRYPOINT /usr/bin/gather
