FROM quay.io/openshift/origin-cli
COPY ./scripts/* /usr/bin/
COPY ./scripts/* /usr/tmp/

# Install Python 3 and pip
RUN yum update -y && \
    yum install -y python3 python3-pip && \
    yum clean all
WORKDIR /usr/tmp/
# Upgrade pip
RUN python3 -m pip install --upgrade pip && \
    python3 -m venv venv && \
    source venv/bin/activate && \
    python3 -m pip install --no-cache-dir -r requirements.txt --user

ENTRYPOINT /usr/bin/gather
