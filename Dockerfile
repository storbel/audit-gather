FROM quay.io/openshift/origin-cli
RUN python3 -m pip install -r ./scripts/requirements.txt 

COPY ./scripts/* /usr/bin/

ENTRYPOINT /usr/bin/gather
