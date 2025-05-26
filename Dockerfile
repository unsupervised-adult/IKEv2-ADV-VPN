FROM registry.redhat.io/ubi8/ubi
COPY ./Okta-agent.rpm /tmp/
RUN yum install -y /tmp/Okta-agent.rpm
