FROM registry.access.redhat.com/ubi8/ubi-minimal:8.6 AS builder

RUN microdnf install -y tar gzip make which

# install go 1.17.8
RUN curl -O -J https://dl.google.com/go/go1.18.4.linux-amd64.tar.gz
RUN tar -C /usr/local -xzf go1.18.4.linux-amd64.tar.gz
RUN ln -s /usr/local/go/bin/go /usr/local/bin/go

WORKDIR /workspace

COPY . ./

RUN go mod vendor 
RUN make binary

FROM registry.access.redhat.com/ubi8/ubi-minimal:8.6

COPY --from=builder /workspace/service-account-api /usr/local/bin/

EXPOSE 8000


ENV KEYCLOAK_HOST=keycloak-sso:8180
ENV REALM=redhat-external
ENV SECRET=admin-service-account
ENV DEBUG=true
ENV CLIENTID=admin-service-account

ENTRYPOINT ["/usr/local/bin/service-account-api","serve","--keycloak_host=http://keycloak-sso:8080", "--realm=redhat-external","--clientId=admin-service-account","--secret=admin-service-account","--debug=true"]

LABEL name="ervice-account-api" \
      version="0.0.1" \
      summary="Service account api" \
      description="service-account-api"
