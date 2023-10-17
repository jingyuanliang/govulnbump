ARG PYTHON_IMAGE=python:3.12

FROM golang:1.21 AS golang

FROM ${PYTHON_IMAGE}

RUN pip3 install --no-cache-dir looseversion==1.3.0
COPY --chmod=755 govulnbump.py /usr/local/bin/govulnbump

RUN rm -rf /usr/local/go
COPY --from=golang /usr/local/go /usr/local/go
RUN mkdir -p /go /gocache
RUN chmod a+rwx /gocache
ENV GOROOT /usr/local/go
ENV GOPATH /go
ENV PATH "${GOROOT}/bin:${GOPATH}/bin:${PATH}"
RUN go install golang.org/x/vuln/cmd/govulncheck@v1.0.1
ENV GOCACHE /gocache/gocache
ENV GOMODCACHE /gocache/gomodcache

ENTRYPOINT ["govulnbump"]
