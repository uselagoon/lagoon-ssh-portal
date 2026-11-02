FROM alpine:3.24@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
ARG BINARY=binary-build-arg-not-defined
ENV BINARY=${BINARY}
ENTRYPOINT ["sh", "-c"]
CMD ["exec /${BINARY}"]
# TARGETPLATFORM is defined by goreleaser during the build
ARG TARGETPLATFORM
COPY ${TARGETPLATFORM}/${BINARY} /
