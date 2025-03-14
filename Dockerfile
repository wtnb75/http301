FROM scratch
ARG EXT=
COPY http301${EXT} /http301
ENTRYPOINT ["/http301"]
