FROM alpine:latest
COPY action.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
