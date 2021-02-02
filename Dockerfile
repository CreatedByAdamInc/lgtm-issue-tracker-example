FROM alpine:3.10
COPY action.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
