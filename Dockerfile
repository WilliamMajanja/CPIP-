FROM python:3.13-alpine

LABEL description="CPIP — Coffee Pot Internet Protocol (RFC 2324 + RFC 7168)"
LABEL version="2.2.0"

RUN apk add --no-cache gcc make musl-dev

WORKDIR /opt/cpip

COPY server.py .
COPY htcpcp /usr/local/bin/htcpcp
COPY radio/ radio/

RUN chmod +x /usr/local/bin/htcpcp && \
    make -C radio 2>/dev/null || true

EXPOSE 4180 4190 4191 4195 4196

ENV CPIP_DEVICE=hyper-text
ENV CPIP_BIND=0.0.0.0
ENV CPIP_PORT=4180
ENV CPIP_MESH=1
ENV CPIP_SAT=0
ENV CPIP_RADIO=0
ENV CPIP_MOBILE=0
ENV CPIP_COVERT=1
ENV CPIP_COVERT_KEY=""
ENV CPIP_NTP=0

HEALTHCHECK --interval=30s --timeout=5s \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:4180/')" || exit 1

CMD ["python3", "/opt/cpip/server.py"]
