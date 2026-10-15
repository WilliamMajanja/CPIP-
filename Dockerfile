FROM python:3.13-alpine

LABEL description="CPIP v7.0.0 — Coffee Pot Internet Protocol (RFC 2324 + RFC 7168 + Mesh + KEM providers + network defense)"
LABEL version="7.0.0"

RUN apk add --no-cache gcc make musl-dev openssl

WORKDIR /opt/cpip

COPY pyproject.toml .
COPY server.py .
COPY inf1del_kyber.py .
COPY pure_mlkem.py .
COPY providers/ providers/
COPY cpip_gui.py cpip_gui.py
COPY cpip_tui.py cpip_tui.py
COPY b4dm4n_cw.py b4dm4n_cw.py
COPY cpip /usr/local/bin/cpip
COPY radio/ radio/
COPY web/ web/

RUN chmod +x /usr/local/bin/cpip && \
    pip install --no-cache-dir -e . && \
    make -C radio 2>/dev/null || true && \
    mkdir -p /opt/cpip/.ssl && \
    chmod 777 /opt/cpip/.ssl

EXPOSE 4180 4181 4190 4191 4195 4196

ENV CPIP_DEVICE=hyper-text
ENV CPIP_BIND=0.0.0.0
ENV CPIP_PORT=4180
ENV CPIP_MESH=1
ENV CPIP_SAT=0
ENV CPIP_RADIO=0
ENV CPIP_MOBILE=0
ENV CPIP_COVERT=1
ENV CPIP_COVERT_KEY=""
ENV CPIP_RPC_AUTH=1
ENV CPIP_NTP=0
ENV CPIP_SSL=1
ENV CPIP_SSL_AUTO=1
ENV CPIP_HTTP_REDIRECT=1
ENV CPIP_HTTP_REDIRECT_PORT=4181
ENV CPIP_ANTI_ISP=1
ENV CPIP_ANTI_STINGRAY=1
ENV CPIP_ANTI_SURVEILLANCE=1
ENV CPIP_DPI_EVASION=1
ENV CPIP_TRAFFIC_OBFUSC=1
ENV CPIP_METADATA_STRIP=1
ENV CPIP_NET_NEUTRALITY=1

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD python3 -c "import ssl,urllib.request; urllib.request.urlopen('https://localhost:4180/health', context=ssl._create_unverified_context())" || exit 1

CMD ["python3", "/opt/cpip/server.py"]
