# Lynceus in a container. Two services from one image (see compose.yaml):
#   scanner    python main.py   ARP + port checks; needs CAP_NET_RAW and the host network
#   dashboard  python app.py    Flask dashboard; no capabilities at all
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    LYNCEUS_DB=/data/devices.db

# libcap2-bin only to set the capability below; netbase for port -> service names.
RUN apt-get update \
 && apt-get install -y --no-install-recommends libcap2-bin netbase \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY *.py ./
COPY static ./static
COPY templates ./templates

# Run as a normal user. ARP needs raw packets: instead of root, a copy of the interpreter
# used only by the scanner gets exactly one file capability, CAP_NET_RAW. The dashboard
# runs the plain interpreter, so it works with every capability dropped.
RUN useradd --system --uid 10001 --home /nonexistent lynceus \
 && mkdir /data && chown lynceus /data \
 && cp "$(readlink -f /usr/local/bin/python3)" /usr/local/bin/python-netraw \
 && setcap cap_net_raw+ep /usr/local/bin/python-netraw \
 && apt-get purge -y libcap2-bin && apt-get autoremove -y

USER lynceus
VOLUME /data
CMD ["python-netraw", "main.py"]
