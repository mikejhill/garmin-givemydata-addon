ARG BUILD_FROM
FROM ${BUILD_FROM}

# Install Chromium, Xvfb (virtual display for stealth), Python 3
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        chromium \
        chromium-driver \
        fonts-liberation \
        libnss3 \
        libatk-bridge2.0-0 \
        libatk1.0-0 \
        libgtk-3-0 \
        libdrm2 \
        libgbm1 \
        xvfb \
        python3 \
        python3-pip \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

ENV CHROME_BIN=/usr/bin/chromium

COPY requirements.txt /tmp/
RUN pip3 install --no-cache-dir --break-system-packages -r /tmp/requirements.txt

COPY garmin_auth_api.py /app/
COPY run.sh /
RUN chmod a+x /run.sh

CMD ["/run.sh"]
