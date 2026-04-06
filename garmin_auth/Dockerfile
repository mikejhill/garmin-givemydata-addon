ARG BUILD_FROM=ghcr.io/home-assistant/aarch64-base-debian:bookworm
FROM ${BUILD_FROM}

# Install Chromium, Xvfb (virtual display for stealth), Python 3,
# git (for pip VCS installs), and build tools (for native extensions on aarch64)
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
        python3-dev \
        git \
        build-essential \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Tell SeleniumBase to use the system Chromium instead of downloading its own
ENV CHROME_BIN=/usr/bin/chromium
ENV CHROMEDRIVER_BIN=/usr/bin/chromedriver
ENV SB_USE_SYSTEM_CHROMEDRIVER=true

COPY requirements.txt /tmp/
RUN pip3 install --no-cache-dir --break-system-packages -r /tmp/requirements.txt

# Remove build tools to reduce image size
RUN apt-get update && \
    apt-get remove -y build-essential python3-dev && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY garmin_auth_api.py /app/
COPY run.sh /
RUN chmod a+x /run.sh

CMD ["/run.sh"]
