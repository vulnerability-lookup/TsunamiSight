ARG APP_IMAGE=python:3.11-slim
FROM $APP_IMAGE AS builder

ENV PYTHONFAULTHANDLER=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=off \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    PATH="/root/.local/bin:$PATH"

RUN apt-get update && apt-get -y install python3-pip && pip install pipx

FROM $APP_IMAGE
ARG UID=1000
ARG GID=1000

ENV PYTHONFAULTHANDLER=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=off \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    PATH="/root/.local/bin:$PATH"

RUN apt-get update && apt-get -y install git && rm -rf /var/lib/apt/lists/*

RUN groupadd -g $GID basicuser && useradd -r -u $UID -g basicuser basicuser
RUN mkdir -p /home/basicuser && chown basicuser:basicuser -R /home/basicuser

USER basicuser
WORKDIR /home/basicuser

RUN git clone https://github.com/google/tsunami-security-scanner-plugins.git \
    /home/basicuser/tsunami-security-scanner-plugins

ENV PATH="/home/basicuser/.local/bin:${PATH}"

COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

RUN pipx install TsunamiSight

ENTRYPOINT ["TsunamiSight", "--init"]
