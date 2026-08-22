FROM python:3.12-slim

WORKDIR /work
COPY . /work

RUN python -m pip install --no-cache-dir ".[reports]"

# Self-identify as a container so `adaf-attack doctor` and the runner can warn
# that live AD/Kerberos capabilities require host integration (DNS, clock, SMB
# routing) that this offline image does not provide.
ENV ADAF_ATTACK_IN_CONTAINER=1

ENTRYPOINT ["adaf-attack"]
CMD ["doctor", "--profile", "user-readiness"]
