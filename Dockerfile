FROM python:3.12-slim

WORKDIR /work
COPY . /work

RUN python -m pip install --no-cache-dir ".[reports]"

ENTRYPOINT ["adaf-attack"]
CMD ["doctor", "--profile", "user-readiness"]
