FROM mcr.microsoft.com/playwright/python:v1.49.0-noble
RUN pip install --no-cache-dir "playwright==1.49.0"
# Base image already ships a `pwuser` account: run the browser as
# non-root. Chromium's own sandbox is off (see driver.py) because this
# image targets kernels that block unprivileged user namespaces;
# containment comes from this USER plus the docker run flags
# (--cap-drop=ALL, no-new-privileges, pids/mem/cpu/shm limits).
USER pwuser
