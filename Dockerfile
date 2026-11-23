ARG PYTHON_BASE_IMAGE=python:3.12-slim
FROM ${PYTHON_BASE_IMAGE} AS build
WORKDIR /build
COPY pyproject.toml uv.lock ./
COPY src/persistent_terminal_mcp ./src/persistent_terminal_mcp
RUN pip install --no-cache-dir uv==0.11.15 \
    && UV_PROJECT_ENVIRONMENT=/opt/venv uv sync --locked --no-dev --no-editable

FROM ${PYTHON_BASE_IMAGE}
ARG PTMCP_UID=10001
ARG PTMCP_GID=10001
RUN test "$PTMCP_UID" -ne 0 && test "$PTMCP_GID" -ne 0 \
    && install -d -m 0700 -o "$PTMCP_UID" -g "$PTMCP_GID" /data
COPY --from=build /opt/venv /opt/venv
WORKDIR /data
USER ${PTMCP_UID}:${PTMCP_GID}
ENV PTMCP_DATA_DIR=/data PYTHONUNBUFFERED=1
EXPOSE 8766
ENTRYPOINT ["/opt/venv/bin/terminal-mcp"]
CMD ["serve"]
