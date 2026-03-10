FROM python:3.10-alpine

RUN apk add --no-cache build-base libffi-dev openssl-dev

WORKDIR /app

COPY . .

RUN pip install --upgrade pip \
    && pip install --no-cache-dir .

# Default to SSE mode for container deployments
ENV MCP_TRANSPORT=sse
ENV MCP_HOST=0.0.0.0
ENV MCP_PORT=8000

EXPOSE 8000

CMD ["python", "-m", "paper_search_mcp.server"]
