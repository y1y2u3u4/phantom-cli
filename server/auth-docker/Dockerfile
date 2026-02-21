FROM node:20-slim

RUN npm install -g @anthropic-ai/claude-code && npm cache clean --force

# Create non-root user for Claude Code
RUN useradd -m -s /bin/bash claude

USER claude
WORKDIR /home/claude

ENTRYPOINT ["claude"]
