FROM python:3.10-slim

USER root

# -----------------------------------------------------
# Install system tools
# -----------------------------------------------------
RUN apt-get update && apt-get install -y \
    curl wget git unzip gnupg ca-certificates docker.io \
    apt-transport-https tzdata vim jq \
    && rm -rf /var/lib/apt/lists/*

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DEBIAN_FRONTEND=noninteractive \
    PATH="/usr/local/bin:${PATH}"

# -----------------------------------------------------
# Python security tools
# -----------------------------------------------------
RUN pip install --upgrade pip && \
    pip install bandit pip-audit pytest checkov

# -----------------------------------------------------
# Install tfsec - FIXED WORKING VERSION
# -----------------------------------------------------
RUN wget -q https://github.com/aquasecurity/tfsec/releases/download/v1.28.6/tfsec_1.28.6_linux_amd64.tar.gz \
    && tar -xzf tfsec_1.28.6_linux_amd64.tar.gz tfsec \
    && mv tfsec /usr/local/bin/tfsec \
    && chmod +x /usr/local/bin/tfsec \
    && rm tfsec_1.28.6_linux_amd64.tar.gz

# -----------------------------------------------------
# Install Trivy
# -----------------------------------------------------
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh - \
    && mv ./bin/trivy /usr/local/bin/trivy \
    && chmod +x /usr/local/bin/trivy

# -----------------------------------------------------
# Install Gitleaks - FIXED (use GitHub API)
# -----------------------------------------------------
RUN GITLEAKS_VERSION=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/') \
    && wget https://github.com/gitleaks/gitleaks/releases/download/${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION#v}_linux_x64.tar.gz -O gitleaks.tar.gz \
    && tar -xzf gitleaks.tar.gz gitleaks \
    && mv gitleaks /usr/local/bin/gitleaks \
    && chmod +x /usr/local/bin/gitleaks \
    && rm gitleaks.tar.gz

# -----------------------------------------------------
# Default command
# -----------------------------------------------------
CMD ["bash"] 