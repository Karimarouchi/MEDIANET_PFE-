FROM kalilinux/kali-rolling

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PIP_BREAK_SYSTEM_PACKAGES=1
ENV GO111MODULE=on
ENV PATH="/root/go/bin:/root/.cargo/bin:/opt/dependency-check/bin:${PATH}"

RUN apt-get update && apt-get install -y \
    bash \
    ca-certificates \
    curl \
    wget \
    git \
    jq \
    unzip \
    tar \
    gzip \
    zip \
    xz-utils \
    file \
    vim \
    less \
    procps \
    iputils-ping \
    net-tools \
    dnsutils \
    netcat-openbsd \
    openssl \
    nmap \
    sslscan \
    nikto \
    whatweb \
    bsdextrautils \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    build-essential \
    nodejs \
    npm \
    php-cli \
    golang-go \
    rustc \
    cargo \
    openjdk-21-jre-headless \
    ruby-full \
    dos2unix \
    openscap-scanner \
    && rm -rf /var/lib/apt/lists/*

# PHP Composer — installé via le script officiel (n'existe pas dans les dépôts Kali)
RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer

# SCAP Security Guide (SSG) — contenu OpenSCAP pour CIS/PCI-DSS/NIST
# (Le paquet scap-security-guide est Red Hat uniquement — on télécharge le contenu upstream)
RUN SSG_VERSION=$(curl -s https://api.github.com/repos/ComplianceAsCode/content/releases/latest | jq -r .tag_name | sed 's/^v//') && \
    wget -q -O /tmp/ssg.zip \
    "https://github.com/ComplianceAsCode/content/releases/download/v${SSG_VERSION}/scap-security-guide-${SSG_VERSION}.zip" && \
    unzip -q /tmp/ssg.zip -d /tmp/ssg-extract && \
    mkdir -p /usr/share/scap-security-guide && \
    cp -r /tmp/ssg-extract/scap-security-guide-${SSG_VERSION}/* /usr/share/scap-security-guide/ && \
    rm -rf /tmp/ssg.zip /tmp/ssg-extract

# Python security tools
RUN python3 -m pip install --upgrade --ignore-installed pip setuptools wheel && \
    python3 -m pip install --ignore-installed \
    semgrep \
    sslyze \
    pip-audit \
    checkov

# Trivy
RUN TRIVY_VERSION=$(curl -s https://api.github.com/repos/aquasecurity/trivy/releases/latest | jq -r .tag_name | sed 's/^v//') && \
    wget -q -O /tmp/trivy.tar.gz \
    "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" && \
    tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy && \
    chmod +x /usr/local/bin/trivy && \
    rm -f /tmp/trivy.tar.gz

# Syft
RUN SYFT_VERSION=$(curl -s https://api.github.com/repos/anchore/syft/releases/latest | jq -r .tag_name | sed 's/^v//') && \
    wget -q -O /tmp/syft.tar.gz \
    "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_amd64.tar.gz" && \
    tar -xzf /tmp/syft.tar.gz -C /usr/local/bin syft && \
    chmod +x /usr/local/bin/syft && \
    rm -f /tmp/syft.tar.gz

# Grype
RUN GRYPE_VERSION=$(curl -s https://api.github.com/repos/anchore/grype/releases/latest | jq -r .tag_name | sed 's/^v//') && \
    wget -q -O /tmp/grype.tar.gz \
    "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_amd64.tar.gz" && \
    tar -xzf /tmp/grype.tar.gz -C /usr/local/bin grype && \
    chmod +x /usr/local/bin/grype && \
    rm -f /tmp/grype.tar.gz

# OSV-Scanner
RUN OSV_VERSION=$(curl -s https://api.github.com/repos/google/osv-scanner/releases/latest | jq -r .tag_name) && \
    wget -O /usr/local/bin/osv-scanner \
    "https://github.com/google/osv-scanner/releases/download/${OSV_VERSION}/osv-scanner_linux_amd64" && \
    chmod +x /usr/local/bin/osv-scanner

# Gitleaks
RUN GITLEAKS_VERSION=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest | jq -r .tag_name) && \
    wget -O /tmp/gitleaks.tar.gz \
    "https://github.com/gitleaks/gitleaks/releases/download/${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION#v}_linux_x64.tar.gz" && \
    tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks && \
    chmod +x /usr/local/bin/gitleaks && \
    rm -f /tmp/gitleaks.tar.gz

# Nuclei — fast web vulnerability scanner (CVE, misconfig, exposure, panels)
RUN NUCLEI_VERSION=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | jq -r .tag_name | sed 's/^v//') && \
    wget -q -O /tmp/nuclei.zip \
    "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" && \
    unzip -q /tmp/nuclei.zip nuclei -d /usr/local/bin && \
    chmod +x /usr/local/bin/nuclei && \
    rm -f /tmp/nuclei.zip && \
    nuclei -update-templates -no-interactsh || true

# TruffleHog — entropy-based secret detection (complements Gitleaks)
RUN TRUFFLEHOG_VERSION=$(curl -s https://api.github.com/repos/trufflesecurity/trufflehog/releases/latest | jq -r .tag_name | sed 's/^v//') && \
    wget -q -O /tmp/trufflehog.tar.gz \
    "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_amd64.tar.gz" && \
    tar -xzf /tmp/trufflehog.tar.gz -C /usr/local/bin trufflehog && \
    chmod +x /usr/local/bin/trufflehog && \
    rm -f /tmp/trufflehog.tar.gz

# testssl.sh
RUN git clone --depth 1 https://github.com/testssl/testssl.sh.git /opt/testssl.sh && \
    ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh && \
    chmod +x /opt/testssl.sh/testssl.sh

# govulncheck
RUN go install golang.org/x/vuln/cmd/govulncheck@latest

# cargo-audit
RUN cargo install cargo-audit

# OWASP Dependency-Check
RUN DEP_CHECK_VERSION=$(curl -s https://api.github.com/repos/dependency-check/DependencyCheck/releases/latest \
    | jq -r .tag_name | sed 's/^v//') && \
    wget -O /tmp/dependency-check.zip \
    "https://github.com/dependency-check/DependencyCheck/releases/download/v${DEP_CHECK_VERSION}/dependency-check-${DEP_CHECK_VERSION}-release.zip" && \
    unzip /tmp/dependency-check.zip -d /opt && \
    chmod +x /opt/dependency-check/bin/dependency-check.sh && \
    rm -f /tmp/dependency-check.zip

# Hadolint — Dockerfile linter
RUN HADOLINT_VERSION=$(curl -s https://api.github.com/repos/hadolint/hadolint/releases/latest | jq -r .tag_name) && \
    wget -O /usr/local/bin/hadolint \
    "https://github.com/hadolint/hadolint/releases/download/${HADOLINT_VERSION}/hadolint-Linux-x86_64" && \
    chmod +x /usr/local/bin/hadolint

# OWASP ZAP — Dynamic Application Security Testing (DAST)
RUN ZAP_VERSION=$(curl -s https://api.github.com/repos/zaproxy/zaproxy/releases/latest | jq -r .tag_name | sed 's/^v//') && \
    wget -q -O /tmp/zap.tar.gz \
    "https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Linux.tar.gz" && \
    mkdir -p /opt/zaproxy && \
    tar -xzf /tmp/zap.tar.gz -C /opt/zaproxy --strip-components=1 && \
    ln -s /opt/zaproxy/zap.sh /usr/local/bin/zap.sh && \
    rm -f /tmp/zap.tar.gz
# ZAP Python helper (provides zap-baseline.py, zap-full-scan.py)
RUN python3 -m pip install --ignore-installed zaproxy

# Pre-warm Grype and Trivy vulnerability databases (speeds up first scan)
RUN grype db update || true
RUN trivy image --download-db-only || true
# Trivy 0.65+ requires a separate Java DB to resolve Maven BOM-managed versions.
# Without it, dependencies like postgresql@42.6.1 (managed via Spring Boot BOM) cannot
# be resolved and trivy reports 0 CVEs for Java projects.
RUN trivy image --download-java-db-only || true

# Maven — needed to run CycloneDX Maven plugin for proper Java BOM resolution.
# Without Maven, Spring Boot BOM-managed deps (e.g. postgresql@42.6.1) stay as
# UNKNOWN versions in the SBOM, causing Grype/OSV-Scanner to find 0 CVEs.
RUN apt-get update && apt-get install -y maven && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

COPY scan.sh /opt/vulnix/scan.sh
COPY scripts/ /opt/vulnix/scripts/
COPY scripts/scan_common.sh /opt/vulnix/scripts/scan_common.sh
# grype.yaml — active CPE matching pour NVD + RHEL + Debian + Ubuntu + Amazon + Rocky/Alma
COPY grype.yaml /root/.grype.yaml

RUN bash -n /opt/vulnix/scan.sh && \
    for f in /opt/vulnix/scripts/*.sh; do bash -n "$f"; done && \
    dos2unix /opt/vulnix/scan.sh && \
    dos2unix /opt/vulnix/scripts/*.sh && \
    chmod +x /opt/vulnix/scan.sh && \
    chmod +x /opt/vulnix/scripts/*.sh

ENTRYPOINT ["/opt/vulnix/scan.sh"]