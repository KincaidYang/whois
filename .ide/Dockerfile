# 此文件为远程开发环境配置文件
FROM debian:bookworm

ENV GO_VERSION=1.23.5

RUN apt update &&\
    apt install -y wget rsync unzip openssh-server vim lsof git git-lfs locales locales-all libgit2-1.5 libgit2-dev net-tools jq curl &&\
    rm -rf /var/lib/apt/lists/*

# install golang
RUN curl -fsSLO https://dl.google.com/go/go${GO_VERSION}.linux-amd64.tar.gz &&\
    rm -rf /usr/local/go && tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz &&\
    ln -sf /usr/local/go/bin/go /usr/bin/go &&\
    ln -sf /usr/local/go/bin/gofmt /usr/bin/gofmt &&\
    curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s v1.54.2 &&\
    rm -rf go${GO_VERSION}.linux-amd64.tar.gz

# install code-server
RUN curl -fsSL https://code-server.dev/install.sh | sh
RUN code-server --install-extension dbaeumer.vscode-eslint &&\
    code-server --install-extension pinage404.git-extension-pack &&\
    code-server --install-extension redhat.vscode-yaml &&\
    code-server --install-extension esbenp.prettier-vscode &&\
    code-server --install-extension golang.go &&\
    code-server --install-extension eamodio.gitlens &&\
    code-server --install-extension mhutchie.git-graph &&\
    code-server --install-extension ms-azuretools.vscode-docker &&\
    code-server --install-extension PKief.material-icon-theme &&\
    code-server --install-extension tencent-cloud.coding-copilot &&\
    echo done

# install Go Tools
ENV GOPATH /root/go
ENV PATH="${PATH}:${GOPATH}/bin"

RUN go install -v golang.org/x/tools/gopls@latest

# install goreleaser
RUN go install github.com/goreleaser/goreleaser/v2@latest

ENV LC_ALL zh_CN.UTF-8
ENV LANG zh_CN.UTF-8
ENV LANGUAGE zh_CN.UTF-8
