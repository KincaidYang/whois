FROM golang:alpine AS builder

# 设置工作目录
WORKDIR /data/workspace

# 复制go.mod和go.sum文件并下载依赖
COPY go.mod go.sum ./
RUN go mod download

# 复制源代码并构建可执行文件
COPY . .

# 版本号由构建参数注入：golang:alpine 里没有 git，Go 无法自行写入 VCS 信息，
# 不传则 /info 与 MCP 的版本号显示为 dev
ARG VERSION=""
ARG COMMIT=""
RUN go build -ldflags "-X github.com/KincaidYang/whois/internal/config.buildVersion=${VERSION} -X github.com/KincaidYang/whois/internal/config.buildCommit=${COMMIT}" -o whois

FROM alpine

# 设置工作目录
WORKDIR /usr/local/app

# 复制构建的可执行文件
COPY --from=builder /data/workspace/whois .

# 直接使用 Docker 配置文件
COPY config.docker.yaml ./config.yaml

# 暴露Web端口
EXPOSE 8043

# 运行应用程序
CMD ["/usr/local/app/whois"]