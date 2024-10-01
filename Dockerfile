FROM golang:1.23.1-alpine3.20 AS builder

# 设置工作目录
WORKDIR /data/workspace

# 复制go.mod和go.sum文件并下载依赖
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o whois

FROM debian:bookworm

# 设置工作目录
WORKDIR /usr/local/app

# 复制构建的可执行文件和配置文件
COPY --from=builder /data/workspace/whois .
COPY --from=builder /data/workspace/config.json .

# 暴露应用程序的端口
EXPOSE 8043

# 运行应用程序
CMD ["/usr/local/app/whois"]