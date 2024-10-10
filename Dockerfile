FROM golang:1.23.1 AS builder

# 设置工作目录
WORKDIR /data/workspace

# 复制go.mod和go.sum文件并下载依赖
COPY go.mod go.sum ./
RUN go mod download

# 复制源代码并构建可执行文件
COPY . .
RUN go build -o whois

# 调试：列出构建目录中的文件
RUN echo "构建阶段：列出/data/workspace目录中的文件"
RUN ls -la /data/workspace

FROM alpine

# 设置工作目录
WORKDIR /usr/local/app

# 复制构建的可执行文件和配置文件
COPY --from=builder /data/workspace/whois .
COPY --from=builder /data/workspace/config.json .

# 调试：列出应用目录中的文件
RUN echo "运行阶段：列出/usr/local/app目录中的文件"
RUN ls -la /usr/local/app

# 暴露Web端口
EXPOSE 8043

# 运行应用程序
CMD ["/usr/local/app/whois"]