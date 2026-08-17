# ============ 阶段 1：编译（Go 静态编译，CGO 关闭，无运行时外部依赖）============
FROM golang:1.25-alpine AS build
WORKDIR /src
# 先复制依赖清单，利用 Docker 层缓存：依赖未变时跳过重新下载
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/bannerfp-server ./cmd/server \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/bannerfp-client ./cmd/client

# ============ 阶段 2：静态 wget（供 scratch 镜像内健康检查使用）============
FROM busybox:1.36-musl AS tools
RUN mkdir -p /out && cp /bin/busybox /out/ && ln -s busybox /out/wget

# ============ 阶段 3：scratch 极简运行镜像（无 shell、无包管理器，攻击面最小）============
FROM scratch
COPY --from=build /out/ /usr/local/bin/
COPY --from=tools /out/ /usr/local/bin/
# 非 root 用户运行（numeric 用户，scratch 无 /etc/passwd 也生效）
USER 65532:65532
# server 为默认入口；client 在 Compose 中以 command 覆盖
ENTRYPOINT ["/usr/local/bin/bannerfp-server"]
