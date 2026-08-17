// bannerfp-server 指纹识别 HTTP 服务入口
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"bannerfp/internal/engine"
	"bannerfp/internal/server"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	port := envOr("PORT", "8080")
	rulesPath := envOr("RULES_PATH", "rules/fingerprints.yaml")

	// 启动即加载规则：加载失败直接退出（fail-fast），不带病运行
	eng, err := engine.New(rulesPath)
	if err != nil {
		logger.Error("规则加载失败", "error", err)
		os.Exit(1)
	}
	logger.Info("规则加载完成", "count", eng.RuleCount(), "path", rulesPath)

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           server.New(eng, logger).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// SIGHUP 热重载规则：运行期替换规则库无需重启（docker compose kill -s SIGHUP server）
	go watchReload(eng, logger)

	go func() {
		logger.Info("服务启动", "addr", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("服务异常退出", "error", err)
			os.Exit(1)
		}
	}()

	// 优雅关闭：SIGINT/SIGTERM 触发，10 秒内排空在途请求
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("优雅关闭失败", "error", err)
	}
	logger.Info("服务已关闭")
}

// watchReload 监听 SIGHUP 信号并重载规则
func watchReload(eng *engine.Engine, logger *slog.Logger) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	for range ch {
		if err := eng.Reload(); err != nil {
			logger.Error("规则热重载失败", "error", err)
			continue
		}
		logger.Info("规则热重载完成", "count", eng.RuleCount())
	}
}

// envOr 读取环境变量，未设置时返回默认值
func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
