// Package server HTTP 薄层：只做参数绑定 + 调用识别引擎 + 统一响应，不含业务逻辑。
package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"bannerfp/internal/model"
)

// Identifier 识别引擎接口（依赖倒置：HTTP 层只依赖抽象，构造函数注入）
type Identifier interface {
	Identify(model.Record) model.Result
	RuleCount() int
}

// Server HTTP 服务
type Server struct {
	engine  Identifier
	logger  *slog.Logger
	maxBody int64 // 请求体大小上限（字节）
}

// New 构造函数注入引擎与日志器
func New(engine Identifier, logger *slog.Logger) *Server {
	return &Server{engine: engine, logger: logger, maxBody: 10 << 20} // 10MB
}

// Handler 组装路由（Go 1.22+ 方法路由）
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /fingerprint", s.fingerprint)
	mux.HandleFunc("GET /health", s.health)
	return s.recoverPanic(s.logging(mux))
}

// fingerprint 批量识别：POST /fingerprint
// 入参 {"records":[{"ip":"...","port":22,"banner":"..."}]}，逐条独立识别，单条异常不影响整批
func (s *Server) fingerprint(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, s.maxBody)
	var req model.FingerprintRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, 400, "请求体必须是 JSON 对象：{\"records\":[{\"ip\":\"...\",\"port\":80,\"banner\":\"...\"}]}")
		return
	}
	results := make([]model.Result, 0, len(req.Records))
	for _, rec := range req.Records {
		results = append(results, s.identifySafe(rec))
	}
	s.writeJSON(w, model.FingerprintResponse{Results: results})
}

// identifySafe 逐条识别 + recover 兜底：任何单条异常都归为 unknown，绝不中断整批
func (s *Server) identifySafe(rec model.Record) (res model.Result) {
	defer func() {
		if p := recover(); p != nil {
			s.logger.Error("单条识别异常，已归为 unknown", "ip", rec.IP, "port", rec.Port, "panic", p)
			res = model.Result{IP: rec.IP, Port: rec.Port, Protocol: "unknown", Confidence: 0}
		}
	}()
	return s.engine.Identify(rec)
}

// health 健康检查：GET /health，同时暴露规则加载状态供真实探活
func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	s.writeJSON(w, map[string]any{
		"status":  "ok",
		"service": "banner-fingerprint",
		"rules":   s.engine.RuleCount(),
		"time":    time.Now().Format(time.RFC3339),
	})
}

// writeJSON 统一 JSON 成功响应
func (s *Server) writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		s.logger.Error("写响应失败", "error", err)
	}
}

// writeError 统一错误响应：HTTP 状态码始终 200，业务状态通过 code 字段区分
func (s *Server) writeError(w http.ResponseWriter, code int, msg string) {
	s.writeJSON(w, map[string]any{"code": code, "message": msg})
}

// logging 请求日志中间件
func (s *Server) logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		s.logger.Info("请求",
			"method", r.Method, "path", r.URL.Path,
			"remote", r.RemoteAddr, "cost", time.Since(start).String())
	})
}

// recoverPanic 全局兜底中间件：任何未捕获 panic 都转 200 + 错误 JSON，服务不崩
func (s *Server) recoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if p := recover(); p != nil {
				s.logger.Error("请求处理 panic", "panic", p, "path", r.URL.Path)
				s.writeError(w, 500, "内部错误")
			}
		}()
		next.ServeHTTP(w, r)
	})
}
