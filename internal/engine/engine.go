// Package engine 指纹识别引擎：规则库（YAML）与代码完全解耦，
// 识别流程 = 端口先验筛选候选 → 正则逐条匹配 → 捕获组提取 → 置信度评分。
package engine

import (
	"fmt"
	"math"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"

	"gopkg.in/yaml.v3"

	"bannerfp/internal/model"
)

// 置信度算法系数（对齐验收示例的档位：0.95/0.90/0.85/0.70）
const (
	confBase    = 0.42 // 规则命中基础分
	confPort    = 0.03 // 端口先验命中
	confProduct = 0.25 // product 确定
	confVersion = 0.20 // version 提取成功
	confOS      = 0.05 // os_hint 提取成功
)

// Rule 一条指纹识别规则，全部来自 YAML 规则库，代码中零硬编码。
// 捕获组约定：software/product（软件名，可覆盖默认 product）、version（版本）、os（OS 特征）。
type Rule struct {
	ID        string            `yaml:"id"`
	Protocol  string            `yaml:"protocol"`
	Product   string            `yaml:"product"`
	PortHints []int             `yaml:"port_hints"`
	Priority  int               `yaml:"priority"`
	ConfBias  float64           `yaml:"conf_bias"` // 规则级置信度微调（如 Jetty -0.05）
	OsMap     map[string]string `yaml:"os_map"`    // OS 捕获组规范化映射（ubuntu → Ubuntu）
	Patterns  []string          `yaml:"patterns"`

	compiled []*regexp.Regexp
}

// matchResult 单条规则的命中结果（捕获组提取值）
type matchResult struct {
	rule    *Rule
	product string
	version string
	os      string
}

// Engine 识别引擎。规则快照通过 atomic.Pointer 只读共享，并发识别零锁竞争。
type Engine struct {
	path  string
	rules atomic.Pointer[[]Rule]
}

// New 从规则文件加载并构造引擎
func New(path string) (*Engine, error) {
	e := &Engine{path: path}
	if err := e.Reload(); err != nil {
		return nil, err
	}
	return e, nil
}

// Reload 重新加载规则（启动时与 SIGHUP 热重载共用入口），原子替换快照
func (e *Engine) Reload() error {
	raw, err := os.ReadFile(e.path)
	if err != nil {
		return fmt.Errorf("读取规则文件: %w", err)
	}
	var cfg struct {
		Rules []Rule `yaml:"rules"`
	}
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return fmt.Errorf("解析规则文件: %w", err)
	}
	for i := range cfg.Rules {
		r := &cfg.Rules[i]
		r.compiled = r.compiled[:0]
		for _, p := range r.Patterns {
			re, err := regexp.Compile(p)
			if err != nil {
				return fmt.Errorf("规则 %s 正则编译失败: %w", r.ID, err)
			}
			r.compiled = append(r.compiled, re)
		}
	}
	// 按优先级降序，匹配时先到先得
	sort.Slice(cfg.Rules, func(i, j int) bool { return cfg.Rules[i].Priority > cfg.Rules[j].Priority })
	e.rules.Store(&cfg.Rules)
	return nil
}

// RuleCount 当前已加载规则数（供 /health 暴露）
func (e *Engine) RuleCount() int {
	rules := e.rules.Load()
	if rules == nil {
		return 0
	}
	return len(*rules)
}

// Identify 识别单条记录。防御性 recover：任何意外一律归为 unknown，绝不向上抛 panic。
func (e *Engine) Identify(rec model.Record) (res model.Result) {
	defer func() {
		if recover() != nil {
			res = unknownResult(rec)
		}
	}()

	banner := strings.TrimSpace(rec.Banner)
	if banner == "" {
		return unknownResult(rec)
	}
	rules := *e.rules.Load()

	// 第一轮：仅匹配端口先验命中的规则，降低非标端口上的误判
	best := scan(rules, rec.Port, banner, true)
	if best == nil {
		// 第二轮：非标端口仍可凭 banner 特征识别（如 8080 上的 Jetty）
		best = scan(rules, rec.Port, banner, false)
	}
	if best == nil {
		return unknownResult(rec)
	}

	conf := confBase + best.rule.ConfBias
	if contains(best.rule.PortHints, rec.Port) {
		conf += confPort
	}
	if best.product != "" {
		conf += confProduct
	}
	if best.version != "" {
		conf += confVersion
	}
	osHint := normalizeOS(best.os, best.rule.OsMap)
	if osHint != "" {
		conf += confOS
	}

	return model.Result{
		IP:         rec.IP,
		Port:       rec.Port,
		Protocol:   best.rule.Protocol,
		Product:    best.product,
		Version:    best.version,
		OsHint:     osHint,
		Confidence: round2(clamp(conf)),
	}
}

// scan 按优先级顺序尝试匹配；portHintsOnly=true 时只考虑端口先验命中的规则
func scan(rules []Rule, port int, banner string, portHintsOnly bool) *matchResult {
	for i := range rules {
		r := &rules[i]
		if portHintsOnly && !contains(r.PortHints, port) {
			continue
		}
		for _, re := range r.compiled {
			m := re.FindStringSubmatch(banner)
			if m == nil {
				continue
			}
			res := &matchResult{rule: r, product: r.Product}
			for j, name := range re.SubexpNames() {
				if j == 0 || name == "" {
					continue
				}
				switch name {
				case "product", "software": // 捕获组可覆盖规则默认 product
					if m[j] != "" {
						res.product = m[j]
					}
				case "version":
					res.version = m[j]
				case "os":
					res.os = m[j]
				}
			}
			return res
		}
	}
	return nil
}

// normalizeOS 规范化 OS 捕获组：取第一段（Ubuntu-3ubuntu0.10 → ubuntu）后查映射表，
// 映射表未命中时首字母大写返回原词
func normalizeOS(raw string, osMap map[string]string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	seg := strings.Split(strings.Split(raw, "-")[0], "_")[0]
	low := strings.ToLower(seg)
	if v, ok := osMap[low]; ok {
		return v
	}
	if seg == "" {
		return ""
	}
	return strings.ToUpper(seg[:1]) + seg[1:]
}

func unknownResult(rec model.Record) model.Result {
	return model.Result{IP: rec.IP, Port: rec.Port, Protocol: "unknown", Confidence: 0}
}

func contains(haystack []int, needle int) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}

func clamp(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func round2(v float64) float64 {
	return math.Round(v*100) / 100
}
