// Package model 定义 client 与 server 共享的数据传输对象（DTO）
package model

// Record 扫描原始数据：一条待识别的网络探测记录
type Record struct {
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	Banner string `json:"banner"`
}

// Result 指纹识别结果（字段与验收示例对齐）
type Result struct {
	IP         string  `json:"ip"`
	Port       int     `json:"port"`
	Protocol   string  `json:"protocol"`
	Product    string  `json:"product"`
	Version    string  `json:"version"`
	OsHint     string  `json:"os_hint"`
	Confidence float64 `json:"confidence"`
}

// FingerprintRequest POST /fingerprint 批量识别入参
type FingerprintRequest struct {
	Records []Record `json:"records"`
}

// FingerprintResponse POST /fingerprint 批量识别出参
type FingerprintResponse struct {
	Results []Result `json:"results"`
}
