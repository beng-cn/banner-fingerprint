// bannerfp-client 扫描数据批量识别客户端：
// 读取本地 JSON 文件 → 分批提交 server → 终端表格展示识别结果。
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"text/tabwriter"
	"time"

	"bannerfp/internal/model"
)

func main() {
	serverAddr := flag.String("server", "http://localhost:8080", "server 地址")
	file := flag.String("file", "", "扫描数据 JSON 文件路径（必填）")
	batchSize := flag.Int("batch", 100, "每批提交条数")
	timeout := flag.Duration("timeout", 30*time.Second, "HTTP 请求超时")
	flag.Parse()
	if *file == "" {
		fmt.Fprintln(os.Stderr, "用法: bannerfp-client -file <扫描数据.json> [-server http://localhost:8080] [-batch 100]")
		os.Exit(2)
	}

	records, err := loadRecords(*file)
	if err != nil {
		fmt.Fprintln(os.Stderr, "读取数据文件失败:", err)
		os.Exit(1)
	}
	if len(records) == 0 {
		fmt.Fprintln(os.Stderr, "数据文件为空")
		os.Exit(1)
	}

	httpc := &http.Client{Timeout: *timeout}
	var all []model.Result
	for start := 0; start < len(records); start += *batchSize {
		end := min(start+*batchSize, len(records))
		res, err := postBatch(httpc, *serverAddr, records[start:end])
		if err != nil {
			fmt.Fprintln(os.Stderr, "提交 server 失败:", err)
			os.Exit(1)
		}
		all = append(all, res.Results...)
	}

	printTable(all)
}

// loadRecords 读取数据文件，兼容两种格式：顶层 JSON 数组，或 {"records":[...]} 包装对象
func loadRecords(path string) ([]model.Record, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var records []model.Record
	if err := json.Unmarshal(raw, &records); err == nil {
		return records, nil
	}
	var wrapped model.FingerprintRequest
	if err := json.Unmarshal(raw, &wrapped); err != nil {
		return nil, fmt.Errorf("文件必须是 JSON 数组或 {\"records\":[...]} 对象: %w", err)
	}
	return wrapped.Records, nil
}

// postBatch 单批提交到 POST /fingerprint
func postBatch(httpc *http.Client, addr string, records []model.Record) (*model.FingerprintResponse, error) {
	body, err := json.Marshal(model.FingerprintRequest{Records: records})
	if err != nil {
		return nil, err
	}
	resp, err := httpc.Post(addr+"/fingerprint", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server 返回状态 %d: %s", resp.StatusCode, string(raw))
	}
	var out model.FingerprintResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("解析响应失败: %w", err)
	}
	return &out, nil
}

// printTable 终端表格展示识别结果 + 统计
func printTable(results []model.Result) {
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "IP\tPORT\tPROTOCOL\tPRODUCT\tVERSION\tOS_HINT\tCONFIDENCE")
	known := 0
	for _, r := range results {
		if r.Protocol != "unknown" && r.Protocol != "" {
			known++
		}
		fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\t%s\t%.2f\n",
			r.IP, r.Port, r.Protocol, r.Product, r.Version, r.OsHint, r.Confidence)
	}
	w.Flush()
	fmt.Printf("\n共 %d 条：识别成功 %d 条，unknown %d 条\n", len(results), known, len(results)-known)
}
