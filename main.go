package main

import (
	"bufio"
	"fmt"
	"io/fs"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/tidwall/gjson"
	"github.com/xuri/excelize/v2"
)

type Result struct {
	URL      string
	PoC      string
	Template string
	Severity string
}

var (
	resultLock sync.Mutex
	results    []Result
	semaphore  = make(chan struct{}, 10) // 最大同时运行10个 nuclei
)

func main() {
	os.MkdirAll("nuclei_results", 0755)

	reader := bufio.NewReader(os.Stdin)
	fmt.Println("请选择模式：")
	fmt.Println("1. 输入 txt 文件，清洗并调用 ehole 后续测试")
	fmt.Println("2. 直接输入已有 xlsx 文件，跳过 ehole 扫描")
	fmt.Print("输入模式编号：")
	modeInput, _ := reader.ReadString('\n')
	mode := strings.TrimSpace(modeInput)

	var outputFile string
	if mode == "1" {
		fmt.Print("请输入待扫描的txt文件名（不带后缀）: ")
		inputName, _ := reader.ReadString('\n')
		inputName = strings.TrimSpace(inputName)
		cleanedInput := inputName + "_cleaned.txt"
		if err := cleanTxtFile(inputName+".txt", cleanedInput); err != nil {
			fmt.Println("清洗 txt 文件失败:", err)
			return
		}
		cleanedInEhole := filepath.Join("ehole_windows", filepath.Base(cleanedInput))
		outputFile = inputName + ".xlsx"
		if err := runEhole(cleanedInEhole, outputFile); err != nil {
			fmt.Println("运行 ehole 失败（忽略错误继续）：", err)
		}
	} else if mode == "2" {
		fmt.Print("请输入已有xlsx文件名（不带后缀）: ")
		inputName, _ := reader.ReadString('\n')
		inputName = strings.TrimSpace(inputName)
		outputFile = inputName + ".xlsx"
		if _, err := os.Stat(outputFile); os.IsNotExist(err) {
			fmt.Printf("❌ 找不到文件 %s，请确认它是否存在！\n", outputFile)
			return
		}
	} else {
		fmt.Println("无效模式，请输入 1 或 2")
		return
	}

	f, _ := excelize.OpenFile(outputFile)
	rows, _ := f.GetRows("Sheet1")

	cmsMap := map[string][]string{}
	serverMap := map[string][]string{}

	for i, row := range rows {
		if i == 0 || len(row) < 3 {
			continue
		}
		url := strings.TrimSpace(row[0])
		cms := strings.ToLower(strings.TrimSpace(row[1]))
		server := strings.ToLower(strings.TrimSpace(row[2]))
		if url != "" {
			if cms != "" {
				cmsMap[cms] = append(cmsMap[cms], url)
			}
			if server != "" {
				serverMap[server] = append(serverMap[server], url)
			}
		}
	}

	scanGrouped("CMS", cmsMap)
	scanGrouped("Server", serverMap)
	parseAllNucleiResults("nuclei_results")
	exportResultExcel("scan_result.xlsx")
	fmt.Printf("\n🎯 共发现 %d 个漏洞，结果保存在 scan_result.xlsx\n", len(results))
}

func scanGrouped(groupType string, group map[string][]string) {
	fmt.Printf("\n===== %s 漏洞检测开始（并发受限） =====\n", groupType)

	for keyword, urls := range group {
		fmt.Printf("\n[%s: %s] 共 %d 个目标 URL\n", groupType, keyword, len(urls))

		cves := searchRealCVE(keyword)
		pocs := findYAMLs(cves)
		cnvd := findCNVDYAMLs(keyword)
		pocs = append(pocs, cnvd...)
		kwPocs := findKeywordYAMLs(keyword)
		pocs = append(pocs, kwPocs...)

		if len(pocs) == 0 {
			fmt.Println("  → 未找到任何 PoC，跳过。")
			continue
		}

		var wg sync.WaitGroup
		for _, url := range urls {
			for _, poc := range pocs {
				wg.Add(1)
				go func(u, p string) {
					defer wg.Done()
					semaphore <- struct{}{} // 占位
					runNucleiScan(u, p)
					<-semaphore // 释放
				}(url, poc)
			}
		}
		wg.Wait()
	}
}

func runNucleiScan(url, pocPath string) {
	fmt.Printf("正在扫描：%s\n", url)
	timestamp := time.Now().Format("20060102_150405.000")
	base := filepath.Base(pocPath)
	filename := fmt.Sprintf("nuclei_results/result_%s_%s.json", timestamp, base)

	cmd := exec.Command(filepath.Join("nuclei", "nuclei.exe"),
		"-u", url,
		"-t", pocPath,
		"-json",
		"-o", filename,
	)
	_ = cmd.Run()
}

func parseAllNucleiResults(dir string) {
	files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	for _, file := range files {
		data, _ := os.ReadFile(file)
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) == "" {
				continue
			}
			url := gjson.Get(line, "host").String()
			tpl := gjson.Get(line, "template-id").String()
			severity := gjson.Get(line, "info.severity").String()
			if url != "" && tpl != "" {
				resultLock.Lock()
				results = append(results, Result{
					URL:      url,
					PoC:      tpl,
					Template: tpl,
					Severity: severity,
				})
				resultLock.Unlock()
			}
		}
	}
}

func exportResultExcel(filename string) {
	f := excelize.NewFile()
	sheet := "Result"
	_, _ = f.NewSheet(sheet)
	f.SetCellValue(sheet, "A1", "URL")
	f.SetCellValue(sheet, "B1", "PoC")
	f.SetCellValue(sheet, "C1", "模板")
	f.SetCellValue(sheet, "D1", "严重性")

	for i, r := range results {
		f.SetCellValue(sheet, fmt.Sprintf("A%d", i+2), r.URL)
		f.SetCellValue(sheet, fmt.Sprintf("B%d", i+2), r.PoC)
		f.SetCellValue(sheet, fmt.Sprintf("C%d", i+2), r.Template)
		f.SetCellValue(sheet, fmt.Sprintf("D%d", i+2), r.Severity)
	}
	f.SaveAs(filename)
}

func cleanTxtFile(inputPath, outputPath string) error {
	data, _ := os.ReadFile(inputPath)
	lines := strings.Split(string(data), "\n")
	unique := make(map[string]bool)
	var cleaned []string
	for _, line := range lines {
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		base := extractBaseURL(t)
		if base != "" && !unique[base] {
			unique[base] = true
			cleaned = append(cleaned, base)
		}
	}
	_ = os.WriteFile(outputPath, []byte(strings.Join(cleaned, "\n")), 0644)
	eholeCopyPath := filepath.Join("ehole_windows", filepath.Base(outputPath))
	return os.WriteFile(eholeCopyPath, []byte(strings.Join(cleaned, "\n")), 0644)
}

func extractBaseURL(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if !strings.Contains(trimmed, "://") {
		return trimmed
	}
	u, err := url.Parse(trimmed)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	host := u.Host
	if !strings.Contains(host, ":") {
		if u.Scheme == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}
	return fmt.Sprintf("%s://%s", u.Scheme, host)
}

func runEhole(input string, output string) error {
	cmd := exec.Command(filepath.Join("ehole_windows", "ehole_windows.exe"), "finger", "-l", input, "-o", output)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func searchRealCVE(keyword string) []string {
	apiURL := "https://cve.circl.lu/api/search/" + keyword
	resp, err := http.Get(apiURL)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	var cves []string
	results := gjson.Get(string(body), "data.#.id")
	results.ForEach(func(_, v gjson.Result) bool {
		cves = append(cves, v.String())
		return true
	})
	if len(cves) > 5 {
		cves = cves[:5]
	}
	return cves
}

func findYAMLs(cves []string) []string {
	var files []string
	for _, cve := range cves {
		match := filepath.Join("poc", "cve", cve+".yaml")
		if _, err := os.Stat(match); err == nil {
			files = append(files, match)
		}
	}
	return files
}

func findCNVDYAMLs(keyword string) []string {
	var files []string
	entries, err := os.ReadDir("poc/cve")
	if err != nil {
		return files
	}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, "CNVD") && strings.Contains(strings.ToLower(name), keyword) {
			files = append(files, filepath.Join("poc", "cve", name))
		}
	}
	return files
}

func findKeywordYAMLs(keyword string) []string {
	var files []string
	filepath.WalkDir("poc", func(path string, d fs.DirEntry, err error) error {
		if err == nil && strings.HasSuffix(path, ".yaml") && strings.Contains(strings.ToLower(path), keyword) {
			files = append(files, path)
		}
		return nil
	})
	return files
}
