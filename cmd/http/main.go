// 单独的 HTTP 服务。逻辑全部在 internal/httpapi。
package main

import (
	"log"
	"net/http"

	"privacyfilter/filter"
	"privacyfilter/internal/env"
	"privacyfilter/internal/httpapi"
)

func main() {
	tomlPath := env.String("PF_GITLEAKS_TOML", "rules/gitleaks.toml")
	addr := ":" + env.String("PF_PORT", "8088")

	f, err := filter.New(tomlPath)
	if err != nil {
		log.Printf("加载 %s 失败：%v —— 改用内置规则", tomlPath, err)
		f, _ = filter.New("")
	}
	rules, skipped := f.Stats()
	log.Printf("就绪：gitleaks 规则 %d 条（跳过 %d 条不兼容）", rules, skipped)

	log.Printf("HTTP 监听 %s", addr)
	log.Fatal(http.ListenAndServe(addr, httpapi.Handler(f)))
}

