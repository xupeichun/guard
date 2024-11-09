package main

import (
	"encoding/json"
	"flag"
	"fscan.desc.xpc.gx.cn/common"
	"fscan.desc.xpc.gx.cn/types"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

var listen string
var result types.Resp

func main() {
	flag.StringVar(&listen, "listen", ":8181", "HTTP server listen address")
	flag.Parse()

	http.HandleFunc("/api/v1/filename", func(w http.ResponseWriter, r *http.Request) {
		result.Code = http.StatusOK
		result.Msg = "succ"
		if r.Method != http.MethodGet {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		// 1. 获取请求参数poc filename
		urlQ := r.URL.Query()
		filename := urlQ.Get("filename")
		if filename == "" {
			http.Error(w, "filename is required", http.StatusBadRequest)
			return
		}
		log.Printf("get request with filename: %s", filename)
		if common.Status == 1 {
			result.Data = common.Dict1[filename]
		} else {
			result.Data = common.Dict2[filename]
		}
		if strings.TrimSpace(result.Data.PocFileName) == "" {
			result.Code = -1
			result.Msg = "未命中数据"
		}

		log.Printf("filename: %s response:%+v", filename, result)
		if err := json.NewEncoder(w).Encode(result); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		return
	})
	go common.LoadExcel(common.Dict1)
	var notice = make(chan bool)
	go common.DirWatch("./excel", notice)

	go func() {
		log.Printf("HTTP server listening on %s", listen)
		if err := http.ListenAndServe(listen, nil); err != nil {
			log.Fatalf("HTTP server start failed: %v", err)
		}
	}()
	signalChan := make(chan os.Signal)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	for sig := range signalChan {
		log.Printf("Received an interrupt:%s, stopping services...", sig)
		notice <- true
		time.Sleep(time.Second * 1)
		return
	}
		log.Printf("debug:diff 对比主线差异")
	log.Printf("debug:diff 对比主线差异2")
}
