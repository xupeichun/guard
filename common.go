package common

import (
	"fmt"
	"fscan.desc.xpc.gx.cn/types"
	"github.com/fsnotify/fsnotify"
	"github.com/xuri/excelize/v2"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

var Status int32 = 1
var eventNotify int32 = 0
var Dict1 = types.ResultDict{}
var Dict2 = types.ResultDict{}
var mx sync.Mutex

// DirWatch 监听目录有无变化
func DirWatch(watchPath string, notice chan bool) {
	// 创建一个 watcher 实例
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatalf("watcher init err:%s", err)
	}
	defer watcher.Close()

	// 开始监听指定目录
	err = watcher.Add(watchPath)
	if err != nil {
		log.Fatalf("watcher add path err:%s", err)
	}
	log.Printf("start to 监听 %s", watchPath)
	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				log.Println("error:", err)
				return
			}
			fmt.Printf("event name:%s, operate:%s\n", event.Name, event.Op.String())
			eventNotify = 1
		case <-time.After(time.Second):
			if eventNotify == 0 {
				continue
			}
			mx.Lock()
			if Status == 1 {
				Dict2 = types.ResultDict{}
				LoadExcel(Dict2)
				Status = 2
			} else {
				Dict1 = types.ResultDict{}
				Status = 1
				LoadExcel(Dict1)
			}
			eventNotify = 0
			mx.Unlock()
		case err, ok := <-watcher.Errors:
			if !ok {
				log.Println("error:", err)
				return
			}

		case <-notice:
			log.Printf("---------------------stop service-----------------")
			return
		}
	}
}

// DirTraverse 遍历目录
func DirTraverse(dirPath string) []string {
	var fileList = make([]string, 0)
	err := filepath.Walk(dirPath, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			log.Printf("dir traverse err:%s", err)
			return nil
		}
		if !info.IsDir() {
			//fmt.Printf("File: %s (size: %d bytes)\n", path, info.Size())
			fileList = append(fileList, path)
		}
		return nil
	})
	if err != nil {
		log.Printf("dir traverse err:%s", err)
		return nil
	}
	return fileList
}

// IsExcelFile 检查是否是excel文件
func IsExcelFile(filePath string) bool {
	// 读取文件的前 4 个字节
	file, err := os.Open(filePath)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	buffer := make([]byte, 4)
	_, err = file.Read(buffer)
	if err != nil {
		log.Fatal(err)
	}

	// 检查文件签名
	if len(buffer) >= 4 {
		if buffer[0] == 0x50 && buffer[1] == 0x4B && buffer[2] == 0x03 && buffer[3] == 0x04 {
			// .xlsx 文件签名
			return true
		}
		if len(buffer) >= 8 && buffer[0] == 0xD0 && buffer[1] == 0xCF && buffer[2] == 0x11 && buffer[3] == 0xE0 &&
			buffer[4] == 0xA1 && buffer[5] == 0xB1 && buffer[6] == 0x1A && buffer[7] == 0xE1 {
			// .xls 文件签名
			return true
		}
	}

	return false
}

// ExcelFileParse excel文件解析
func ExcelFileParse(filePath string) (vulnerList *types.List, err error) {
	// 打开一个现有的 Excel 文件
	var f *excelize.File
	if f, err = excelize.OpenFile(filePath); err != nil {
		log.Printf("parse excel file:%s err:%s", filePath, err)
		return nil, err
	}
	vulnerList = &types.List{}
	// 获取工作表的名称
	sheets := f.GetSheetMap()
	for _, sheetName := range sheets {
		//log.Printf("Sheet: %s", sheetName)
		if sheetName != "Sheet1" {
			continue
		}
		// 遍历工作表中的所有行和列
		rows, err := f.GetRows(sheetName)
		if err != nil {
			log.Printf("sheetName get rows err:%s", err)
			return nil, err
		}
		var vulner types.Vuln
		for k, row := range rows {
			if k == 0 { //去掉表头
				continue
			}
			if len(row) < 7 {
				log.Printf("sheetName:%s 数据结构不全", sheetName)
				continue
			}
			vulner.PocFileName = row[0]
			vulner.CveId = row[1]
			vulner.PocName = row[2]
			vulner.DestSysDesc = row[3]
			vulner.PocDesc = row[4]
			vulner.Solution = row[5]
			isOptimizeStr := row[6]
			num, err := strconv.Atoi(isOptimizeStr)
			if err != nil {
				log.Printf("isOptimizeStr;%s atoi err:%s", isOptimizeStr, err)
				return nil, err
			}
			vulner.IsOptimize = num
			if vulnerList.VulnInfo == nil {
				vulnerList.VulnInfo = map[string]types.Vuln{}
			}
			vulnerList.VulnInfo[vulner.PocFileName] = vulner
		}
	}
	//log.Printf("debug:%+v", vulnerList)
	return vulnerList, nil
}

// LoadExcel 加载到内存
func LoadExcel(dict types.ResultDict) {
	fileList := DirTraverse("./excel")
	for _, path := range fileList {
		if ok := IsExcelFile(path); !ok {
			log.Printf("file:%s is not excel type file", path)
			continue
		}
		log.Printf("excel file path:%s", path)

		tmpMap, err := ExcelFileParse(path)
		if err != nil {
			log.Printf("excel file:%s parse err:%s", path, err)
			continue
		}
		for pocFileName, vulner := range tmpMap.VulnInfo {
			dict[pocFileName] = vulner
		}
	}
}
