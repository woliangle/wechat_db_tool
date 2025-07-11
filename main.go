package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
	"github.com/shirou/gopsutil/v3/process"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// 定义版本偏移映射
type VersionOffsetMap map[string][]uint

// 全局变量
var (
	keyHex      string
	wxID        string
	statusLabel *widget.Label
)

// 获取文件版本信息
func getFileVersion(filePath string) (string, error) {
	size, err := windows.GetFileVersionInfoSize(filePath, nil)
	if err != nil || size == 0 {
		return "", fmt.Errorf("无法获取版本信息: %v", err)
	}

	versionInfo := make([]byte, size)
	err = windows.GetFileVersionInfo(filePath, 0, size, unsafe.Pointer(&versionInfo[0]))
	if err != nil {
		return "", fmt.Errorf("获取版本信息失败: %v", err)
	}

	var fixedInfo *windows.VS_FIXEDFILEINFO
	fixedInfoLen := uint32(unsafe.Sizeof(*fixedInfo))
	err = windows.VerQueryValue(unsafe.Pointer(&versionInfo[0]), `\`, unsafe.Pointer(&fixedInfo), &fixedInfoLen)
	if err != nil || fixedInfoLen < uint32(unsafe.Sizeof(*fixedInfo)) || fixedInfo.Signature != 0xFEEF04BD {
		return "", fmt.Errorf("无效的版本信息")
	}

	major := fixedInfo.FileVersionMS >> 16
	minor := fixedInfo.FileVersionMS & 0xFFFF
	build := fixedInfo.FileVersionLS >> 16
	revision := fixedInfo.FileVersionLS & 0xFFFF

	return fmt.Sprintf("%d.%d.%d.%d", major, minor, build, revision), nil
}

// 获取WeChatWin.dll路径
func getDllPath(proc *process.Process) (string, error) {
	exePath, err := proc.Exe()
	if err != nil {
		return "", err
	}

	baseDir := filepath.Dir(exePath)
	
	// 首先检查版本化子目录
	matches, _ := filepath.Glob(filepath.Join(baseDir, "*", "WeChatWin.dll"))
	if len(matches) > 0 {
		return matches[0], nil
	}

	// 然后检查基本目录
	fallback := filepath.Join(baseDir, "WeChatWin.dll")
	if _, err := os.Stat(fallback); err == nil {
		return fallback, nil
	}

	return "", fmt.Errorf("找不到 WeChatWin.dll")
}

// 查找微信进程
func findWeChatProcess() (*process.Process, error) {
	processes, err := process.Processes()
	if err != nil {
		return nil, err
	}

	for _, p := range processes {
		name, err := p.Name()
		if err == nil && strings.EqualFold(name, "WeChat.exe") {
			return p, nil
		}
	}

	return nil, fmt.Errorf("未找到微信进程")
}

// 加载版本偏移映射
func loadVersionOffsetMap() (VersionOffsetMap, error) {
	exeDir := filepath.Dir(os.Args[0])
	paths := []string{
		"version_list.json",
		filepath.Join(exeDir, "version_list.json"),
	}

	var rawData []byte
	var err error
	for _, path := range paths {
		if rawData, err = os.ReadFile(path); err == nil {
			break
		}
	}

	if rawData == nil {
		return nil, fmt.Errorf("找不到 version_list.json")
	}

	var result VersionOffsetMap
	if err := json.Unmarshal(rawData, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// 提取数据库密钥
func extractDbKey(procHandle windows.Handle, baseAddr uintptr, keyOffset uint) ([]byte, error) {
	// 读取指针地址
	ptrAddr := baseAddr + uintptr(keyOffset)
	var pointer uintptr
	err := windows.ReadProcessMemory(
		procHandle,
		ptrAddr,
		(*byte)(unsafe.Pointer(&pointer)),
		unsafe.Sizeof(pointer),
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("读取指针失败: %v", err)
	}

	// 读取实际的密钥
	key := make([]byte, 32)
	err = windows.ReadProcessMemory(procHandle, pointer, &key[0], 32, nil)
	if err != nil {
		return nil, fmt.Errorf("读取密钥失败: %v", err)
	}

	return key, nil
}

// 获取模块基址
func getModuleBaseAddress(procHandle windows.Handle, moduleName string) (uintptr, error) {
	// 加载psapi.dll
	psapi, err := syscall.LoadLibrary("psapi.dll")
	if err != nil {
		return 0, fmt.Errorf("加载psapi.dll失败: %v", err)
	}
	defer syscall.FreeLibrary(psapi)

	// 获取函数地址
	enumProcessModules, err := syscall.GetProcAddress(psapi, "EnumProcessModules")
	if err != nil {
		return 0, fmt.Errorf("获取EnumProcessModules地址失败: %v", err)
	}

	getModuleBaseName, err := syscall.GetProcAddress(psapi, "GetModuleBaseNameW")
	if err != nil {
		return 0, fmt.Errorf("获取GetModuleBaseNameW地址失败: %v", err)
	}

	// 枚举模块
	modules := make([]syscall.Handle, 1024)
	var cbNeeded uint32

	ret, _, _ := syscall.Syscall6(
		uintptr(enumProcessModules),
		4,
		uintptr(procHandle),
		uintptr(unsafe.Pointer(&modules[0])),
		uintptr(len(modules)*int(unsafe.Sizeof(modules[0]))),
		uintptr(unsafe.Pointer(&cbNeeded)),
		0, 0,
	)
	if ret == 0 {
		return 0, fmt.Errorf("EnumProcessModules失败")
	}

	moduleCount := int(cbNeeded / uint32(unsafe.Sizeof(modules[0])))
	
	// 查找目标模块
	for i := 0; i < moduleCount; i++ {
		var name [256]uint16
		ret, _, _ := syscall.Syscall6(
			uintptr(getModuleBaseName),
			4,
			uintptr(procHandle),
			uintptr(modules[i]),
			uintptr(unsafe.Pointer(&name[0])),
			uintptr(len(name)),
			0, 0,
		)

		if ret > 0 && syscall.UTF16ToString(name[:]) == moduleName {
			return uintptr(modules[i]), nil
		}
	}

	return 0, fmt.Errorf("未找到模块: %s", moduleName)
}

// 获取微信ID - 改进版本：尝试多种方法
func getWxid() (string, error) {
	// 方法1：尝试从注册表直接获取UserID
	wxid, err := getWxidFromRegistry()
	if err == nil && wxid != "" {
		return wxid, nil
	}
	
	// 方法2：尝试从文件系统获取
	wxid, err = getWxidFromFileSystem()
	if err == nil && wxid != "" {
		return wxid, nil
	}
	
	return "", fmt.Errorf("无法获取微信ID，所有方法均失败")
}

// 从注册表直接获取UserID
func getWxidFromRegistry() (string, error) {
	k, err := registry.OpenKey(
		registry.CURRENT_USER,
		`Software\Tencent\WeChat`,
		registry.QUERY_VALUE,
	)
	if err != nil {
		return "", err
	}
	defer k.Close()

	userID, _, err := k.GetStringValue("UserID")
	if err != nil {
		return "", err
	}

	return userID, nil
}

// 从文件系统获取微信ID
func getWxidFromFileSystem() (string, error) {
	// 获取文档目录路径
	docDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	// 尝试多个可能的路径
	possiblePaths := []string{
		filepath.Join(docDir, "Documents", "WeChat Files"),
		filepath.Join(docDir, "文档", "WeChat Files"), // 中文系统
		filepath.Join(docDir, "OneDrive", "文档", "WeChat Files"), // OneDrive路径
		filepath.Join(docDir, "WeChat Files"), // 直接在主目录
	}

	var foundPath string
	for _, path := range possiblePaths {
		if _, err := os.Stat(path); err == nil {
			foundPath = path
			break
		}
	}

	if foundPath == "" {
		return "", fmt.Errorf("未找到微信数据目录")
	}

	// 获取所有子目录
	entries, err := os.ReadDir(foundPath)
	if err != nil {
		return "", err
	}

	// 查找wxid_开头的目录
	var wxidDirs []string
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "wxid_") {
			wxidDirs = append(wxidDirs, entry.Name())
		}
	}

	// 处理找到的目录
	switch len(wxidDirs) {
	case 0:
		return "", fmt.Errorf("未找到微信ID目录")
	case 1:
		return wxidDirs[0], nil
	default:
		// 如果有多个wxid目录，尝试找到最近活跃的
		return findMostRecentWxidDir(foundPath, wxidDirs)
	}
}

// 查找最近活跃的wxid目录
func findMostRecentWxidDir(basePath string, wxidDirs []string) (string, error) {
	var mostRecentDir string
	var mostRecentTime time.Time

	for _, dir := range wxidDirs {
		dirPath := filepath.Join(basePath, dir)
		
		// 检查目录修改时间
		info, err := os.Stat(dirPath)
		if err != nil {
			continue
		}
		
		// 使用修改时间作为活跃度指标
		modTime := info.ModTime()
		if modTime.After(mostRecentTime) {
			mostRecentTime = modTime
			mostRecentDir = dir
		}
	}

	if mostRecentDir == "" {
		return "", fmt.Errorf("无法确定活跃微信账号")
	}

	return mostRecentDir, nil
}

// 主获取函数
func getWeChatInfo() (string, string, error) {
	proc, err := findWeChatProcess()
	if err != nil {
		return "", "", err
	}

	dllPath, err := getDllPath(proc)
	if err != nil {
		return "", "", err
	}

	version, err := getFileVersion(dllPath)
	if err != nil {
		return "", "", err
	}

	vm, err := loadVersionOffsetMap()
	if err != nil {
		return "", "", err
	}

	offsets, exists := vm[version]
	if !exists {
		return "", "", fmt.Errorf("版本 %s 不在偏移表中", version)
	}
	
	if len(offsets) < 5 {
		return "", "", fmt.Errorf("版本 %s 的偏移量数量不足", version)
	}

	procHandle, err := windows.OpenProcess(
		windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ,
		false,
		uint32(proc.Pid),
	)
	if err != nil {
		return "", "", fmt.Errorf("打开进程失败: %v", err)
	}
	defer windows.CloseHandle(procHandle)

	baseAddr, err := getModuleBaseAddress(procHandle, "WeChatWin.dll")
	if err != nil {
		return "", "", err
	}

	key, err := extractDbKey(procHandle, baseAddr, offsets[4])
	if err != nil {
		return "", "", err
	}

	wxid, err := getWxid()
	if err != nil {
		// 即使获取wxid失败，仍然返回key
		return hex.EncodeToString(key), "", fmt.Errorf("获取微信ID失败: %v", err)
	}

	return hex.EncodeToString(key), wxid, nil
}

// GUI界面
func createUI() {
	myApp := app.New()
	window := myApp.NewWindow("微信数据库密钥提取工具")
	window.Resize(fyne.NewSize(500, 300))

	keyEntry := widget.NewEntry()
	wxidEntry := widget.NewEntry()
	statusLabel = widget.NewLabel("就绪")
	statusLabel.Wrapping = fyne.TextWrapWord

	getButton := widget.NewButton("获取密钥", func() {
		statusLabel.SetText("正在查找微信进程...")
		
		key, id, err := getWeChatInfo()
		if err != nil {
			// 即使wxid获取失败，仍然显示key
			if key != "" {
				keyEntry.SetText(key)
				wxidEntry.SetText("获取失败: " + err.Error())
				statusLabel.SetText("成功获取密钥，但获取微信ID失败: " + err.Error())
			} else {
				statusLabel.SetText(fmt.Sprintf("错误: %v", err))
			}
			return
		}
		
		keyEntry.SetText(key)
		wxidEntry.SetText(id)
		statusLabel.SetText("成功获取密钥和微信ID!")
	})

	copyKeyButton := widget.NewButton("复制密钥", func() {
		window.Clipboard().SetContent(keyEntry.Text)
		statusLabel.SetText("密钥已复制到剪贴板")
	})

	copyWxidButton := widget.NewButton("复制微信ID", func() {
		window.Clipboard().SetContent(wxidEntry.Text)
		statusLabel.SetText("微信ID已复制到剪贴板")
	})

	form := widget.NewForm(
		widget.NewFormItem("数据库密钥:", keyEntry),
		widget.NewFormItem("微信ID:", wxidEntry),
	)

	buttonBox := container.NewHBox(
		getButton,
		copyKeyButton,
		copyWxidButton,
	)

	content := container.NewVBox(
		form,
		buttonBox,
		statusLabel,
	)

	window.SetContent(content)
	window.ShowAndRun()
}

func main() {
	createUI()
}