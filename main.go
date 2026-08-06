package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/Bugs5382/go-certkit"
)

func main() {
	myApp := app.New()
	myWindow := myApp.NewWindow("📜 证书解析小工具")
	myWindow.Resize(fyne.NewSize(800, 550))

	passwordEntry := widget.NewPasswordEntry()
	passwordEntry.SetPlaceHolder("如果证书有密码，请在这里输入 (PFX/P12常用)")

	dropLabel := widget.NewLabelWithStyle(
		"📂 将 证书文件 或 包含证书的文件夹 拖入此处\n\n(支持 .pem .crt .cer .pfx .p12 .p7b .jks)",
		fyne.TextAlignCenter,
		fyne.TextStyle{Bold: true},
	)
	dropArea := container.NewMax(container.NewPadded(dropLabel))

	logEntry := widget.NewMultiLineEntry()
	logEntry.SetPlaceHolder("✨ 解析结果将会显示在这里...")
	logEntry.Wrapping = fyne.TextWrapBreak
	logEntry.Disable()

	appendLog := func(msg string) {
		logEntry.SetText(logEntry.Text + msg + "\n")
		logEntry.CursorRow = len(strings.Split(logEntry.Text, "\n")) - 1
	}

	clearBtn := widget.NewButtonWithIcon("清空", theme.DeleteIcon(), func() {
		logEntry.SetText("")
	})

	parseFile := func(path string, password string) string {
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Sprintf("❌ 读取失败: %v", err)
		}
		if len(data) == 0 {
			return "❌ 文件为空"
		}

		bundle, err := certkit.Parse(data, password)
		if err != nil {
			if strings.Contains(err.Error(), "password") || strings.Contains(err.Error(), "decrypt") {
				return "❌ 证书加密，请输入正确密码后重试"
			}
			if block, _ := pem.Decode(data); block != nil {
				if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
					return formatCert(cert, path)
				}
			}
			return fmt.Sprintf("❌ 解析失败 (可能格式不支持): %v", err)
		}

		if len(bundle.Certificates) == 0 {
			return "⚠️ 未找到任何证书条目"
		}

		var result strings.Builder
		if len(bundle.Certificates) > 1 {
			result.WriteString(fmt.Sprintf("📦 该文件包含 %d 张证书:\n", len(bundle.Certificates)))
		}
		for i, cert := range bundle.Certificates {
			if len(bundle.Certificates) > 1 {
				result.WriteString(fmt.Sprintf("\n--- 证书 #%d ---\n", i+1))
			}
			result.WriteString(formatCert(cert, path))
		}
		return result.String()
	}

	formatCert := func(cert *x509.Certificate, path string) string {
		fileName := filepath.Base(path)
		notBefore := cert.NotBefore.Format("2006-01-02 15:04:05")
		notAfter := cert.NotAfter.Format("2006-01-02 15:04:05")

		keyAlgo := "未知"
		keySize := 0
		if pub := cert.PublicKey; pub != nil {
			switch k := pub.(type) {
			case *rsa.PublicKey:
				keyAlgo = "RSA"
				keySize = k.N.BitLen()
			case *ecdsa.PublicKey:
				keyAlgo = "ECDSA"
				keySize = k.Curve.Params().BitSize
			case ed25519.PublicKey:
				keyAlgo = "Ed25519"
				keySize = 256
			}
		}

		fingerprint := ""
		if len(cert.Raw) > 0 {
			hash := sha1.Sum(cert.Raw)
			fingerprint = hex.EncodeToString(hash[:])
			var fp strings.Builder
			for i, b := range fingerprint {
				if i > 0 && i%2 == 0 {
					fp.WriteByte(':')
				}
				fp.WriteByte(b)
			}
			fingerprint = fp.String()
		}

		return fmt.Sprintf(
			"✅ [%s]\n"+
				"   ├─ 主 题: %s\n"+
				"   ├─ 颁发者: %s\n"+
				"   ├─ 序列号: %s\n"+
				"   ├─ 有效期: %s ~ %s\n"+
				"   ├─ 公钥算法: %s (%d 位)\n"+
				"   └─ 指纹(SHA-1): %s\n",
			fileName,
			cert.Subject.String(),
			cert.Issuer.String(),
			cert.SerialNumber.String(),
			notBefore,
			notAfter,
			keyAlgo,
			keySize,
			fingerprint,
		)
	}

	processDropped := func(uris []fyne.URI) {
		if len(uris) == 0 {
			return
		}
		password := passwordEntry.Text
		appendLog("")
		appendLog("========== 开始解析 ==========")
		appendLog(fmt.Sprintf("⏰ %s", time.Now().Format("2006-01-02 15:04:05")))

		for _, uri := range uris {
			if uri.Scheme() != "file" {
				continue
			}
			path := uri.Path()
			if runtime.GOOS == "windows" && strings.HasPrefix(path, "/") {
				path = strings.TrimPrefix(path, "/")
			}

			info, err := os.Stat(path)
			if err != nil {
				appendLog(fmt.Sprintf("❌ 无法访问路径: %v", err))
				continue
			}

			if info.IsDir() {
				appendLog(fmt.Sprintf("📁 扫描文件夹: %s", info.Name()))
				err := filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
					if err != nil {
						return nil
					}
					if !d.IsDir() {
						appendLog(parseFile(p, password))
					}
					return nil
				})
				if err != nil {
					appendLog(fmt.Sprintf("⚠️ 遍历文件夹出错: %v", err))
				}
			} else {
				appendLog(parseFile(path, password))
			}
		}
		appendLog("========== 解析完成 ==========")
	}

	dropArea.Dropped = func(e *fyne.DropEvent) {
		processDropped(e.URIs)
	}

	fileOpenBtn := widget.NewButtonWithIcon("📎 选择文件", theme.FileIcon(), func() {
		dialog.ShowFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil || reader == nil {
				return
			}
			defer reader.Close()
			uris := []fyne.URI{reader.URI()}
			processDropped(uris)
		}, myWindow)
	})

	folderOpenBtn := widget.NewButtonWithIcon("📁 选择文件夹", theme.FolderIcon(), func() {
		dialog.ShowFolderOpen(func(uri fyne.ListableURI, err error) {
			if err != nil || uri == nil {
				return
			}
			uris := []fyne.URI{uri}
			processDropped(uris)
		}, myWindow)
	})

	topBar := container.NewHBox(
		widget.NewLabel("🔑 密码:"),
		passwordEntry,
	)
	actionBar := container.NewHBox(
		fileOpenBtn,
		folderOpenBtn,
		clearBtn,
		widget.NewButtonWithIcon("❓ 帮助", theme.HelpIcon(), func() {
			dialog.ShowInformation("使用说明",
				"1. 支持拖入单个证书文件，或整个文件夹（自动遍历查找）\n"+
					"2. 若证书有密码（如 .pfx/.p12），先在密码框输入再拖入\n"+
					"3. 支持格式: PEM(.crt/.cer/.pem), PKCS#12(.pfx/.p12), PKCS#7(.p7b), JKS\n"+
					"4. 解析结果会显示在下方日志区，可直接复制",
				myWindow)
		}),
	)

	content := container.NewBorder(
		container.NewVBox(
			widget.NewLabelWithStyle("📌 使用方式：拖入 或 点击按钮选择", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
			topBar,
			actionBar,
		),
		nil,
		nil,
		nil,
		container.NewVSplit(
			container.NewMax(dropArea),
			container.NewBorder(nil, nil, nil, nil, logEntry),
		),
	)

	myWindow.SetContent(content)
	myWindow.ShowAndRun()
}
