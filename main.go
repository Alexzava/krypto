//go:build linux || windows
package main

import (
	"os"
	"fmt"
	"embed"
	"context"
	"runtime"

	"github.com/wailsapp/wails/v2"
	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)


var (
	sodium uintptr

	//go:embed all:frontend/dist
	assets embed.FS
)

func getSodiumLibrary() string {
	switch runtime.GOOS {
		case "linux":
			return "libsodium.so.26"
		case "windows":
			return "libsodium.dll"
		default:
			panic(fmt.Errorf("GOOS=%s is not supported", runtime.GOOS))
	}
}

func main() {
	s, err := openLibrary(getSodiumLibrary())
	if err != nil {
		panic(err)
	}
	sodium = s

	// Create an instance of the app structure
	app := NewApp()

	// Create application with options
	err = wails.Run(&options.App{
		Title:  "Krypto",
		Width:  1024, //1024
		Height: 768, // 768
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		EnableDefaultContextMenu: false,
		OnStartup:        app.startup,
		Bind: []interface{}{
			app,
		},
		DragAndDrop: &options.DragAndDrop{
          EnableFileDrop:       true,
          DisableWebViewDrop:   false,
          CSSDropProperty:      "--wails-drop-target",
          CSSDropValue:         "drop",
        },
        OnDomReady: func(ctx context.Context) {
			wailsruntime.OnFileDrop(ctx, func(x, y int, paths []string) {
				if len(paths) > 0 {
					info, err := os.Stat(paths[0])
					if err != nil {
						wailsruntime.EventsEmit(ctx, "log", "Invalid file")
						return
					}

					if !info.IsDir() {
						wailsruntime.EventsEmit(ctx, "filedrop", paths[0])
					} else {
						wailsruntime.EventsEmit(ctx, "log", "Invalid file")
					}
				}
			})
		},
	})

	if err != nil {
		println("Error:", err.Error())
	}
}
