package main

import (
	"fmt"
	"strings"
	"sync"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

var (
	allTunnels []*tunnel
	tunnelsMu  sync.Mutex
	listWidget *widget.List
)

func refreshList() {
	if listWidget != nil {
		listWidget.Refresh()
	}
}

func persistAndRefresh() {
	tunnelsMu.Lock()
	saveConfig(allTunnels)
	tunnelsMu.Unlock()
	refreshList()
}

func statusIcon(status string) fyne.Resource {
	switch {
	case strings.HasPrefix(status, "activo"), strings.HasPrefix(status, "conectando"):
		return theme.MediaPlayIcon()
	default:
		return theme.MediaStopIcon()
	}
}

func bwStatusText(t *tunnel) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.bwTextUnlocked()
}

func (t *tunnel) bwTextUnlocked() string {
	inStr := "∞"
	if t.limitInKiB > 0 {
		inStr = fmt.Sprintf("%.1f/%dKiB", float64(t.usedInBytes)/1024, t.limitInKiB)
	}
	outStr := "∞"
	if t.limitOutKiB > 0 {
		outStr = fmt.Sprintf("%.1f/%dKiB", float64(t.usedOutBytes)/1024, t.limitOutKiB)
	}
	return fmt.Sprintf("↑%s ↓%s", inStr, outStr)
}

func main() {
	a := app.NewWithID("com.bastion.client")
	w := a.NewWindow("Bastion")
	w.Resize(fyne.NewSize(700, 440))

	title := canvas.NewText("Bastion", theme.ForegroundColor())
	title.TextSize = 20
	title.TextStyle = fyne.TextStyle{Bold: true}

	addBtn := widget.NewButtonWithIcon("Agregar .p12", theme.ContentAddIcon(), func() {
		dialog.ShowFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil || reader == nil {
				return
			}
			p12Path := reader.URI().Path()
			reader.Close()
			showP12Dialog(w, reader.URI().Name(), p12Path)
		}, w)
	})
	addBtn.Importance = widget.HighImportance

	header := container.NewHBox(title, layout.NewSpacer(), addBtn)

	listWidget = widget.NewList(
		func() int {
			tunnelsMu.Lock()
			defer tunnelsMu.Unlock()
			return len(allTunnels)
		},
		func() fyne.CanvasObject {
			icon := widget.NewIcon(theme.MediaStopIcon())
			nameL := widget.NewLabel("name")
			nameL.TextStyle = fyne.TextStyle{Bold: true}
			addrL := widget.NewLabel("addr")
			addrL.TextStyle = fyne.TextStyle{Monospace: true}
			statusL := widget.NewLabel("status")
			statusL.Importance = widget.LowImportance
			bwL := widget.NewLabel("bw")
			bwL.TextStyle = fyne.TextStyle{Monospace: true}
			bwL.Importance = widget.LowImportance
			actionBtn := widget.NewButton("Detener", nil)
			editBtn := widget.NewButtonWithIcon("", theme.DocumentCreateIcon(), nil)
			removeBtn := widget.NewButtonWithIcon("", theme.DeleteIcon(), nil)
			removeBtn.Importance = widget.DangerImportance
			// Row 1: name | addr → server
			topLeft := container.NewHBox(icon, nameL)
			topRight := addrL
			topRow := container.NewBorder(nil, nil, topLeft, nil, topRight)
			// Row 2: status | bandwidth | buttons
			botLeft := container.NewHBox(statusL)
			botRight := container.NewHBox(actionBtn, editBtn, removeBtn)
			botRow := container.NewBorder(nil, nil, botLeft, botRight, bwL)
			return container.NewVBox(topRow, botRow)
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			tunnelsMu.Lock()
			if id >= len(allTunnels) {
				tunnelsMu.Unlock()
				return
			}
			t := allTunnels[id]
			tunnelsMu.Unlock()

			vbox := obj.(*fyne.Container)
			topRow := vbox.Objects[0].(*fyne.Container)
			botRow := vbox.Objects[1].(*fyne.Container)

			topLeftBox := topRow.Objects[1].(*fyne.Container)
			icon := topLeftBox.Objects[0].(*widget.Icon)
			nameL := topLeftBox.Objects[1].(*widget.Label)
			addrL := topRow.Objects[0].(*widget.Label)

			botLeftBox := botRow.Objects[1].(*fyne.Container)
			statusL := botLeftBox.Objects[0].(*widget.Label)
			bwL := botRow.Objects[0].(*widget.Label)
			botRightBox := botRow.Objects[2].(*fyne.Container)
			actionBtn := botRightBox.Objects[0].(*widget.Button)
			editBtn := botRightBox.Objects[1].(*widget.Button)
			removeBtn := botRightBox.Objects[2].(*widget.Button)

			t.mu.Lock()
			status := t.status
			active := !t.stopped
			t.mu.Unlock()

			nameL.SetText(t.Name)
			bindIP := t.BindCIDR
			if bindIP == "" {
				bindIP = "127.0.0.1/32"
			}
			addrL.SetText(fmt.Sprintf("%s:%s → %s", strings.Split(bindIP, "/")[0], t.Port, t.Server))
			icon.SetResource(statusIcon(status))
			statusL.SetText(status)
			if active {
				statusL.Importance = widget.SuccessImportance
			} else {
				statusL.Importance = widget.LowImportance
			}
			bwL.SetText(bwStatusText(t))
			if active {
				actionBtn.SetText("Detener")
				actionBtn.Importance = widget.DangerImportance
				actionBtn.OnTapped = func() { t.stop(); refreshList() }
			} else {
				actionBtn.SetText("Iniciar")
				actionBtn.Importance = widget.SuccessImportance
				actionBtn.OnTapped = func() { showReconnectDialog(w, t) }
			}
			capturedID := id
			editBtn.OnTapped = func() { showEditDialog(w, t) }
			removeBtn.OnTapped = func() {
				t.stop()
				tunnelsMu.Lock()
				if capturedID < len(allTunnels) {
					allTunnels = append(allTunnels[:capturedID], allTunnels[capturedID+1:]...)
				}
				tunnelsMu.Unlock()
				persistAndRefresh()
			}
		},
	)

	w.SetContent(container.NewBorder(container.NewVBox(header, widget.NewSeparator()), nil, nil, nil, listWidget))
	w.SetOnDropped(func(pos fyne.Position, uris []fyne.URI) {
		for _, uri := range uris {
			showP12Dialog(w, uri.Name(), uri.Path())
		}
	})

	cfg := loadConfig()
	for _, st := range cfg.Tunnels {
		allTunnels = append(allTunnels, &tunnel{
			Name: st.Name, Server: st.Server, Port: st.Port, P12Path: st.P12Path,
			BindCIDR: st.BindCIDR,
			status: "detenido", limitInKiB: st.LimitInKiB, limitOutKiB: st.LimitOutKiB,
			usedInBytes: st.UsedInBytes, usedOutBytes: st.UsedOutBytes,
			stopped: true, done: make(chan struct{}),
		})
	}
	refreshList()
	w.ShowAndRun()
}
