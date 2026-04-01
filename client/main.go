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

func usesText(uses int) string {
	if uses < 0 {
		return "∞"
	}
	return fmt.Sprintf("%d usos", uses)
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
			usesL := widget.NewLabel("uses")
			usesL.TextStyle = fyne.TextStyle{Monospace: true}
			actionBtn := widget.NewButton("Detener", nil)
			removeBtn := widget.NewButtonWithIcon("", theme.DeleteIcon(), nil)
			removeBtn.Importance = widget.DangerImportance
			left := container.NewHBox(icon, nameL)
			mid := container.NewHBox(addrL, statusL, usesL)
			right := container.NewHBox(actionBtn, removeBtn)
			return container.NewBorder(nil, nil, left, right, mid)
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			tunnelsMu.Lock()
			if id >= len(allTunnels) {
				tunnelsMu.Unlock()
				return
			}
			t := allTunnels[id]
			tunnelsMu.Unlock()

			border := obj.(*fyne.Container)
			leftBox := border.Objects[1].(*fyne.Container)
			rightBox := border.Objects[2].(*fyne.Container)
			midBox := border.Objects[0].(*fyne.Container)

			icon := leftBox.Objects[0].(*widget.Icon)
			nameL := leftBox.Objects[1].(*widget.Label)
			addrL := midBox.Objects[0].(*widget.Label)
			statusL := midBox.Objects[1].(*widget.Label)
			usesL := midBox.Objects[2].(*widget.Label)
			actionBtn := rightBox.Objects[0].(*widget.Button)
			removeBtn := rightBox.Objects[1].(*widget.Button)

			t.mu.Lock()
			status := t.status
			active := !t.stopped
			uses := t.remainingUses
			t.mu.Unlock()

			nameL.SetText(t.Name)
			addrL.SetText(fmt.Sprintf("127.0.0.1:%s → %s", t.Port, t.Server))
			icon.SetResource(statusIcon(status))
			statusL.SetText(status)
			if active {
				statusL.Importance = widget.SuccessImportance
			} else {
				statusL.Importance = widget.LowImportance
			}
			if active || uses >= 0 {
				usesL.SetText("[" + usesText(uses) + "]")
				usesL.Show()
			} else {
				usesL.Hide()
			}
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
			status: "detenido", remainingUses: st.RemainingUses, stopped: true, done: make(chan struct{}),
		})
	}
	refreshList()
	w.ShowAndRun()
}
