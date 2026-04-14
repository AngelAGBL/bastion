package main

import (
	"fmt"
	"strings"
	"sync"
	"time"

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

func fmtDuration(secs int) string {
	if secs <= 0 {
		return "0s"
	}
	d := secs / 86400
	h := (secs % 86400) / 3600
	m := (secs % 3600) / 60
	s := secs % 60
	if d > 0 {
		return fmt.Sprintf("%dd %dh", d, h)
	}
	if h > 0 {
		return fmt.Sprintf("%dh %dm", h, m)
	}
	if m > 0 {
		return fmt.Sprintf("%dm %ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

func bwStatusText(t *tunnel) (string, bool, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.bwTextUnlocked()
}

func (t *tunnel) bwTextUnlocked() (string, bool, bool) {
	inStr := "∞"
	inOver := false
	if t.limitInKiB > 0 {
		inStr = fmt.Sprintf("%.1f/%dKiB", float64(t.usedInBytes)/1024, t.limitInKiB)
		inOver = t.usedInBytes >= int64(t.limitInKiB)*1024
	}
	outStr := "∞"
	outOver := false
	if t.limitOutKiB > 0 {
		outStr = fmt.Sprintf("%.1f/%dKiB", float64(t.usedOutBytes)/1024, t.limitOutKiB)
		outOver = t.usedOutBytes >= int64(t.limitOutKiB)*1024
	}
	return fmt.Sprintf("↑%s ↓%s", inStr, outStr), inOver, outOver
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
			statusL.Importance = widget.MediumImportance
			bwUpL := widget.NewLabel("bw-up")
			bwUpL.TextStyle = fyne.TextStyle{Monospace: true}
			bwUpL.Importance = widget.MediumImportance
			bwDownL := widget.NewLabel("bw-down")
			bwDownL.TextStyle = fyne.TextStyle{Monospace: true}
			bwDownL.Importance = widget.MediumImportance
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
			botRow := container.NewBorder(nil, nil, botLeft, botRight, container.NewHBox(bwUpL, bwDownL))
			// Row 3: cert time | endpoint time
			certTimeL := widget.NewLabel("cert")
			certTimeL.TextStyle = fyne.TextStyle{Monospace: true}
			certTimeL.Importance = widget.MediumImportance
			epTimeL := widget.NewLabel("ep")
			epTimeL.TextStyle = fyne.TextStyle{Monospace: true}
			epTimeL.Importance = widget.MediumImportance
			timeRow := container.NewHBox(certTimeL, epTimeL)
			return container.NewVBox(topRow, botRow, timeRow)
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
			timeRowBox := vbox.Objects[2].(*fyne.Container)

			topLeftBox := topRow.Objects[1].(*fyne.Container)
			icon := topLeftBox.Objects[0].(*widget.Icon)
			nameL := topLeftBox.Objects[1].(*widget.Label)
			addrL := topRow.Objects[0].(*widget.Label)

			botLeftBox := botRow.Objects[1].(*fyne.Container)
			statusL := botLeftBox.Objects[0].(*widget.Label)
			bwBox := botRow.Objects[0].(*fyne.Container)
			bwUpL := bwBox.Objects[0].(*widget.Label)
			bwDownL := bwBox.Objects[1].(*widget.Label)
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
			addrL.SetText(fmt.Sprintf("%s %s:%s → %s", t.proto(), strings.Split(bindIP, "/")[0], t.Port, t.Server))
			icon.SetResource(statusIcon(status))
			statusL.SetText(status)
			if active {
				statusL.Importance = widget.SuccessImportance
			} else if strings.HasPrefix(status, "error") {
				statusL.Importance = widget.DangerImportance
			} else {
				statusL.Importance = widget.WarningImportance
			}
			statusL.Refresh()
			bwText, inOver, outOver := bwStatusText(t)
			parts := strings.SplitN(bwText, " ", 2)
			bwUpL.SetText(parts[0])
			if inOver {
				bwUpL.Importance = widget.DangerImportance
			} else {
				bwUpL.Importance = widget.MediumImportance
			}
			bwUpL.Refresh()
			if len(parts) > 1 {
				bwDownL.SetText(parts[1])
			}
			if outOver {
				bwDownL.Importance = widget.DangerImportance
			} else {
				bwDownL.Importance = widget.MediumImportance
			}
			bwDownL.Refresh()
			// Row 3: times
			certTimeL := timeRowBox.Objects[0].(*widget.Label)
			epTimeL := timeRowBox.Objects[1].(*widget.Label)
			cs := t.certSecsLeft()
			t.mu.Lock()
			es := t.endpointSecs
			t.mu.Unlock()
			if cs >= 0 {
				certTimeL.SetText(fmt.Sprintf("cert: %s", fmtDuration(cs)))
			} else {
				certTimeL.SetText("cert: ∞")
			}
			if es >= 0 {
				epTimeL.SetText(fmt.Sprintf("endpoint: %s", fmtDuration(es)))
			} else {
				epTimeL.SetText("")
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
			actionBtn.Refresh()
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

	listWidget.OnSelected = func(id widget.ListItemID) { listWidget.UnselectAll() }

	w.SetContent(container.NewBorder(container.NewVBox(header, widget.NewSeparator()), nil, nil, nil, listWidget))
	w.SetOnDropped(func(pos fyne.Position, uris []fyne.URI) {
		for _, uri := range uris {
			showP12Dialog(w, uri.Name(), uri.Path())
		}
	})

	cfg := loadConfig()
	for _, st := range cfg.Tunnels {
		var certExp time.Time
		if st.CertExpiry != "" {
			certExp, _ = time.Parse(time.RFC3339, st.CertExpiry)
		}
		allTunnels = append(allTunnels, &tunnel{
			Name: st.Name, Server: st.Server, Port: st.Port, Protocol: st.Protocol,
			P12Path: st.P12Path, BindCIDR: st.BindCIDR,
			certExpiry: certExp,
			status: "detenido", limitInKiB: st.LimitInKiB, limitOutKiB: st.LimitOutKiB,
			usedInBytes: st.UsedInBytes, usedOutBytes: st.UsedOutBytes,
			stopped: true, done: make(chan struct{}),
		})
	}
	refreshList()

	// Global 1s ticker to update cert/endpoint countdowns
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			tunnelsMu.Lock()
			any := false
			for _, t := range allTunnels {
				t.mu.Lock()
				if t.endpointSecs > 0 {
					t.endpointSecs--
				}
				if !t.certExpiry.IsZero() || t.endpointSecs >= 0 {
					any = true
				}
				t.mu.Unlock()
			}
			tunnelsMu.Unlock()
			if any {
				refreshList()
			}
		}
	}()

	w.ShowAndRun()
}
