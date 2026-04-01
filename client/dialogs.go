package main

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
)

func showP12Dialog(w fyne.Window, filename, p12Path string) {
	serverEntry := widget.NewEntry()
	serverEntry.SetPlaceHolder("servidor:3001")
	serverEntry.SetText(getEnvOr("BASTION_HOST", "localhost:3001"))
	passEntry := widget.NewPasswordEntry()
	passEntry.SetPlaceHolder("Contraseña del .p12")
	portEntry := widget.NewEntry()
	portEntry.SetPlaceHolder("Puerto local (ej: 8080)")

	dialog.ShowForm("Túnel: "+filename, "Conectar", "Cancelar",
		[]*widget.FormItem{
			widget.NewFormItem("Servidor", serverEntry),
			widget.NewFormItem("Contraseña", passEntry),
			widget.NewFormItem("Puerto local", portEntry),
		}, func(ok bool) {
			if !ok {
				return
			}
			t := &tunnel{
				Name: filename, Server: serverEntry.Text, Port: portEntry.Text,
				P12Path: p12Path, Password: passEntry.Text,
				status: "conectando...", remainingUses: -1, done: make(chan struct{}),
			}
			tunnelsMu.Lock()
			allTunnels = append(allTunnels, t)
			tunnelsMu.Unlock()
			persistAndRefresh()
			go connectTunnel(w, t)
		}, w)
}

func showReconnectDialog(w fyne.Window, t *tunnel) {
	passEntry := widget.NewPasswordEntry()
	passEntry.SetPlaceHolder("Contraseña del .p12")

	dialog.ShowForm("Reconectar: "+t.Name, "Conectar", "Cancelar",
		[]*widget.FormItem{
			widget.NewFormItem("Contraseña", passEntry),
		}, func(ok bool) {
			if !ok {
				return
			}
			t.mu.Lock()
			t.stopped = false
			t.done = make(chan struct{})
			t.status = "conectando..."
			t.Password = passEntry.Text
			t.mu.Unlock()
			refreshList()
			go connectTunnel(w, t)
		}, w)
}
