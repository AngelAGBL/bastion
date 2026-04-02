package main

import (
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
)

func defaultServer() string {
	if lastServer != "" {
		return lastServer
	}
	return getEnvOr("BASTION_HOST", "localhost:3001")
}

type enterEntry struct {
	widget.Entry
	onEnter func()
}

func newEnterEntry(placeholder string, password bool, onEnter func()) *enterEntry {
	e := &enterEntry{onEnter: onEnter}
	e.SetPlaceHolder(placeholder)
	e.Password = password
	e.ExtendBaseWidget(e)
	return e
}

func (e *enterEntry) TypedKey(ev *fyne.KeyEvent) {
	if (ev.Name == fyne.KeyReturn || ev.Name == fyne.KeyEnter) && e.onEnter != nil {
		e.onEnter()
		return
	}
	e.Entry.TypedKey(ev)
}

// formRow creates a horizontal row: fixed-width label + entry filling the rest.
func formRow(label string, entry fyne.CanvasObject) *fyne.Container {
	l := widget.NewLabel(label)
	l.Alignment = fyne.TextAlignTrailing
	return container.NewBorder(nil, nil, container.NewGridWrap(fyne.NewSize(100, 0), l), nil, entry)
}

// wideForm wraps a form VBox with a minimum width so inputs aren't cramped.
type wideForm struct {
	widget.BaseWidget
	content *fyne.Container
	minW    float32
}

func newWideForm(minWidth float32, items ...fyne.CanvasObject) *wideForm {
	w := &wideForm{content: container.NewVBox(items...), minW: minWidth}
	w.ExtendBaseWidget(w)
	return w
}

func (w *wideForm) CreateRenderer() fyne.WidgetRenderer {
	return &wideFormRenderer{form: w}
}

type wideFormRenderer struct {
	form *wideForm
}

func (r *wideFormRenderer) Layout(size fyne.Size) {
	r.form.content.Resize(size)
}

func (r *wideFormRenderer) MinSize() fyne.Size {
	ms := r.form.content.MinSize()
	if ms.Width < r.form.minW {
		ms.Width = r.form.minW
	}
	return ms
}

func (r *wideFormRenderer) Refresh()                     { r.form.content.Refresh() }
func (r *wideFormRenderer) Objects() []fyne.CanvasObject { return []fyne.CanvasObject{r.form.content} }
func (r *wideFormRenderer) Destroy()                     {}

func validate(w fyne.Window, fields map[string]string) bool {
	for name, val := range fields {
		if strings.TrimSpace(val) == "" {
			dialog.ShowInformation("Campo requerido", name+" no puede estar vacío", w)
			return false
		}
	}
	return true
}

func showP12Dialog(w fyne.Window, filename, p12Path string) {
	var d *dialog.CustomDialog

	serverEntry := widget.NewEntry()
	serverEntry.SetPlaceHolder("servidor:3001")
	serverEntry.SetText(defaultServer())

	passEntry := newEnterEntry("Contraseña del .p12", true, nil)

	portEntry := widget.NewEntry()
	portEntry.SetPlaceHolder("8080")

	bindEntry := widget.NewEntry()
	bindEntry.SetPlaceHolder("127.0.0.1/32")
	bindEntry.SetText("127.0.0.1/32")

	connectBtn := widget.NewButton("Conectar", nil)
	connectBtn.Importance = widget.HighImportance
	cancelBtn := widget.NewButton("Cancelar", nil)

	submit := func() {
		if !validate(w, map[string]string{
			"Servidor": serverEntry.Text, "Contraseña": passEntry.Text,
			"Puerto":   portEntry.Text, "Red": bindEntry.Text,
		}) {
			return
		}
		d.Hide()
		lastServer = serverEntry.Text
		t := &tunnel{
			Name: filename, Server: serverEntry.Text, Port: portEntry.Text,
			P12Path: p12Path, BindCIDR: bindEntry.Text, Password: passEntry.Text,
			status: "conectando...", done: make(chan struct{}),
		}
		tunnelsMu.Lock()
		allTunnels = append(allTunnels, t)
		tunnelsMu.Unlock()
		persistAndRefresh()
		go connectTunnel(w, t)
	}

	passEntry.onEnter = submit
	connectBtn.OnTapped = submit
	cancelBtn.OnTapped = func() { d.Hide() }

	form := newWideForm(420,
		formRow("Servidor", serverEntry),
		formRow("Contraseña", passEntry),
		formRow("Puerto", portEntry),
		formRow("Red (CIDR)", bindEntry),
	)
	content := container.NewVBox(form, container.NewHBox(layout.NewSpacer(), cancelBtn, connectBtn))

	d = dialog.NewCustomWithoutButtons("Túnel: "+filename, content, w)
	d.Show()
	w.Canvas().Focus(passEntry)
}

func showReconnectDialog(w fyne.Window, t *tunnel) {
	var d *dialog.CustomDialog

	passEntry := newEnterEntry("Contraseña del .p12", true, nil)

	connectBtn := widget.NewButton("Conectar", nil)
	connectBtn.Importance = widget.HighImportance
	cancelBtn := widget.NewButton("Cancelar", nil)

	submit := func() {
		if !validate(w, map[string]string{"Contraseña": passEntry.Text}) {
			return
		}
		d.Hide()
		t.mu.Lock()
		t.stopped = false
		t.done = make(chan struct{})
		t.status = "conectando..."
		t.Password = passEntry.Text
		t.mu.Unlock()
		refreshList()
		go connectTunnel(w, t)
	}

	passEntry.onEnter = submit
	connectBtn.OnTapped = submit
	cancelBtn.OnTapped = func() { d.Hide() }

	form := newWideForm(420, formRow("Contraseña", passEntry))
	content := container.NewVBox(form, container.NewHBox(layout.NewSpacer(), cancelBtn, connectBtn))

	d = dialog.NewCustomWithoutButtons("Reconectar: "+t.Name, content, w)
	d.Show()
	w.Canvas().Focus(passEntry)
}

func showEditDialog(w fyne.Window, t *tunnel) {
	var d *dialog.CustomDialog

	serverEntry := widget.NewEntry()
	serverEntry.SetText(t.Server)
	portEntry := widget.NewEntry()
	portEntry.SetText(t.Port)
	bindEntry := widget.NewEntry()
	bindEntry.SetText(t.BindCIDR)
	if bindEntry.Text == "" {
		bindEntry.SetText("127.0.0.1/32")
	}

	saveBtn := widget.NewButton("Guardar", nil)
	saveBtn.Importance = widget.HighImportance
	cancelBtn := widget.NewButton("Cancelar", nil)

	saveBtn.OnTapped = func() {
		if !validate(w, map[string]string{
			"Servidor": serverEntry.Text, "Puerto": portEntry.Text, "Red": bindEntry.Text,
		}) {
			return
		}
		d.Hide()
		if t.isActive() {
			t.stop()
		}
		t.mu.Lock()
		t.Server = serverEntry.Text
		t.Port = portEntry.Text
		t.BindCIDR = bindEntry.Text
		t.mu.Unlock()
		persistAndRefresh()
	}
	cancelBtn.OnTapped = func() { d.Hide() }

	form := newWideForm(420,
		formRow("Servidor", serverEntry),
		formRow("Puerto", portEntry),
		formRow("Red (CIDR)", bindEntry),
	)
	content := container.NewVBox(form, container.NewHBox(layout.NewSpacer(), cancelBtn, saveBtn))

	d = dialog.NewCustomWithoutButtons("Editar: "+t.Name, content, w)
	d.Show()
}
