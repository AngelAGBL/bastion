.PHONY: build-windows build-linux build-all

build-windows:
	CC=x86_64-w64-mingw32-gcc CXX=x86_64-w64-mingw32-g++ GOOS=windows GOARCH=amd64 CGO_ENABLED=1 go build -ldflags "-H windowsgui" -o bastion.exe .

build-linux:
	GOOS=linux GOARCH=amd64 go build -o bastion .

build-all: build-linux build-windows
