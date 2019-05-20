build: main.go
	go build -o server -i main.go

clean:
	rm -f server

cleanbuild: clean build

setup:
	go get ./... &>/dev/null ||:
