build: main.go argparser.go database.go helpers.go server.go types.go
	go build -i main.go argparser.go database.go helpers.go server.go types.go

clean:
	rm -f main

cleanbuild: clean build

setup:
	go get ./... &>/dev/null ||:
