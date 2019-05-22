build: main.go argparser.go database.go helpers.go server.go types.go configuration_parser.go
	go build -o nidan -i main.go argparser.go database.go helpers.go server.go types.go configuration_parser.go

clean:
	rm -f nidan

cleanbuild: clean build

setup:
	go get ./... &>/dev/null ||:
