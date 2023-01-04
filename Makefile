all: gen build run

gen:
	go generate ./pkg/...	

build:
	go build

run:
	./rto-softener