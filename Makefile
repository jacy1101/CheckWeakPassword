BUILD_ENV := CGO_ENABLED=0
LDFLAGS=-v -a -ldflags '-s -w' -gcflags="all=-trimpath=${PWD}" -asmflags="all=-trimpath=${PWD}"

TARGET_EXEC := CheckWeakPassword

.PHONY: all setup build-linux 

all: setup build-linux 



build-linux:
	${BUILD_ENV} GOARCH=amd64 GOOS=linux go build ${LDFLAGS} -o build/${TARGET_EXEC}_linux_amd64

