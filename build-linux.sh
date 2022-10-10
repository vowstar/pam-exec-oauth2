set GOPATH=$PWD
go env -w GOPATH=$GOPATH
go env -w GO111MODULE=on
go env -w GOPROXY=https://mirrors.aliyun.com/goproxy/,direct
go env | grep GOPROXY
go build -o pam-exec-oauth2
