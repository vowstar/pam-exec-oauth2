set GOPATH=$PWD/go
go env -w GO111MODULE=on
go env -w GOPROXY=https://mirrors.aliyun.com/goproxy/,direct
go env | grep GOPROXY
go build -o pam-exec-oauth2
sudo chown root:root pam-exec-oauth2
sudo chmod +s pam-exec-oauth2
