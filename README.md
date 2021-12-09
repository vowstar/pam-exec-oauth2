# pam-exec-oauth2

**This repository is no longer maintained.**

## Install

```bash
go get github.com/vowstar/pam-exec-oauth2

PREFIX=/opt/pam-exec-oauth2

sudo mkdir $PREFIX
sudo cp go/bin/pam-exec-oauth2 $PREFIX/pam-exec-oauth2
sudo touch $PREFIX/pam-exec-oauth2.yaml
sudo chmod 755 $PREFIX/pam-exec-oauth2
sudo chmod 600 $PREFIX/pam-exec-oauth2.yaml
```

## Configuration

### PAM

add the following lines to `/etc/pam.d/common-auth`. 

```bash
auth sufficient pam_exec.so expose_authtok /opt/pam-exec-oauth2/pam-exec-oauth2
```

### pam-exec-oauth2.yaml

edit `/opt/pam-exec-oauth2/pam-exec-oauth2.yaml`

#### Keycloak

```yaml
{
    client-id: "xxxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    client-secret: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    redirect-url: "urn:ietf:wg:oauth:2.0:oob",
    config-url: "https:/keycloak.xxxx.com/auth/realms/xxx",
    scopes: ["openid", "email", "profile"],
    username-format: "%s",
    command: "/opt/pam-exec-oauth2/script/login.sh",
}
```

The command can be empty, or it can be a command or script that needs to be executed. This command will be executed after successful login.
