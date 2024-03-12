// Copyright © 2017 Shinichi MOTOKI
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/oauth2"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/shimt/go-simplecli"
)

var cli = simplecli.NewCLI()

const (
	userFile string = "/etc/passwd"
	groupFile string = "/etc/group"
)

// Read file /etc/passwd and return slice of users
func ReadEtcPasswd(f string) (list []string) {

	file, err := os.Open(f)
	if err != nil {
		cli.Log.Debug(err)
		panic(err)
	}
	defer file.Close()

	r := bufio.NewScanner(file)

	for r.Scan() {
		lines := r.Text()
		parts := strings.Split(lines, ":")
		list = append(list, parts[0])
	}
	return list
}

// Read file /etc/group and return slice of groups
func ReadEtcGroup(f string) (list []string) {

	file, err := os.Open(f)
	if err != nil {
		cli.Log.Debug(err)
		panic(err)
	}
	defer file.Close()

	r := bufio.NewScanner(file)

	for r.Scan() {
		lines := r.Text()
		parts := strings.Split(lines, ":")
		list = append(list, parts[0])
	}
	return list
}

// Check if user on the host
func CheckUserOnHost(s []string, u string) bool {

	for _, w := range s {
		if u == w {
			return true
		}
	}
	return false
}

// Check if group on the host
func CheckGroupOnHost(s []string, u string) bool {

	for _, w := range s {
		if u == w {
			return true
		}
	}
	return false
}

// User is created by executing shell command useradd
func AddNewUser(name string) (bool) {

	const path string = "/usr/sbin/useradd"

	if _, err := os.Stat(path); err != nil {
		cli.Log.Debug(err, ", command not found: ", path)
		return false;
	}

	var arg = []string{"-m", "-U", name}
	var cmd = exec.Command(path, arg...)

	if _, err := cmd.Output(); err != nil {
		cli.Log.Debug(err, ", There was an error when adding user: ", name)
		return false
	} else {
		cli.Log.Debug("Add new user success: " + name)
		return true
	}
}

// Group is created by executing shell command useradd
func AddNewGroup(name string) (bool) {

	const path string = "/usr/sbin/groupadd"

	if _, err := os.Stat(path); err != nil {
		cli.Log.Debug(err, ", command not found: ", path)
		return false;
	}

	var arg = []string{"-f", name}
	var cmd = exec.Command(path, arg...)

	if _, err := cmd.Output(); err != nil {
		cli.Log.Debug(err, ", There was an error when adding group: ", name)
		return false
	} else {
		cli.Log.Debug("Add new group success: " + name)
		return true
	}
}

// UID is changed by executing shell command usermod
func ChangeUid(name string, id int) (bool) {

	const path string = "/usr/sbin/usermod"

	if _, err := os.Stat(path); err != nil {
		cli.Log.Debug(err, ", command not found: ", path)
		return false;
	}

	var arg = []string{"-u", strconv.Itoa(id), name}
	var cmd = exec.Command(path, arg...)

	if _, err := cmd.Output(); err != nil {
		cli.Log.Debug(err, ", There was an error when change user id: ", name)
		return false
	} else {
		cli.Log.Debug("Change Uid success: " + strconv.Itoa(id))
		return true
	}
}

// GID is changed by executing shell command groupmod
func ChangeGid(name string, id int) (bool) {

	const path string = "/usr/sbin/groupmod"

	if _, err := os.Stat(path); err != nil {
		cli.Log.Debug(err, ", command not found: ", path)
		return false;
	}

	var arg = []string{"-g", strconv.Itoa(id), name}
	var cmd = exec.Command(path, arg...)

	if _, err := cmd.Output(); err != nil {
		cli.Log.Debug(err, ", There was an error when change group id: ", name)
		return false
	} else {
		cli.Log.Debug("Change Gid success: ", strconv.Itoa(id))
		return true
	}
}

// Groups is changed by executing shell command usermod
func ChangeGroups(name string, groups []string) (bool) {

	const path string = "/usr/sbin/usermod"

	if _, err := os.Stat(path); err != nil {
		cli.Log.Debug(err, ", command not found: ", path)
		return false;
	}

	groups = append(groups, name)

	var arg =  []string{"-G", strings.Join(groups, ","), name}
	var cmd = exec.Command(path, arg...)

	if _, err := cmd.Output(); err != nil {
		cli.Log.Debug(err, ", There was an error when change user group: ", strings.Join(groups, ","))
		return false
	} else {
		cli.Log.Debug("Change groups success: ", strings.Join(groups, ","))
		return true
	}
}

// Owner is changed by executing shell command usermod
func ChangeOwner(name string, dirPath string) (bool) {

	const path string = "/usr/bin/chown"

	if _, err := os.Stat(path); err != nil {
		cli.Log.Debug(err, ", command not found: ", path)
		return false;
	}

	var arg =  []string{fmt.Sprintf("%s:%s", name, name), "-R", dirPath}
	var cmd = exec.Command(path, arg...)

	if _, err := cmd.Output(); err != nil {
		cli.Log.Debug(err, ", There was an error when change owner: ", fmt.Sprintf("%s:%s", name, name))
		return false
	} else {
		cli.Log.Debug("Change owner success: ", fmt.Sprintf("%s:%s", name, name))
		return true
	}
}

// Kill all process by user id
func KillProcess(id int) (bool) {

	const path string = "/usr/bin/pkill"

	if _, err := os.Stat(path); err != nil {
		cli.Log.Debug(err, ", command not found: ", path)
		return false;
	}

	var arg =  []string{"-9", "-u", strconv.Itoa(id)}
	var cmd = exec.Command(path, arg...)

	if _, err := cmd.Output(); err != nil {
		cli.Log.Debug(err, ", There was an error when kill user id process: ", strconv.Itoa(id))
		return false
	} else {
		cli.Log.Debug("Kill user id success: ", strconv.Itoa(id))
		return true
	}
}

// Run command using /bin/sh -c
func RunCmd(command string) (bool) {

	const path string = "/bin/sh"

	if _, err := os.Stat(path); err != nil {
		cli.Log.Debug(err, ", command not found: ", path)
		return false;
	}

	var arg =  []string{"-c", command}
	var cmd = exec.Command(path, arg...)

	cmd.Env = os.Environ()

	if _, err := cmd.Output(); err != nil {
		cli.Log.Debug(err, ", There was an error when run user script: ", path)
		return false
	} else {
		cli.Log.Debug("Run user script success: ", path)
		return true
	}
}

// Write and append text to text file
func WriteToLogFile(log string, path string) (bool) {

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		cli.Log.Debug(err)
		return false
	}
	
	defer f.Close()
	
	if _, err = f.WriteString(log); err != nil {
		cli.Log.Debug(err)
		return false
	}
	return true
}

func initCLI() {
	cli.CommandLine.String("client-id", "", "OAuth2 Client ID")
	cli.CommandLine.String("client-secret", "", "OAuth2 Client Secret")
	cli.CommandLine.StringArray("scopes", []string{}, "OAuth2 Scopes")
	cli.CommandLine.String("config-url", "", "OAuth2 Config URL")
	cli.CommandLine.String("redirect-url", "", "OAuth2 Redirect URL")
	cli.CommandLine.String("username-format", "%s", "username format")
	cli.CommandLine.String("script", "", "Script to run after login")

	cli.BindSameName(
		"client-id",
		"client-secret",
		"scopes",
		"config-url",
		"redirect-url",
		"username-format",
		"script",
	)
}

func init() {
	initCLI()
}

func main() {
	setting := cli.NewCLISetting()
	err := cli.Setup(
		setting.ConfigSearchPath(),
		setting.ConfigFile(filepath.Join(cli.Application.Directory, cli.Application.Name+".yaml")),
	)
	cli.Exit1IfError(err)

	if cli.ConfigFile != "" {
		cli.Log.Debug("Using config file:", cli.ConfigFile)
	}

	username := os.Getenv("PAM_USER")
	password := ""

	stdinScanner := bufio.NewScanner(os.Stdin)
	if stdinScanner.Scan() {
		password = stdinScanner.Text()
	}

	cli.Log.Debug("create oauth2Config")
	cli.Log.Debugf("ClientID: %s", cli.Config.GetString("client-id"))
	cli.Log.Debugf("ClientSecret: %s", cli.Config.GetString("client-secret"))
	cli.Log.Debugf("Scopes: %s", cli.Config.GetStringSlice("scopes"))
	cli.Log.Debugf("ConfigURL: %s", cli.Config.GetString("config-url"))
	cli.Log.Debugf("Script: %s", cli.Config.GetString("script"))

	configURL := cli.Config.GetString("config-url")
	cli.Log.Debug("create oauth2Context")
	oauth2Context := context.Background()
	provider, err := oidc.NewProvider(oauth2Context, configURL)
	oidcConfig := &oidc.Config{
		ClientID: cli.Config.GetString("client-id"),
	}
	oauth2Config := oauth2.Config{
		ClientID:     cli.Config.GetString("client-id"),
		ClientSecret: cli.Config.GetString("client-secret"),
		Scopes:       cli.Config.GetStringSlice("scopes"),
		Endpoint: provider.Endpoint(),
	}

	cli.Log.Debug("call PasswordCredentialsToken")

	oauth2Token, err := oauth2Config.PasswordCredentialsToken(
		oauth2Context,
		fmt.Sprintf(cli.Config.GetString("username-format"), username),
		password,
	)

	cli.Exit1IfError(err)

	if err != nil {
		// handle error
		cli.Log.Debug("OAuth2 password to token failed")
		cli.Exit(1)
	}

	// Extract the ID Token from OAuth2 token.
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		// handle missing token
		cli.Log.Debug("No id_token field in oauth2 token")
		cli.Exit(1)
	}

	verifier := provider.Verifier(oidcConfig)

	// Parse and verify ID Token payload.
	idToken, err := verifier.Verify(oauth2Context, rawIDToken)
	if err != nil {
		// handle error
		cli.Log.Debug("OAuth2 verify ID token failed")
		cli.Exit(1)
	}

	userInfo, err := provider.UserInfo(oauth2Context, oauth2.StaticTokenSource(oauth2Token))
	if err != nil {
		// handle error
		cli.Log.Debug("Failed to get userinfo")
		cli.Exit(1)
	}

	// Extract provider claims
	var providerClaims struct {
		ScopesSupported []string `json:"scopes_supported"`
		ClaimsSupported []string `json:"claims_supported"`
	}
	
	if err := provider.Claims(&providerClaims); err != nil {
		// handle unmarshaling error
	}

	cli.Log.Debug(providerClaims.ScopesSupported)
	cli.Log.Debug(providerClaims.ClaimsSupported)

	// Extract idToken claims
	var idTokenClaims struct {
		Email    string   `json:"email"`
		Verified bool     `json:"email_verified,omitempty"`
		Name     string   `json:"name,omitempty"`
		Groups   []string `json:"groups,omitempty"`
		Uid      int      `json:"uid,omitempty"`
		Display  int      `json:"display,omitempty"`
		Arg      string   `json:"arg,omitempty"`
	}
	if err := idToken.Claims(&idTokenClaims); err != nil {
		// handle error
		cli.Log.Debug("OAuth2 get idToken claims failed")
	}

	cli.Log.Debug(idTokenClaims.Email)
	cli.Log.Debug(idTokenClaims.Verified)
	cli.Log.Debug(idTokenClaims.Name)
	cli.Log.Debug(idTokenClaims.Groups)
	cli.Log.Debug(idTokenClaims.Uid)
	cli.Log.Debug(idTokenClaims.Display)
	cli.Log.Debug(idTokenClaims.Arg)

	// Extract userInfo claims
	var userInfoClaims struct {
		Subject       string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified,omitempty"`
	}
	
	if err := userInfo.Claims(&userInfoClaims); err != nil {
		// handle unmarshaling error
	}

	cli.Log.Debug(userInfoClaims.Subject)
	cli.Log.Debug(userInfoClaims.Email)
	cli.Log.Debug(userInfoClaims.EmailVerified)

	userList := ReadEtcPasswd(userFile)
	groupList := ReadEtcGroup(groupFile)

	if username == "root" {
		cli.Log.Debug("OAuth2 not permit root login")
		cli.Exit(1)
	}

	if !oauth2Token.Valid() {
		cli.Log.Debug("OAuth2 authentication failed")
		cli.Exit(1)
	} else {
		// Check SUID
		if syscall.Getuid() != 0 {
			// Try set SUID
			err := syscall.Setuid(0)
			if err != nil {
				cli.Log.Debug("Set SUID fail, Some functions will not work")
			}
		}

		// Check and add user to host
		if CheckUserOnHost(userList, username) == false {
			// If user not exist, add new one
			if AddNewUser(username) == true {
				cli.Log.Debug("User was added:", username)
			}
		}
		
		// Lookup exist username
		u, err := user.Lookup(username)
		if err != nil {
			cli.Log.Debug("User not exist:", username)
		} else {
			cli.Log.Debug(fmt.Sprintf("u.Uid: %s, u.Gid: %s, u.Name: %s, u.HomeDir: %s, u.Username: %s\n",
				u.Uid, u.Gid, u.Name, u.HomeDir, u.Username))
			// If current user id not keycloak user id, it should be change
			if (idTokenClaims.Uid != 0) {
				if (strconv.Itoa(idTokenClaims.Uid) != u.Uid) {
					// Change the user id form keycloak
					oldUid, _:= strconv.Atoi(u.Uid)
					KillProcess(oldUid)
					ChangeUid(username, idTokenClaims.Uid)
					ChangeGid(username, idTokenClaims.Uid)
					ChangeOwner(username, u.HomeDir)
				}
			}

			// Run user script
			var command = cli.Config.GetString("command")
			if len(command) > 0 {
				var display = idTokenClaims.Display;
				if display >= 5900 {
					display = idTokenClaims.Display - 5900;
				}
				os.Setenv("USERNAME", username)
				os.Setenv("PASSWORD", base64.StdEncoding.EncodeToString([]byte(password)))
				os.Setenv("HOMEDIR", u.HomeDir)
				if (idTokenClaims.Uid != 0) {
					os.Setenv("UID", strconv.Itoa(idTokenClaims.Uid))
				}
				if (display != 0) {
					os.Setenv("DISPLAY", strconv.Itoa(display))
				}
				if (len(idTokenClaims.Arg) > 0) {
					os.Setenv("ARGUMENTS", idTokenClaims.Arg)
				}
				RunCmd(command)
			}
		}

		// Add groups from keycloak if exists
		var existGroupList =  []string{}
		for _, groupname := range idTokenClaims.Groups {
			if CheckGroupOnHost(groupList, groupname) == false {
				// Group not exist
				cli.Log.Debug("Group not found:", groupname)
			} else {
				// Group exist, add to list
				existGroupList = append(existGroupList, groupname)
			}
		}
		if username != "root" {
			if len(existGroupList) > 0 {
				// Change the user group from keycloak if exist
				ChangeGroups(username, existGroupList)
			}
		}
	}

	cli.Log.Debug("OAuth2 authentication success")
	cli.Exit(0)
}
