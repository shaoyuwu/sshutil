package main

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/mitchellh/go-homedir"
	"github.com/pkg/sftp"
	"github.com/wonderivan/logger"
	"golang.org/x/crypto/ssh"
)

type SSH struct {
	User     string
	Password string
	Host     string
	Port     string
	PkFile   string
}

var (
	auth         []ssh.AuthMethod
	clientConfig *ssh.ClientConfig
	sshClient    *ssh.Client
	sftpClient   *sftp.Client
	SSHConfig    SSH
)

//获取用户家目录
func GetHome() string {
	home, err := homedir.Dir()
	if err != nil {
		fmt.Printf("err: %v\n", err)
	}
	return home
}

//格式化ssh地址
func (ss *SSH) addrFormat(host string, port string) (addr string) {
	addr = fmt.Sprintf("%s:%s", host, port)
	return addr
}

//ssh连接配置,获取sshclient
func (ss *SSH) connect(host string) (*ssh.Client, error) {

	// auth := ss.sshAuthMethod(host)
	auth := make([]ssh.AuthMethod, 0)
	//get auth method
	auth = make([]ssh.AuthMethod, 0)
	auth = append(auth, ssh.Password(ss.Password))
	clientConfig = &ssh.ClientConfig{
		User:            ss.User,
		Auth:            auth,
		Timeout:         time.Second * 30,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	addr := ss.addrFormat(ss.Host, ss.Port)
	sshClient, err := ssh.Dial("tcp", addr, clientConfig)
	if err != nil {
		return nil, err
	}
	return sshClient, err
}

// func (ss *SSH) sshAuthMethod(host string) (auth []ssh.AuthMethod) {
// 	if ss.Password != "" {
// 		auth = append(auth, ss.sshPasswordMethod(ss.Password))
// 	}
// }

// func (ss *SSH) sshPasswordMethod(passwd string) ssh.AuthMethod {
// 	return ssh.Password(passwd)
// }

//ssh基于密码远程连接
//获取ssh session
func (ss *SSH) sshConnect() (*ssh.Session, error) {
	sshClient, err := ss.connect(ss.Host)
	if err != nil {
		logger.Error("[sshConnect]connect failed:%v\n", err)
		return nil, err
	}

	session, err := sshClient.NewSession()
	if err != nil {
		logger.Error("[sshConnect]session failed:%v\n", err)
		return nil, err
	}
	return session, nil
}

//ssh密码方式执行命令
func (ss *SSH) Cmd(cmd string) []byte {
	session, err := ss.sshConnect()
	defer func() {
		if r := recover(); r != nil {
			logger.Error("[ssh][%s]Error create ssh failed,%s", ss.Host, err)
		}
	}()
	if err != nil {
		panic(1)
	}
	defer session.Close()
	b, err := session.CombinedOutput(cmd)
	defer func() {
		if r := recover(); r != nil {
			logger.Error("[ssh][%s]Error exec command failed,%v", ss.Host, err)
		}
	}()
	if err != nil {
		panic(1)
	}

	//执行执行脚本
	/*
		err = session.Run("/usr/bin/sh /root/test.sh")
		if err != nil {
			fmt.Println("远程执行脚本失败", err)

		} else {
			fmt.Println("远程执行脚本成功")
		}
	*/
	return b

}

//获取ftp连接
func (ss *SSH) getftpClient() (*sftp.Client, error) {
	sshClient, _ := ss.connect(ss.Host)
	sftpClient, err := sftp.NewClient(sshClient)
	if err != nil {
		return nil, err
	}
	return sftpClient, err
}

//本地向远程传递文件
func (ss *SSH) UploadFile() {
	ftpClient, err := ss.getftpClient()
	defer func() {
		if r := recover(); r != nil {
			logger.Error("[ftpclient]Error ftpclient create failed,%s", err)
		}
	}()
	if err != nil {
		panic(1)
	}
	defer ftpClient.Close()

	localpath := filepath.Join(GetHome(), "kubernetes-master.zip")
	fmt.Printf("localpath: %v\n", localpath)
	srcFile, err := os.Open(localpath)
	if err != nil {
		fmt.Println("打开文件失败", err)
		panic(err)
	}
	defer srcFile.Close()
	remotepath := "/root"
	remoteFileName := filepath.Base(localpath)
	dstFile, e := ftpClient.Create(filepath.Join(remotepath, remoteFileName))
	if e != nil {
		fmt.Println("创建文件失败", e)
		panic(e)
	}
	defer dstFile.Close()

	buffer := make([]byte, 1024)
	for {
		n, _ := srcFile.Read(buffer)
		if n == 0 {
			break
		}
		dstFile.Write(buffer[:n])
	}
	fmt.Println("文件上传成功")

}

//ssh从远程下载文件到本地
func (ss *SSH) Download() {
	ftpClient, err := ss.getftpClient()
	defer func() {
		if r := recover(); r != nil {
			logger.Error("[ftpclient]Error ftpclient create failed,%s", err)
		}
	}()
	if err != nil {
		panic(1)
	}
	defer ftpClient.Close()
	remotepath := "/root/kubernetes-master.zip"
	srcFile, err := ftpClient.Open(remotepath)
	if err != nil {
		fmt.Println("文件读取失败", err)
		panic(err)
	}
	defer srcFile.Close()
	localFilename := path.Base(remotepath)

	localpath := GetHome()
	dstFile, e := os.Create(path.Join(localpath, localFilename))
	if e != nil {
		fmt.Println("文件创建失败", e)
		panic(e)
	}

	defer dstFile.Close()

	if _, err := srcFile.WriteTo(dstFile); err != nil {
		fmt.Println("文件写入失败", err)
		panic(err)
	}
	fmt.Println("文件下载成功")
}

func main() {
	SSHConfig = SSH{
		User:     "root",
		Password: "123456",
		Host:     "192.168.158.160",
		Port:     "22",
	}
	// cmd := "df -h"
	// result := SSHConfig.Cmd(cmd)
	// fmt.Printf("result: \n%v", string(result))

	// SSHConfig.UploadFile()

	SSHConfig.Download()
}
