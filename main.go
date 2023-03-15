package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/GehirnInc/crypt"
	_ "github.com/GehirnInc/crypt/md5_crypt"
	_ "github.com/GehirnInc/crypt/sha256_crypt"
	_ "github.com/GehirnInc/crypt/sha512_crypt"
	"github.com/fatih/color"
)

// 常见密码字典
var weakpasswords = []string{
	"123456",
	"password",
	"12345678",
	"qwerty",
	"12345",
	"123456789",
	"letmein",
	"1234567",
	"football",
	"iloveyou",
	"admin",
	"welcome",
	"monkey",
	"login",
	"abc123",
	"starwars",
	"123123",
	"dragon",
	"passw0rd",
	"master",
	"hello",
	"freedom",
	"whatever",
	"qazwsx",
	"trustno1",
	"1qaz@WSX",
}

// 获取弱密码字典
func GetWeakPassword(file string) []string {

	f, err := os.Open(file)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	defer f.Close()

	var passwords []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		password := scanner.Text()
		passwords = append(passwords, password)
	}
	if err := scanner.Err(); err != nil {
		fmt.Println(err)
		return nil
	}

	return passwords
}

// 使用给定的哈希类型和盐值生成密码哈希
func Crypt(hashType, salt, password string) (string, error) {
	var ct crypt.Crypter
	switch hashType {
	case "1":
		ct = crypt.MD5.New()
	case "5":
		ct = crypt.SHA256.New()
	case "6":
		ct = crypt.SHA512.New()
	default:
		return "", errors.New("Unsupported encryption type, type=" + hashType)
	}
	raw_salt := "$" + hashType + "$" + salt + "$"
	return ct.Generate([]byte(password), []byte(raw_salt))
}

func main() {
	WeakPasswordFile := ""
	args := os.Args[1:]
	if len(args) == 0 {
		color.Green("[*] Currently no weak password dictionary file path is entered, and the built-in dictionary is used by default")
	} else {
		WeakPasswordFile = args[0]
		color.Green("[*] Weak password dictionary file path : " + WeakPasswordFile)
	}

	// 打开 /etc/shadow 文件
	file, err := os.Open("/etc/shadow")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer file.Close()

	// 创建新的扫描器，用于逐行读取文件
	scanner := bufio.NewScanner(file)

	// 设置弱密码计数
	weakPassCount := 0
	// 遍历所有行并分析用户名和密码
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ":")
		username := fields[0]
		password := fields[1]

		// 跳过没有设置密码的用户
		if len(password) == 0 || password == "*" || !strings.ContainsRune(password, '$') {
			continue
		}

		// 将密码哈希分离出来
		passwordFields := strings.Split(password, "$")
		hashType := passwordFields[1]
		salt := passwordFields[2]

		// 检查是否使用弱密码
		if len(WeakPasswordFile) != 0 {
			passwords := GetWeakPassword(WeakPasswordFile)
			for _, weakPassword := range passwords {

				testHash, _ := Crypt(hashType, salt, weakPassword)
				if testHash == password {
					weakPassCount = weakPassCount + 1
					color.Red("[-] User %s is using a weak password: %s\n", username, weakPassword)
				}
			}
		} else {
			for _, weakPassword := range weakpasswords {

				testHash, _ := Crypt(hashType, salt, weakPassword)
				if testHash == password {
					weakPassCount = weakPassCount + 1
					color.Red("[-] User %s is using a weak password: %s\n", username, weakPassword)
				}
			}
		}

	}
	if weakPassCount == 0 {
		color.Green("[+] There should be no weak passwords!")
	}
	// 检查扫描器是否发生错误
	if err := scanner.Err(); err != nil {
		color.Red("[-] Scanner encountered an error")
	}
}
