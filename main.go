package main

import (
	"bufio"
	"errors"
	"flag"
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
var passwords = []string{
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
		return "", errors.New("不支持当前加密类型, type=" + hashType)
	}
	raw_salt := "$" + hashType + "$" + salt + "$"
	return ct.Generate([]byte(password), []byte(raw_salt))
}

func main() {
	// 解析命令行参数
	minLen := flag.Int("minlen", 8, "Minimum password length")
	excludeUser := flag.String("exclude", "", "Exclude username")
	flag.Parse()

	// 打开 /etc/shadow 文件
	file, err := os.Open("/etc/shadow")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer file.Close()

	// 创建新的扫描器，用于逐行读取文件
	scanner := bufio.NewScanner(file)

	// 遍历所有行并分析用户名和密码
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ":")
		username := fields[0]
		password := fields[1]

		// 排除指定的用户
		if *excludeUser != "" && username == *excludeUser {
			continue
		}

		// 跳过没有设置密码的用户
		if len(password) == 0 || password == "*" || !strings.ContainsRune(password, '$') {
			continue
		}

		// 将密码哈希分离出来
		passwordFields := strings.Split(password, "$")
		hashType := passwordFields[1]
		salt := passwordFields[2]

		// 检查是否使用弱密码
		for _, weakPassword := range passwords {
			if len(weakPassword) < *minLen {
				continue
			}
			testHash, _ := Crypt(hashType, salt, weakPassword)

			if testHash == password {

				color.Red("User %s is using a weak password: %s\n", username, weakPassword)
			}
		}
	}

	// 检查扫描器是否发生错误
	if err := scanner.Err(); err != nil {
		fmt.Println(err)
	}
}
