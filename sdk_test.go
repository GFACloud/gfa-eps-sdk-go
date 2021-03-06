package epssdk

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"strings"
	"testing"

	uuid "github.com/satori/go.uuid"
)

func TestCreateEvidence(t *testing.T) {
	// 新建客户端
	opts := &Options{
		AppID:     "2aa321a2-ff9a-4460-a814-3c166e3c66b1",
		AppKey:    "230af15419b1bd9a2ccf4654b04f9c36f517181f1afa33656100e390db54c52c",
		AppSecret: "513b6cc2c36ee88900cf9bc21c0e1ee42b0b8564734d0cc9bd71e19754898eda230af15419b1bd9a2ccf4654b04f9c36f517181f1afa33656100e390db54c52c",
		Addr: "127.0.0.1:8888",
	}
	c, err := NewClient(opts)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	// 读取测试文件
	contentBase64, fileType, err := readTestFile("files/test1.pdf")
	if err != nil {
		t.Fatalf("Read test file failed: %v", err)
	}

	// 构建证据数据并提交
	e := &Evidence{
		CollectID: uuid.NewV4().String(),
		Name:      "张三的劳动合同",
		Materials: []Material{
			Material{
				ID:            uuid.NewV4().String(),
				Type:          fileType,
				ContentBase64: contentBase64,
			},
		},
	}
	err = c.CreateEvidence(e)
	if err != nil {
		t.Fatalf("CreateEvidence failed: %v", err)
	}

	fmt.Println("证据ID: ", e.ID)
}

func readTestFile(filename string) (contentBase64 string, fileType string, err error) {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return
	}
	contentBase64 = base64.StdEncoding.EncodeToString(content)

	items := strings.Split(filename, ".")
	if len(items) >= 2 {
		fileType = items[len(items)-1]
	} else {
		fileType = "normal"
	}

	return
}
