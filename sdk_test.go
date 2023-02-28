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
		AppID:     "c2e29fbf-5499-49e2-b1fd-6916e21661ad",
		AppKey:    "15f3e1a524332a3680a4c526c9f0fbbedec21b01f9ce55d1da61a3df1e3466e2",
		AppSecret: "b9bb7b69cbd7d8477063adf9e388b545211065a91eeba246a517e184e8c597fc15f3e1a524332a3680a4c526c9f0fbbedec21b01f9ce55d1da61a3df1e3466e2",
		Addr:      "test.eps.gfapki.com.cn:8888",
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
