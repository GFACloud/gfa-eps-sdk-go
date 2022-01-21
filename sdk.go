package epssdk

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	cl "github.com/ewangplay/cryptolib"
	resty "github.com/go-resty/resty/v2"
)

// Material represents the material structure.
type Material struct {
	// 证据资料标识符，用来唯一标识该份资料
	ID string `json:"id"`

	// 证据资料原始文本的类型，比如pdf、doc等
	Type string `json:"type"`

	// 证据资料原始文本的内容，Base64编码
	ContentBase64 string `json:"contentBase64"`

	// 证据资料原始文本的摘要值，使用SHA256哈希算法
	//
	// 注意：该字段由客户端程序自动生成，用户不需要填充
	DigestHex string `json:"digestHex"`
}

// Evidence represents the evidence structure.
type Evidence struct {
	// 证据保全标识符，由证据保全平台生成后返回
	//
	// 注意：客户端程序会通过返回值自动填充，用户不需要填充
	ID string `json:"id"`

	// 应用标识符，创建客户端时指定，由程序自动填充
	AppID string `json:"appID"`

	// 采集标识符，表示一次证据采集的唯一编号。一次采集可以
	// 包含多个证据资料，分别在下面的Materials字段中指定
	CollectID string `json:"collectID"`

	// 证据保全名称，有意义的名称帮助记忆证据保全内容
	Name string `json:"name"`

	// 证据保全 权属主
	Owner string `json:"owner"`
	// 证据保全 权属主ID
	OwnerID string `json:"owner_id"`
	// 证据保全 权属主邮箱
	MailAddress string `json:"mail_address"`
	// 标识证书模板
	Mark string `json:"mark"`

	// 证据摘要值,十六进制编码字符串。
	// 该摘要值由所有证据资料的摘要值计算而成，计算规则是：
	// 1. 对证据包内所有的资料内容分别做SHA256哈希运算得到各自的摘要值
	// 2. 对这些摘要值做字典排序，把排序后的摘要值列表拼接成一个文本
	// 3. 对该文本内容再做一次SHA256哈希运算，得到最终的证据保全摘要值
	//
	// 注意：该字段由客户端程序自动生成，用户不需要填充
	DigestHex string `json:"digestHex"`

	// 证据签名值，Base64编码字符串。
	// 该签名值是使用应用私钥(appSecret)对上面的证据摘要值进行
	// 签名运算后得到的证据签名值。证据保全服务会对该签名进行校验，
	// 以验证证据提交的有效性和合法性。
	//
	// 注意：该字段由客户端程序自动生成，用户不需要填充
	SignatureBase64 string `json:"signatureBase64"`

	// 区块链交易ID，保留字段，用户不需要填充
	TxID string `json:"txID"`

	// 证据的原始资料列表
	Materials []Material `json:"materials"`
}

// Response represents the response of http request.
type Response struct {
	Code int      `json:"code"`
	Msg  string   `json:"msg"`
	Data Evidence `json:"data"`
}

// Options represents the client options.
type Options struct {
	// 应用标识符，需要向证据保全平台申请
	AppID string

	// 应用公钥，需要向证据保全平台申请
	AppKey string

	// 应用私钥，需要向证据保全平台申请
	AppSecret string

	// 证据保全服务地址
	Addr string
}

// Client represents GFA-EPS client.
type Client struct {
	opts       *Options
	csp        cl.CSP
	httpClient *resty.Client
}

// NewClient creates an instance of Client.
func NewClient(opts *Options) (c *Client, err error) {
	err = checkOptions(opts)
	if err != nil {
		return nil, err
	}

	// 初始化CSP
	csp, err := cl.GetCSP(nil)
	if err != nil {
		return nil, err
	}

	// 初始化Http客户端
	httpClient := resty.New()

	c = &Client{opts: opts, csp: csp, httpClient: httpClient}
	return c, nil
}

// CreateEvidence posts the evidence to GFA-EPS service.
func (c *Client) CreateEvidence(evidence *Evidence) (err error) {
	// 检查入参
	err = c.checkParams(evidence)
	if err != nil {
		return err
	}

	// 生成摘要值
	err = c.makeDigest(evidence)
	if err != nil {
		return err
	}

	// 生成签名值
	err = c.makeSignature(evidence)
	if err != nil {
		return err
	}

	// 提交证据
	err = c.postEvidence(evidence)
	if err != nil {
		return err
	}

	return nil
}

func checkOptions(opts *Options) error {
	if opts.AppID == "" {
		return fmt.Errorf("应用标识符为空")
	}
	if opts.AppKey == "" {
		return fmt.Errorf("应用公钥为空")
	}
	if opts.AppSecret == "" {
		return fmt.Errorf("应用私钥为空")
	}
	if opts.Addr == "" {
		return fmt.Errorf("服务地址为空")
	}
	return nil
}

func (c *Client) checkParams(evidence *Evidence) (err error) {
	if evidence.AppID == "" {
		evidence.AppID = c.opts.AppID
	}
	if evidence.CollectID == "" {
		return fmt.Errorf("采集ID为空")
	}
	if evidence.Name == "" {
		return fmt.Errorf("证据名称为空")
	}
	if len(evidence.Materials) == 0 {
		return fmt.Errorf("资料列表为空")
	}
	for i, m := range evidence.Materials {
		if m.ID == "" {
			return fmt.Errorf("资料[%d]ID为空", i)
		}
		if m.Type == "" {
			return fmt.Errorf("资料[%d]类型为空", i)
		}
		if m.ContentBase64 == "" {
			return fmt.Errorf("资料[%d]内容为空", i)
		}
	}
	return nil
}

func (c *Client) makeDigest(evidence *Evidence) (err error) {
	var materialDigests []string
	for i, m := range evidence.Materials {
		content, err := base64.StdEncoding.DecodeString(m.ContentBase64)
		if err != nil {
			err = fmt.Errorf("资料[%d]内容格式无效：%v", i, err)
			return err
		}

		digest, err := c.csp.Hash(content, &cl.SHA256Opts{})
		if err != nil {
			err = fmt.Errorf("资料[%d]内容摘要失败: %v", i, err)
			return err
		}
		digestHex := hex.EncodeToString(digest)
		materialDigests = append(materialDigests, digestHex)

		evidence.Materials[i].DigestHex = digestHex
	}

	evidenceDigest, err := MakeEvidenceDigest(c.csp, materialDigests)
	if err != nil {
		return err
	}
	evidence.DigestHex = evidenceDigest

	return nil
}

func (c *Client) makeSignature(evidence *Evidence) (err error) {
	// 解析应用私钥
	appSecret, err := hex.DecodeString(c.opts.AppSecret)
	if err != nil {
		err = fmt.Errorf("应用私钥appSecret格式无效: %v", err)
		return err
	}
	k := &cl.Ed25519PrivateKey{
		PrivKey: appSecret,
	}

	// 解析摘要值
	digest, err := hex.DecodeString(evidence.DigestHex)
	if err != nil {
		return err
	}

	// 对摘要值进行签名
	signature, err := c.csp.Sign(k, digest)
	if err != nil {
		err = fmt.Errorf("对证据签名失败: %v", err)
		return err
	}

	// 对签名值做Base54编码
	signatureBase64 := base64.StdEncoding.EncodeToString(signature)

	evidence.SignatureBase64 = signatureBase64
	return nil
}

func (c *Client) postEvidence(evidence *Evidence) (err error) {
	url := fmt.Sprintf("http://%s/evidence/createEvidence", c.opts.Addr)
	var result Response

	resp, err := c.httpClient.R().
		SetBody(evidence).
		SetResult(&result).
		Post(url)
	if err != nil {
		return err
	}
	if resp.IsError() {
		return fmt.Errorf("%v %v", resp.Status(), resp.Error())
	}
	if result.Code != 0 {
		return fmt.Errorf("%v %v", result.Code, result.Msg)
	}

	evidence.ID = result.Data.ID
	return nil
}

// MakeEvidenceDigest makes evidenc digest based on material digest list.
func MakeEvidenceDigest(csp cl.CSP, materialDigests []string) (evidenceDigest string, err error) {
	// Step1: 对资料摘要值列表进行字典排序
	sort.Strings(materialDigests)

	// Step2: 把排序后的摘要值列表拼接到一起
	msg := strings.Join(materialDigests, "")

	// Step3: 对拼接后的字符串计算SHA256摘要值
	digest, err := csp.Hash([]byte(msg), &cl.SHA256Opts{})
	if err != nil {
		return
	}
	evidenceDigest = hex.EncodeToString(digest)

	return
}
