package filter

import (
	"fmt"
	"strings"
	"testing"
)

func newFilter(t *testing.T) *Filter {
	t.Helper()
	f, err := New("../rules/gitleaks.toml")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return f
}

func redact(t *testing.T, f *Filter, text string) string {
	t.Helper()
	return f.Redact(text).Redacted
}

// --- 结构化 PII ---

func TestEmail(t *testing.T) {
	f := newFilter(t)
	if got := redact(t, f, "有事联系 test.user@example.com 谢谢"); !strings.Contains(got, "[邮箱]") {
		t.Errorf("邮箱未脱敏: %q", got)
	}
}

func TestPhoneCN(t *testing.T) {
	f := newFilter(t)
	if got := redact(t, f, "我的手机是 13812345678 随时打"); !strings.Contains(got, "[电话]") {
		t.Errorf("手机号未脱敏: %q", got)
	}
}

func TestIDCard(t *testing.T) {
	f := newFilter(t)
	if got := redact(t, f, "身份证号 11010519900307743X 务必保密"); !strings.Contains(got, "[身份证]") {
		t.Errorf("身份证未脱敏: %q", got)
	}
}

func TestBankCardValidLuhn(t *testing.T) {
	f := newFilter(t)
	if got := redact(t, f, "付款卡号 4111111111111111"); !strings.Contains(got, "[银行卡]") {
		t.Errorf("银行卡未脱敏: %q", got)
	}
}

func TestBankCardInvalidLuhnIgnored(t *testing.T) {
	f := newFilter(t)
	if got := redact(t, f, "订单编号 1234567890123456"); strings.Contains(got, "[银行卡]") {
		t.Errorf("Luhn 不通过的数字串被误判成银行卡: %q", got)
	}
}

// --- 密钥层 ---

func TestGitleaksRulesLoaded(t *testing.T) {
	f := newFilter(t)
	rules, skipped := f.Stats()
	if rules <= 100 {
		t.Errorf("gitleaks 规则只加载了 %d 条（应上百条）", rules)
	}
	t.Logf("gitleaks 规则 %d 条，跳过 %d 条", rules, skipped)
}

func TestContextPassword(t *testing.T) {
	f := newFilter(t)
	if got := redact(t, f, "我的密码是 Hunter2xyz"); !strings.Contains(got, "[密钥]") {
		t.Errorf("上下文口令未脱敏: %q", got)
	}
}

func TestContextAPIKey(t *testing.T) {
	f := newFilter(t)
	if got := redact(t, f, "配置里 api_key = aB3xK9pLmN2qR7sT"); !strings.Contains(got, "[密钥]") {
		t.Errorf("api_key 未脱敏: %q", got)
	}
}

func TestEntropyFallback(t *testing.T) {
	f := newFilter(t)
	if got := redact(t, f, "临时凭证 aB3xK9pLmN2qR7sT5vW1zY 已生成"); !strings.Contains(got, "[密钥]") {
		t.Errorf("高熵随机串未脱敏: %q", got)
	}
}

// --- 高熵兜底反误报 ---

// SSH 命令上下文里的 user@host 不当邮箱（允许命令前有自然语言前缀）。
func TestSSHCommandContextSkipsEmail(t *testing.T) {
	f := newFilter(t)
	cases := []string{
		"ssh user@host.example.com",
		"ssh -i ~/.ssh/id_rsa user@host.example.com",
		"打开 ssh user@host.example.com",
		"scp file.txt user@host.example.com:/data/",
		"rsync -av /src/ user@host.example.com:/dst/",
	}
	for _, in := range cases {
		if got := redact(t, f, in); strings.Contains(got, "[邮箱]") {
			t.Errorf("SSH 目标被误判成邮箱: in=%q got=%q", in, got)
		}
	}
}

// 反面：纯邮箱（无 ssh 命令前缀）仍要脱
func TestSSHCommandContextPlainEmailStillRedacted(t *testing.T) {
	f := newFilter(t)
	in := "我的邮箱是 alice@example.com 请保密"
	if got := redact(t, f, in); !strings.Contains(got, "[邮箱]") {
		t.Errorf("普通邮箱漏脱: %q", got)
	}
}

// 回归 case：ls 命令传入长路径时，路径片段被熵兜底误判成密钥。
func TestEntropyFallbackSkipsFilesystemPath(t *testing.T) {
	f := newFilter(t)
	in := "ls /home/user/AbCdEfGh1234567890XyZ"
	if got := redact(t, f, in); strings.Contains(got, "[密钥]") {
		t.Errorf("文件路径被误判: %q", got)
	}
}

// URL path segment 不应被脱敏。
func TestEntropyFallbackSkipsURLPath(t *testing.T) {
	f := newFilter(t)
	in := "curl https://api.example.com/v1/users/AbCdEfGh1234567890XyZ"
	if got := redact(t, f, in); strings.Contains(got, "[密钥]") {
		t.Errorf("URL 路径被误判: %q", got)
	}
}

// S3 / 对象存储路径。
func TestEntropyFallbackSkipsS3URI(t *testing.T) {
	f := newFilter(t)
	in := "aws s3 cp s3://my-bucket/dir/AbCdEfGh1234567890XyZ ."
	if got := redact(t, f, in); strings.Contains(got, "[密钥]") {
		t.Errorf("S3 URI 被误判: %q", got)
	}
}

// 容器镜像 sha256 摘要。
func TestEntropyFallbackSkipsSha256Digest(t *testing.T) {
	f := newFilter(t)
	in := "docker pull registry.io/img@sha256:9f86d081884c7d659a2feaa0c55ad015b1b8a3e6b1d2c4a5e9f8b7d6c5a4b3210"
	if got := redact(t, f, in); strings.Contains(got, "[密钥]") {
		t.Errorf("sha256 摘要被误判: %q", got)
	}
}

// 邮件附件 / 邮箱本身的 domain 段不应触发兜底（域名内 . 边界）。
func TestEntropyFallbackSkipsHostname(t *testing.T) {
	f := newFilter(t)
	in := "host=long-subdomain-with-many-chars.example.com"
	if got := redact(t, f, in); strings.Contains(got, "[密钥]") {
		t.Errorf("主机名被误判: %q", got)
	}
}

// 有 token 关键词的命令行（候选串与关键词同段），仍然要脱敏。
func TestEntropyFallbackKeepsTokenWithContext(t *testing.T) {
	f := newFilter(t)
	in := "请使用 token aB3xK9pLmN2qR7sT5vW1zY 调试"
	if got := redact(t, f, in); !strings.Contains(got, "[密钥]") {
		t.Errorf("带 token 关键词的随机串未脱敏: %q", got)
	}
}

// 普通乱码无 context（既无密钥语义关键词，也无路径边界）走严格阈值。
// 22 字符全异熵 ≈ 4.46，不到 4.8 → 应被放过，避免误伤普通 ID。
func TestEntropyFallbackStrictThresholdSkipsModerateEntropy(t *testing.T) {
	f := newFilter(t)
	in := "订单编号 aB3xK9pLmN2qR7sT5vW1zY 已记账"
	if got := redact(t, f, in); strings.Contains(got, "[密钥]") {
		t.Errorf("无密钥语义的中等乱度串不应脱敏: %q", got)
	}
}

// --- 强上下文凌驾路径检查 ---

// Bearer 真密钥含 base64 padding 的 / —— 不能被 Step 1 当路径放过。
func TestStrongContextOverridesPathBoundary_BearerWithSlash(t *testing.T) {
	f := newFilter(t)
	in := `Authorization: Bearer abcDEF1234567890/xyzABC4567890==`
	if got := redact(t, f, in); !strings.Contains(got, "[密钥]") {
		t.Errorf("Bearer 真密钥被路径检查放过: %q", got)
	}
}

// 反面：api_key 出现在域名里（不是赋值结构）→ 仍走路径检查 → 不脱
func TestStrongContextNotTriggeredByPathKeyword(t *testing.T) {
	f := newFilter(t)
	in := `api_key.example.com/AbCdEfGh1234567890XyZ`
	if got := redact(t, f, in); strings.Contains(got, "[密钥]") {
		t.Errorf("api_key.example.com 域名段被误判: %q", got)
	}
}

// 关键词跨过候选串起点（"api key" 里的 "key" 落进候选串）不应 panic，且应判定为强上下文。
func TestStrongContextKeywordStraddlingCandidateStart(t *testing.T) {
	f := newFilter(t)
	in := "use api key9F3jL8mQ2xR7tK4vN6pW1sZ0dC5 to authenticate"
	if got := redact(t, f, in); !strings.Contains(got, "[密钥]") {
		t.Errorf("跨界的 api key 未脱敏: %q", got)
	}
}

// --- Post Validators ---

// 模板变量不脱
func TestPostValidatorSkipsTemplateVar(t *testing.T) {
	f := newFilter(t)
	cases := []string{
		`secret={{ API_KEY }} 或 token=${TOKEN}`,
		`config: token=%{TOKEN}`,
		`auth=<API_KEY>`,
	}
	for _, in := range cases {
		if got := redact(t, f, in); strings.Contains(got, "[密钥]") {
			t.Errorf("模板变量被误判: in=%q got=%q", in, got)
		}
	}
}

// 业务 ID 不脱
func TestPostValidatorSkipsBusinessIDAssignment(t *testing.T) {
	f := newFilter(t)
	cases := []string{
		`order_id=aB3xK9pLmN2qR7sT5vW1zY`,
		`user_id=AbCdEfGh1234567890XyZQwErTyUiOp`,
		`session_no=aB3xK9pLmN2qR7sT5vW1zY1234`,
	}
	for _, in := range cases {
		if got := redact(t, f, in); strings.Contains(got, "[密钥]") {
			t.Errorf("业务 ID 被误判: in=%q got=%q", in, got)
		}
	}
}

// UUID 不脱
func TestPostValidatorSkipsUUID(t *testing.T) {
	f := newFilter(t)
	in := `trace_id=550e8400-e29b-41d4-a716-446655440000`
	if got := redact(t, f, in); strings.Contains(got, "[密钥]") {
		t.Errorf("UUID 被误判: %q", got)
	}
}

// 长度=32/40/64 的纯 hex hash 不脱（md5/sha1/sha256）
func TestPostValidatorSkipsHexHash(t *testing.T) {
	f := newFilter(t)
	cases := []string{
		`md5: 9f86d081884c7d659a2feaa0c55ad015`,
		`sha1: da39a3ee5e6b4b0d3255bfef95601890afd80709`,
		`commit 9f86d081884c7d659a2feaa0c55ad015b1b8a3e6b1d2c4a5e9f8b7d6c5a4b3210`,
	}
	for _, in := range cases {
		if got := redact(t, f, in); strings.Contains(got, "[密钥]") {
			t.Errorf("hex hash 被误判: in=%q got=%q", in, got)
		}
	}
}

// --- 整体行为 ---

func TestCleanTextNoHit(t *testing.T) {
	f := newFilter(t)
	text := "今天天气不错，我们一起去公园散步吧。"
	res := f.Redact(text)
	if res.Redacted != text || res.Hit || res.Count != 0 {
		t.Errorf("干净文本被误改: %+v", res)
	}
}

func TestMultipleEntities(t *testing.T) {
	f := newFilter(t)
	res := f.Redact("邮箱 a@b.com 手机 13900001111 密码是 Qwer1234")
	if !strings.Contains(res.Redacted, "[邮箱]") ||
		!strings.Contains(res.Redacted, "[电话]") ||
		!strings.Contains(res.Redacted, "[密钥]") {
		t.Errorf("多实体脱敏不全: %q", res.Redacted)
	}
	if res.Count < 3 {
		t.Errorf("命中数 %d，应 >= 3", res.Count)
	}
}

func TestBuiltinFallback(t *testing.T) {
	f, err := New("") // 空路径 → 用内置兜底规则
	if err != nil {
		t.Fatalf("New(\"\"): %v", err)
	}
	if rules, _ := f.Stats(); rules == 0 {
		t.Error("内置兜底规则为空")
	}
}

// BenchmarkRedact 测不同文本长度下的脱敏耗时。
func BenchmarkRedact(b *testing.B) {
	f, err := New("../rules/gitleaks.toml")
	if err != nil {
		b.Fatal(err)
	}
	unit := "我叫张伟，邮箱 a@b.com，密码是 Hunter2xy，卡号 4111111111111111。"
	for _, size := range []int{50, 2000, 32000} {
		text := strings.Repeat(unit, size/len(unit)+1)[:size]
		b.Run(fmt.Sprintf("%dB", len(text)), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				f.Redact(text)
			}
		})
	}
}
