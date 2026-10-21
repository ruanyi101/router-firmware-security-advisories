# VulDB 逐字段填写参考：TEW-657BRM `mini_httpd`

适用于在 https://vuldb.com/vuln/add 新增一条漏洞条目时参考。
提交前请对照真实页面，检查作者身份、原始测试证据和查重情况。

| 表单字段 | 建议填写 |
| --- | --- |
| Vendor | `TRENDnet` |
| Product | `TEW-657BRM` |
| Version or Commit | `1.00.1` |
| Vulnerability | `Buffer Overflow`（如界面有 `Out-of-bounds Write` 亦可选） |
| Description | 复制 `VULDB_DESCRIPTION_mini_httpd.txt` 的完整英文内容 |
| Advisory / Exploit | 公开后填写**真实** GitHub 报告 URL |
| Request a CVE | **只有在已联系厂商、尚无 CVE 且尚未向其他 CNA 申请的情况下**勾选 |

示例 URL 格式（占位符，不能直接提交）：

`https://github.com/<YOUR_USERNAME>/<YOUR_REPOSITORY>/blob/main/advisories/TRENDnet-TEW-657BRM-mini_httpd.md`

⚠️ **私有 GitHub 仓库对公众和 VulDB 审核员不可直接访问**。不要把私有仓库
URL 当成已公开的漏洞参考。先与厂商协调披露；若暂不公开，可通过
VulDB 的保密审核机制咨询证据材料的提交方式，不要伪造链接。

注意：VulDB 页面明确要求厂商已提前获通知。原始研究材料虽有通知草稿和
“已通知”的文字，但本次无法确认发送回执，不能据此自行勾选。
VulDB 同时要求每次提交只有一个独立问题。
