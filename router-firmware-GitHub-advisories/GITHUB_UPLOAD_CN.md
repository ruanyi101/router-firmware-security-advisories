# 使用 GitHub 网页上传报告（无需 Git 命令）

## 建议：先建私有仓库

1. 登录 GitHub，点击右上角 `+` → **New repository**。
2. Repository name：建议 `router-firmware-security-advisories`。
3. Visibility：选 **Private**，防止在厂商联系状态未确认时提前披露。
4. 点击 **Create repository**。
5. 解压随附 ZIP。打开仓库网页，选择 **Add file → Upload files**。
6. 将解压出的**仓库文件和目录内容**拖入页面（不是把整个 ZIP 当一个文件）。
   上传后应该能看到 `README.md`、`advisories/`、`related-findings/` 等。
7. Commit message 可填：`Add reviewed router firmware security advisories`。
8. 点击 **Commit changes**，检查 Markdown 文件能正常打开。

## 何时公开？

先确认厂商已收到报告、CNA 查重工作完成并确定披露计划。
需要公开报告时，在仓库设置中由你自行改为 Public，
再复制**真实**报告 URL 给 VulDB 的 `Advisory / Exploit` 字段。

建议作为第一条参考链接的文件：
`advisories/TRENDnet-TEW-657BRM-mini_httpd.md`

如果仍需保密，暂不把私有仓库链接冒充公众可访问的证据链接，
而应与 VulDB 协调保密提交的证据形式。

## 正式提交前检查

- [ ] 已获得研究成果所有人的发布授权
- [ ] 原始分析、测试环境和报告描述一致
- [ ] 厂商已收到漏洞通知且回执可追踪
- [ ] 没有将仿真测试写成物理设备实测
- [ ] 相关漏洞已与现有 CVE/VulDB 条目查重
- [ ] 原始漏洞利用脚本和潜在个人/内部数据未被意外上传
- [ ] CVE 字段仅在获得正式编号后填写
- [ ] VulDB 引用链接确实可由其他人访问

**仓库发布与提交操作须由 GitHub/VulDB 账号持有人完成。**
