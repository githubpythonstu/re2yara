# GitHub 工作流与自动化

> 本文档记录 RE2YARA 项目的 Git 工作流、PR 流程和自动化实践。

---

## 目录

- [Git 认证](#git-认证)
- [分支策略](#分支策略)
- [PR 流程](#pr-流程)
- [Review 流程](#review-流程)
- [GitHub Rulesets](#github-rulesets)
- [自动化工作流](#自动化工作流)
- [常见问题](#常见问题)

---

## Git 认证

### 方法 1：Personal Access Token (PAT)

```bash
# 1. 生成 token
# GitHub → Settings → Developer settings → Personal access tokens → Tokens (classic)
# 勾选 repo 权限

# 2. 推送时使用 token
git push
Username: githubpythonstu
Password: ghp_xxxxxxxxxxxx
```

### 方法 2：SSH 密钥

```bash
# 1. 生成密钥
ssh-keygen -t ed25519 -C "your_email@example.com"

# 2. 复制公钥
cat ~/.ssh/id_ed25519.pub
# → GitHub → Settings → SSH and GPG keys → New SSH Key

# 3. 修改 remote
git remote set-url origin git@github.com:githubpythonstu/re2yara.git

# 4. 推送
git push
```

---

## 分支策略

### 分支命名

| 前缀 | 用途 | 示例 |
|------|------|------|
| `feat/` | 新功能 | `feat/add-foobar-checker` |
| `fix/` | 修复 bug | `fix/regex-conversion` |
| `docs/` | 文档更新 | `docs/add-api-reference` |
| `test/` | 测试相关 | `test/add-unit-tests` |
| `refactor/` | 重构 | `refactor/simplify-pipeline` |
| `perf/` | 性能优化 | `perf/reduce-memory` |

### 分支关系

```
main (受保护)
  │
  ├── feat/add-checker
  │     └── 开发新功能
  │     └── PR → main
  │
  ├── fix/regex-bug
  │     └── 修复 bug
  │     └── PR → main
  │
  └── docs/update-readme
        └── 更新文档
        └── PR → main
```

---

## PR 流程

### 创建 PR

```bash
# 方法 1：命令行
gh pr create \
  --title "feat: add Foobar checker" \
  --body "## Summary
  - 添加 Foobar 检测器
  - 支持 3 种版本格式
  
  Closes #123" \
  --label "enhancement" \
  --reviewer username

# 方法 2：交互式
gh pr create
# 按提示输入标题、正文等

# 方法 3：从文件读取正文
gh pr create --title "..." --body-file pr_description.md
```

### PR 模板

```markdown
## Summary
<!-- 描述这个 PR 做了什么 -->

## Changes
<!-- 列出主要变更 -->
- 
- 
- 

## Test Plan
<!-- 如何测试这些变更 -->
- [ ] 语法测试通过
- [ ] 功能测试通过
- [ ] 手动验证

## Related Issues
<!-- 关联的 Issue -->
Closes #

## Screenshots
<!-- 如有 UI 变更，添加截图 -->
```

### 关联 Issue（自动关闭）

```bash
# PR body 中包含关键词，merge 后自动关闭 issue
gh pr create --title "fix: bug" --body "Closes #5"
```

| 关键词 | 效果 |
|--------|------|
| `Closes #1` | 自动关闭 |
| `Fixes #1` | 自动关闭 |
| `Resolves #1` | 自动关闭 |
| `Related to #1` | 仅引用，不关闭 |

---

## Review 流程

### 评审类型

```bash
# 批准
gh pr review 123 --approve --body "LGTM"

# 请求修改
gh pr review 123 --request-changes --body "需要修改"

# 仅评论
gh pr review 123 --comment --body "有个问题"
```

### 评审流程图

```
PR 创建 (opened)
    │
    ▼
┌──────────────────┐
│   等待评审        │
│   (pending)      │
└────────┬─────────┘
         │
    ┌────┴────┐
    │ 评审者   │
    └────┬────┘
         │
    ┌────┴────────────────────────────┐
    │                                  │
    ▼                                  ▼
┌──────────┐                    ┌──────────────┐
│ Approve  │                    │ Request      │
│ (批准)   │                    │ Changes      │
│          │                    │ (请求修改)    │
└────┬─────┘                    └──────┬───────┘
     │                                 │
     ▼                                 ▼
┌──────────┐                    ┌──────────────┐
│ 检查是否  │                    │ PR 被阻塞     │
│ 达到要求  │                    │ ❌ 无法合并   │
│ 评审数量  │                    └──────┬───────┘
└────┬─────┘                           │
     │ 是                              ▼
     ▼                           ┌──────────────┐
┌──────────┐                     │ 作者修改代码   │
│ 可以合并  │                     │ git commit   │
│ ✅       │                     │ git push     │
└────┬─────┘                     └──────┬───────┘
     │                                  │
     │                                  ▼
     │                           ┌──────────────┐
     │                           │ 重新请求评审   │
     │                           └──────┬───────┘
     │                                  │
     └──────────────┬───────────────────┘
                    │
                    ▼
             ┌──────────────┐
             │    Merge     │
             │   合并到 main │
             └──────────────┘
```

### Request Changes 流程

```
评审者: --request-changes --body "第 3 行有 bug"
    │
    ▼
PR 状态: Changes requested ❌
    │
    ▼
作者收到通知
    │
    ▼
作者修改代码
    │
    ▼
git add .
git commit -m "fix: 修复第 3 行 bug"
git push
    │
    ▼
PR 自动更新（新 commit）
    │
    ▼
作者评论: "@reviewer 已修改，请重新查看"
    │
    ▼
评审者重新评审
    │
    ├── Approve → 可以合并
    └── Request Changes → 继续循环
```

### 评审最佳实践

#### 评审者

```bash
# ✅ 好的评审
gh pr review 123 --request-changes --body "## 问题
1. 第 3 行：变量名不清晰，建议改为 \`user_count\`
2. 第 15 行：缺少空指针检查

## 建议
- 添加单元测试覆盖核心逻辑
- 考虑边界情况"

# ❌ 差的评审
gh pr review 123 --request-changes --body "有问题"
```

#### 作者

```bash
# 修改后重新请求评审
git push
gh pr comment 123 --body "@reviewer 已修改，请重新查看"

# 回复每个评审意见
gh pr comment 123 --body "已修复：
1. ✅ 变量名已改为 user_count
2. ✅ 添加了空指针检查
3. ✅ 新增单元测试"
```

---

## GitHub Rulesets

### 当前配置

| 设置 | 值 | 说明 |
|------|-----|------|
| 目标分支 | `main` | 规则适用的分支 |
| 强制执行 | Active | 规则立即生效 |
| 需要 PR | Required | 禁止直接 push |
| Merge commits | Disabled | 只允许 squash 或 rebase |
| Bypass list | Repository admins | 管理员可绕过 |

### 效果

```bash
# 普通用户
git push origin main
# → ❌ remote: error: GH013: Repository rule violations found

# 管理员
git push origin main
# → ✅ 成功（但尽量不用）
```

---

## 自动化工作流

### GitHub Actions 事件

```yaml
on:
  pull_request:
    types: [opened, synchronize]
  pull_request_review:
    types: [submitted]
  check_suite:
    types: [completed]
```

### 自动化检查

| 检查 | 触发条件 | 说明 |
|------|---------|------|
| 语法验证 | PR 创建/更新 | `yarac64.exe` 编译检查 |
| 功能测试 | PR 创建/更新 | 扫描测试样本 |
| 代码评审 | PR 创建 | AI 辅助评审 |
| 自动合并 | 评审批准 + CI 通过 | 自动 merge |

### 工作流示例

```yaml
# .github/workflows/ci.yml
name: CI
on:
  pull_request:
    types: [opened, synchronize]

jobs:
  syntax:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      - name: Test YARA Syntax
        run: py re2yara_version_only_converter.py test-syntax

  functionality:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      - name: Test YARA Functionality
        run: py re2yara_version_only_converter.py test-functionality
```

---

## 常见问题

### Q: 为什么 push 被拒绝？

```
remote: error: GH013: Repository rule violations found
remote: - Changes must be made through a pull request.
```

**原因**：Ruleset 要求必须通过 PR 合入 main。

**解决**：推送到功能分支，创建 PR。

### Q: 如何绕过 Ruleset？

**你是 Repository Owner** → 默认有 bypass 权限。

但建议日常开发仍走 PR 流程。

### Q: 多人同一 Issue 冲突？

**解决方案**：
1. 先评论声明你要处理
2. 请求分配 Issue
3. Draft PR 占位

```bash
gh issue comment 123 --body "我来处理这个 Issue"
gh issue edit 123 --add-assignee @me
```

### Q: Rebase vs Merge？

| 操作 | 改谁 | 历史 |
|------|------|------|
| `git rebase main` | 当前分支 | 线性 |
| `git merge main` | 当前分支 | 保留分叉 |
| PR merge | 目标分支 | 取决于设置 |

### Q: 连续创建 PR？

| 场景 | 结果 |
|------|------|
| 不同分支，各有新 commit | ✅ 创建新 PR |
| 同一分支，没有新 commit | ❌ 不行 |
| 同一分支，有新 commit | 更新已有 PR |
| PR 已 merge，分支有新 commit | ✅ 创建新 PR |

---

## 命令速查

### Git

```bash
git checkout -b <branch>      # 创建并切换分支
git add <file>                # 暂存文件
git commit -m "message"       # 提交
git push origin <branch>      # 推送
git rebase main               # rebase 到 main
git merge main                # 合并 main
```

### GitHub CLI

```bash
# Issue
gh issue create --title "..." --body "..."
gh issue list --label "todo" --state open
gh issue comment <number> --body "..."
gh issue edit <number> --add-assignee @me

# PR
gh pr create --title "..." --body "..."
gh pr list --state open
gh pr view <number>
gh pr review <number> --approve --body "LGTM"
gh pr review <number> --request-changes --body "需要修改"
gh pr merge <number> --squash --delete-branch
```

---

*文档版本: 1.0 | 更新日期: 2026-06-29*
