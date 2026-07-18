# 核心三页视觉 QA

## 对比证据

- 首页参考图：`docs/design/reference/01-home-dashboard.jpg`
- 设备列表参考图：`docs/design/reference/02-device-list.jpg`
- 添加设备参考图：`docs/design/reference/03-add-device.jpg`
- Windows 实机截图：GitHub Actions `29624720739` 的 `EvaluationTool-ui-screenshots-windows` 制品
- 实机截图归档：`docs/design/qa/01-home-dashboard-windows.png`、`docs/design/qa/02-device-list-windows.png`、`docs/design/qa/03-add-device-windows.png`
- 并排对比路径：`/tmp/evaluationtool-design-qa`
- 视口：`1100 x 788`，Windows 浅色模式，100% 缩放
- 状态：首次启动空首页、已创建项目的空设备列表、添加设备第 1 步

## 全屏对比

- 字体与层级：使用 Segoe UI / Microsoft YaHei UI，页标题、分区标题、说明文字层级清晰，中文未出现裁切或异常换行。
- 间距与布局：保留参考稿的紧凑左导航、顶部上下文、浅灰画布、白色卡片和右侧辅助区；持久操作按钮在 1100 x 788 视口中全部可见。
- 颜色与令牌：蓝色仅用于主操作和当前步骤，绿色用于只读保护，红/黄保留给失败和待处理状态，对比度和语义一致。
- 图片与图标：首页与安全说明使用真实位图 PNG 资产，导航和安全说明使用 Segoe Fluent Icons，无 emoji、ASCII 或占位图。
- 文案与业务：将参考稿的泛资产管理文案替换为“项目→设备→安全连接→证据”真实测评流程，并持续显示只读保护。

## 聚焦区域

- 已单独查看 `01-home-dashboard.png`、`02-device-list.png` 和 `03-add-device.png` 原始分辨率图片。
- 重点复核导航选中态、顶部上下文、搜索框、空状态主操作、向导步骤、两列表单和底部持久操作区，未见裁切、重叠、溢出或失焦。

## 差异说明

- 首页未制造虚假趋势图和运行日志；MVP 在没有真实任务数据时显示空状态。
- 设备列表未制造演示设备；真实项目刚创建后显示可操作的空状态。
- 添加设备改为三步向导，而非将密码等敏感字段在首屏一次展开；这是降低非技术用户误填概率的有意产品调整。

## 对比历史

- 第 1 轮：三张 Windows 实机截图与对应参考图并排对比；未发现可执行的 P0、P1 或 P2 差异。
- 测试中发现的 WPF 自定义 Tab 模板辅助功能树缺失已修复，修复后 GitHub Actions `29624720739` 全部通过并生成三张截图。

## 结论

- P0/P1/P2 问题：无。
- 剩余测试缺口：深色模式、125%/150% DPI 和有真实设备数据的密集列表视觉状态待后续专项复核。
- final result: passed
