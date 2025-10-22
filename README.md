# burp_ex_portscan
burpsuite端口扫描插件

## 📖 项目简介

**Advanced Port Scanner** 是一款功能强大的 BurpSuite 扩展插件，专为渗透测试人员和安全研究人员设计。它集成了主动扫描、被动监控和智能服务指纹识别功能，能够高效地发现网络资产和服务。
<img width="1440" height="900" alt="image" src="https://github.com/user-attachments/assets/5cbba2b6-efce-48c8-9cf0-44cdbde7ecc0" />


## ✨ 核心特性

### 🔍 多模式扫描
- **主动扫描**: 支持自定义目标IP和端口范围的大规模扫描
- **被动监控**: 自动捕获 BurpSuite 流量中的新主机并触发扫描
- **智能协议识别**: 自动识别 HTTP/HTTPS 及其他常见协议服务

### 🎯 精准服务识别
- **200+ 服务指纹库**: 内置丰富的服务识别规则
- **实时指纹加载**: 支持外部指纹库文件动态加载
- **多维度匹配**: 基于端口、协议、Banner、HTTP头、HTML内容的综合识别
- **置信度评估**: 提供高、中、低三级识别置信度

### ⚡ 高性能引擎
- **多线程并发**: 可配置线程数，支持高并发扫描
- **连接池管理**: 优化的连接复用机制
- **超时控制**: 智能超时设置，平衡速度与准确性

### 🛠️ 专业功能
- **SSL/TLS 支持**: 完整支持 HTTPS 服务扫描
- **自签名证书处理**: 自动信任自签名证书
- **服务探测**: 支持特殊服务端点的主动探测
- **结果过滤**: 多条件结果筛选和搜索

## 🏗️ 支持的协议和服务

### 🌐 Web 服务
- **Web 服务器**: Apache, Nginx, IIS, Tomcat, Jetty
- **应用框架**: WordPress, Drupal, Joomla, Jenkins, GitLab
- **API 服务**: RabbitMQ Management, Elasticsearch, Kibana

### 🗄️ 数据库服务
- **关系型数据库**: MySQL, PostgreSQL, Oracle, SQL Server
- **NoSQL 数据库**: MongoDB, Redis, Cassandra, CouchDB
- **内存数据库**: Memcached, Redis

### ☁️ 云服务和中间件
- **容器平台**: Docker, Kubernetes, OpenShift
- **消息队列**: RabbitMQ, Kafka, ActiveMQ
- **监控系统**: Prometheus, Grafana, Zabbix

### 🔧 网络设备和管理
- **网络设备**: Cisco, Juniper, F5, Fortinet, Palo Alto
- **远程管理**: SSH, Telnet, RDP, VNC
- **控制面板**: cPanel, Plesk, Webmin

## 📋 系统要求

- **BurpSuite**: Professional 或 Community Edition
- **Java**: JDK 8 或更高版本
- **内存**: 建议至少 2GB 可用内存
- **网络**: 稳定的网络连接

## 🚀 快速开始

### 安装步骤

下载jar包，burpsuite加载插件就可以使用了

### 基本使用

1. **配置扫描目标**
   - 在 `Target IPs` 字段输入 IP 地址（支持逗号分隔）
   - 或点击 `Import` 从文件导入目标列表

2. **选择扫描端口**
   - **常用 Web 端口**: 80, 443, 8080 等常见 Web 服务端口
   - **Top 1000 端口**: 最常见的 1000 个网络服务端口
   - **自定义端口**: 手动指定端口范围或列表

3. **配置扫描参数**
   - 设置并发线程数（默认 50）
   - 配置指纹库文件路径
   - 启用被动扫描监控

4. **开始扫描**
   - 点击 `Start Active Scan` 开始主动扫描
   - 实时查看扫描进度和结果
   - 使用过滤功能筛选感兴趣的服务

## ⚙️ 配置说明

### 指纹库配置

插件支持外部指纹库文件，格式为 JSON：

```json
{
  "serviceName": "服务名称",
  "protocol": "协议类型",
  "ports": [端口列表],
  "bannerPatterns": ["Banner 匹配模式"],
  "headerPatterns": {
    "HTTP头字段": ["匹配模式"]
  },
  "htmlPatterns": ["HTML 内容匹配模式"],
  "confidence": "置信度"
}
```

### 性能调优

- **线程数**: 根据网络条件和目标数量调整
- **超时设置**: 内网环境可适当减少，外网环境建议增加
- **端口选择**: 根据扫描目标选择合适的端口范围

## 📊 输出结果

扫描结果包含以下信息：

- **主机**: 目标 IP 地址
- **端口**: 开放的端口号
- **协议**: 检测到的协议类型
- **服务**: 识别出的服务名称
- **Banner**: 服务标识信息
- **状态**: 端口开放状态
- **扫描类型**: 主动或被动扫描

## 🔧 故障排除

### 常见问题

1. **插件加载失败**
   - 检查 Java 版本兼容性
   - 确认 BurpSuite 版本支持

2. **扫描无结果**
   - 检查网络连接
   - 验证目标 IP 可达性
   - 查看调试日志获取详细信息

3. **服务识别不准确**
   - 更新指纹库文件
   - 检查自定义匹配规则
   - 查看响应内容匹配情况

### 调试模式

启用调试日志查看详细扫描过程：

1. 在日志区域观察 `[DEBUG]` 开头的消息
2. 检查响应内容和头部信息
3. 验证指纹匹配得分


## 🛡️ 免责声明

本工具仅用于安全测试和教育目的。使用者应遵守当地法律法规，未经授权不得对他人网络和系统进行扫描或测试。开发者不对使用本工具造成的任何直接或间接损失负责。

---

**⭐ 如果这个项目对你有帮助，请给我们一个 Star！**
