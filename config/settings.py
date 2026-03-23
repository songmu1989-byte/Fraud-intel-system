# config/settings.py
"""
系统全局配置
"""
from pydantic import BaseModel
from typing import Dict
import os
from dotenv import load_dotenv

load_dotenv()


# ─── 风险等级定义 ─────────────────────────────────────────────
class RiskLevel:
    RED    = "RED"     # 高危 ≥ 80
    ORANGE = "ORANGE"  # 中高风险 60–79
    YELLOW = "YELLOW"  # 疑似风险 40–59
    GREEN  = "GREEN"   # 正常 < 40

RISK_THRESHOLDS = {
    RiskLevel.RED:    80,
    RiskLevel.ORANGE: 60,
    RiskLevel.YELLOW: 40,
    RiskLevel.GREEN:   0,
}

# 对应警务处置预案
DISPOSAL_PLANS = {
    RiskLevel.RED: {
        "level":   "高危 🔴",
        "action":  "立即启动下架程序，推送预警短信，移交网安部门",
        "urgency": "IMMEDIATE",
        "steps": [
            "向运营商提交紧急下架申请",
            "发布公众预警（微信公众号/官方 App）",
            "固定电子证据（截图+公证）",
            "移送网安支队立案侦查",
        ],
    },
    RiskLevel.ORANGE: {
        "level":   "中高风险 🟠",
        "action":  "列入重点监控，通知辖区民警跟进",
        "urgency": "HIGH",
        "steps": [
            "录入重点监控名单",
            "向相关平台发协查函",
            "安排 24h 持续监测",
            "联系受害人报案引导",
        ],
    },
    RiskLevel.YELLOW: {
        "level":   "疑似风险 🟡",
        "action":  "继续深度侦查，补充情报",
        "urgency": "MEDIUM",
        "steps": [
            "扩大 OSINT 采集范围",
            "请警校同学评估话术特征",
            "纳入日常巡查名单",
        ],
    },
    RiskLevel.GREEN: {
        "level":   "暂无风险 🟢",
        "action":  "存档备查",
        "urgency": "LOW",
        "steps": ["归档留存，定期复查"],
    },
}

# ─── WRAS 特征权重（由业务专家提供）───────────────────────────
# 权重由 0~1 构成，反映各维度的侦查经验优先级
FEATURE_WEIGHTS: Dict[str, float] = {
    # 域名/注册维度
    "domain_age_days":          0.08,   # 域名注册时间（越新越危险，反向）
    "icp_missing":              0.10,   # 无 ICP 备案
    "whois_privacy_protected":  0.05,   # WHOIS 信息隐藏
    "ssl_self_signed":          0.06,   # 自签名 SSL 证书

    # 地理/网络维度
    "ip_overseas":              0.07,   # 服务器境外
    "ip_cdn_abuse":             0.04,   # CDN 滥用（跳转规避）

    # 页面内容维度
    "keyword_risk_score":       0.15,   # 高风险关键词密度（话术检测）
    "phishing_visual_sim":      0.12,   # 与官方页面感知哈希相似度
    "resource_load_anomaly":    0.05,   # 页面资源加载异常率

    # 舆情维度
    "public_sentiment_neg":     0.14,   # 负面舆情极性分值
    "complaint_count_norm":     0.09,   # 投诉量（归一化）
    "blacklist_hit":            0.05,   # 命中黑名单
}

# 权重验证（总和应 ≈ 1.0）
assert abs(sum(FEATURE_WEIGHTS.values()) - 1.0) < 0.01, "权重之和必须等于 1.0"

# ─── 高风险关键词词库（业务方维护）────────────────────────────
RISK_KEYWORDS = {
    "high": [
        "公检法", "冻结账户", "洗钱嫌疑", "配合调查", "安全账户",
        "内部消息", "保本保息", "年化收益", "套现", "提现秒到",
        "刷单返利", "认购份额", "原始股", "内部额度", "解冻手续费",
    ],
    "medium": [
        "投资理财", "稳定收益", "低风险", "VIP通道", "专属客服",
        "实名认证", "身份核验", "银行卡绑定", "转账", "充值",
    ],
    "low": [
        "注册送", "邀请奖励", "新手礼包", "每日签到",
    ],
}

KEYWORD_WEIGHTS = {"high": 1.0, "medium": 0.5, "low": 0.2}

# ─── 已知官方页面哈希库（用于钓鱼检测）──────────────────────
OFFICIAL_PAGE_HASHES = {
    "icbc":      "a1b2c3d4e5f6a7b8",
    "ccb":       "b2c3d4e5f6a7b8c9",
    "alipay":    "c3d4e5f6a7b8c9d0",
    "wechatpay": "d4e5f6a7b8c9d0e1",
}

# ─── 已知黑名单域名（示例）────────────────────────────────────
BLACKLIST_DOMAINS = {
    "fraud-bank.com", "quick-profit.xyz", "invest-secure.top"
}

# ─── 置信度系数计算参数 ────────────────────────────────────────
CONFIDENCE_DECAY_HOURS = 72    # 情报超过 72h 开始衰减
CONFIDENCE_MIN         = 0.5   # 最低置信度系数

# ─── CORS 允许来源 ─────────────────────────────────────────────
# 默认允许本地 Streamlit 前端，生产环境通过环境变量 CORS_ORIGINS 覆盖（逗号分隔）
CORS_ORIGINS: list = [
    o.strip()
    for o in os.getenv(
        "CORS_ORIGINS",
        "http://localhost:8501,http://127.0.0.1:8501"
    ).split(",")
    if o.strip()
]

# ─── Redis 配置 ────────────────────────────────────────────────
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
REDIS_TASK_TTL = 60 * 60 * 24   # 任务结果保留 24 小时后自动过期

# ─── Gemini AI 配置 ─────────────────────────────────────────────
# 优先读 .env / 环境变量，其次读 Streamlit Cloud Secrets
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
if not GEMINI_API_KEY:
    try:
        import streamlit as st
        GEMINI_API_KEY = st.secrets.get("GEMINI_API_KEY", "")
    except Exception:
        pass
GEMINI_MODEL   = "gemini-2.5-flash"      # 速度快、支持视觉、成本低

# ─── DeepSeek AI 配置（备选，Gemini 限流时自动切换）──────────
DEEPSEEK_API_KEY  = os.getenv("DEEPSEEK_API_KEY", "")
DEEPSEEK_BASE_URL = "https://api.deepseek.com"
DEEPSEEK_MODEL    = "deepseek-chat"        # DeepSeek V3，中文极强

# ─── 招聘诈骗专项配置 ────────────────────────────────────────

RECRUITMENT_FRAUD_TYPES = {
    "付费培训诈骗": {
        "keywords": ["培训费", "报名费", "课程费", "学费", "结业后推荐就业", "包就业", "100%就业"],
        "description": "以入职为条件要求求职者缴纳培训费用",
        "risk_level": "极高",
    },
    "虚假内推诈骗": {
        "keywords": ["内部名额", "内推名额", "绕过笔试", "直接进", "内部渠道", "认识HR", "帮你进"],
        "description": "声称有内部名额，收取保证金或费用",
        "risk_level": "高",
    },
    "刷单返佣诈骗": {
        "keywords": ["刷单", "刷信誉", "兼职刷单", "返佣", "垫付", "先垫资", "购买商品后返款"],
        "description": "以兼职刷单为名诱导垫资，卷款跑路",
        "risk_level": "极高",
    },
    "押金保证金诈骗": {
        "keywords": ["押金", "保证金", "诚信金", "入职押金", "离职退还", "可退押金"],
        "description": "以各种名义收取押金或保证金",
        "risk_level": "高",
    },
    "虚假高薪诈骗": {
        "keywords": ["月薪两万", "月薪三万", "日入千元", "轻松月入过万", "无需经验高薪", "躺赚"],
        "description": "以虚假超高薪资为诱饵，实际为骗局入口",
        "risk_level": "中",
    },
    "冒充猎头诈骗": {
        "keywords": ["猎头", "专属顾问", "世界500强名额", "顶级offer", "代投简历"],
        "description": "冒充猎头公司收取服务费",
        "risk_level": "高",
    },
}

RECRUITMENT_RISK_KEYWORDS = {
    "high": [
        "培训费", "报名费", "押金", "保证金", "诚信金", "材料费",
        "体检费", "工装费", "服装押金", "入职费用",
        "月薪两万", "月薪三万", "日入千元", "轻松月入过万",
        "无需经验月薪", "应届生月薪过万", "躺赚", "睡后收入",
        "内部名额", "绕过笔试", "直接进", "秒过面试", "走内部",
        "刷单", "刷信誉", "先垫资", "垫付购买", "任务返佣",
        "不查征信", "无需面试直接录用", "只要身份证",
    ],
    "medium": [
        "内部渠道", "认识HR", "内推机会", "无门槛兼职",
        "在家工作", "日结工资", "高提成", "朋友圈推广",
        "不限学历", "不限经验", "急招大量", "无需上班",
    ],
    "low": [
        "实习", "应届生", "校招", "社招", "猎头",
    ],
}

RECRUITMENT_SENTIMENT_PATTERNS = [
    (r"骗局|诈骗|骗子|欺骗|坑人", 1.0),
    (r"收了钱就跑|卷款|失联|电话打不通", 0.95),
    (r"培训费骗局|虚假内推|保证金不退", 0.9),
    (r"黑中介|黑心公司|投诉无门", 0.85),
    (r"举报|维权|曝光", 0.7),
    (r"求职陷阱|招聘陷阱|注意避雷", 0.65),
    (r"怀疑|疑似|可能是骗", 0.5),
]

COMPANY_RISK_THRESHOLDS = {
    "min_established_days": 90,
    "suspicious_business_scope": ["信息咨询", "教育咨询", "管理咨询"],
}

